namespace NightTech.Business.Core.Security;

/// <summary>
/// Turns what a computer showed, plus the owner's answers, into plain-language results with fixes.
/// Results describe what was checked at the time; they are not a guarantee the business is secure.
/// </summary>
public static class SecurityRules
{
    public const int UpdatesWarnDays = 45, UpdatesFailDays = 90;
    public const int SignaturesWarnDays = 3, SignaturesFailDays = 7;
    public const int ScreenLockMaxSeconds = 15 * 60;
    public const int MinGoodPasswordLength = 12;

    public static readonly IReadOnlyList<OwnerQuestion> Questions = new[]
    {
        new OwnerQuestion("mfa_email", "Accounts", "Is multi-factor sign-in (a code or app prompt) turned on for every business email account?",
            "Multi-factor sign-in on email", "Turn on multi-factor sign-in for every email account. Email is the key to resetting every other password.", 1),
        new OwnerQuestion("mfa_money", "Accounts", "Is it on for online banking, payroll and payment accounts too?",
            "Multi-factor sign-in on money accounts", "Turn on multi-factor sign-in for banking, payroll and payment accounts.", 1),
        new OwnerQuestion("password_manager", "Accounts", "Does the business use a password manager, instead of reused or written-down passwords?",
            "Password manager", "Use a password manager so every account has its own long password.", 2),
        new OwnerQuestion("backup_offsite", "Backups", "Are business files backed up automatically to a second place (cloud or off-site)?",
            "Automatic off-site backup", "Set up automatic backup to a second place, so one failed drive or ransomware attack doesn't take the business's files.", 1),
        new OwnerQuestion("backup_tested", "Backups", "Has someone restored a file from that backup in the last 3 months to test it?",
            "Backup restore tested", "Test a restore every few months. A backup that has never been restored may not work when it's needed.", 2),
        new OwnerQuestion("wifi_guest", "Network", "Do customers and guests use a separate guest Wi-Fi, not the business network?",
            "Separate guest Wi-Fi", "Put customers and guests on a separate guest Wi-Fi so their devices can't reach business computers.", 2),
        new OwnerQuestion("router_password", "Network", "Has the router's admin password been changed from the one it came with?",
            "Router admin password changed", "Change the router's admin password from the default and keep its firmware updated.", 2),
        new OwnerQuestion("offboarding", "Accounts", "When someone leaves, are their accounts and access removed that same day?",
            "Former staff access removed", "Remove a departing person's accounts, passwords and keys on their last day.", 2),
        new OwnerQuestion("training", "People", "Has staff been shown how to spot phishing emails and scam calls in the last year?",
            "Staff know how to spot scams", "Give staff a short refresher on phishing emails, fake invoices and \"tech support\" scam calls.", 3),
    };

    private static readonly int[] RiskyPorts = { 21, 23, 5900, 5800 };

    public static List<CheckResult> Evaluate(SecurityFacts f, IReadOnlyDictionary<string, Answer> answers, DateTime now)
    {
        var r = new List<CheckResult>();
        void Add(string id, string area, string title, CheckStatus s, string found, string fix = "", int priority = 2) =>
            r.Add(new CheckResult { Id = id, Area = area, Title = title, Status = s, Found = found, Fix = s is CheckStatus.Fail or CheckStatus.Warn ? fix : "", Priority = priority });
        void NotChecked(string id, string area, string title, string why) => Add(id, area, title, CheckStatus.NotChecked, why);
        const string Dev = "Device protection", Acc = "Accounts", Exp = "Network exposure", Sw = "Software";
        string NeedsAdmin(string what) => f.RanAsAdministrator ? $"Windows didn't report {what}." : $"Run as administrator to check {what}.";
        const string Unknown = "Windows didn't report this, or the check didn't finish.";
        bool managedSignIn = f.DomainJoined == true || f.EntraJoined == true;

        // ---------- Device protection ----------
        var bl = f.BitLockerSystemDrive;
        if (bl.Length == 0) NotChecked("bitlocker", Dev, "Drive encryption (BitLocker)", NeedsAdmin("drive encryption"));
        else if (bl.StartsWith("On", StringComparison.OrdinalIgnoreCase))
            Add("bitlocker", Dev, "Drive encryption (BitLocker)", CheckStatus.Pass, "The Windows drive is encrypted. Make sure the recovery key is saved somewhere safe.");
        else if (bl.StartsWith("Suspended", StringComparison.OrdinalIgnoreCase))
            Add("bitlocker", Dev, "Drive encryption (BitLocker)", CheckStatus.Fail,
                "The drive is encrypted, but protection is off: paused (often for an update), or Device Encryption is waiting for its recovery key to be backed up.",
                "Resume BitLocker protection. On Windows Home, sign in with a Microsoft account (or back up the recovery key) so Device Encryption turns on.", 1);
        else if (bl.StartsWith("Encrypting", StringComparison.OrdinalIgnoreCase))
            Add("bitlocker", Dev, "Drive encryption (BitLocker)", CheckStatus.Warn, "Encryption has started but isn't finished.",
                "Leave the computer on until encryption finishes, then check again.", 2);
        else if (bl.StartsWith("Unavailable", StringComparison.OrdinalIgnoreCase))
            Add("bitlocker", Dev, "Drive encryption (BitLocker)", CheckStatus.Fail,
                "This edition of Windows doesn't offer drive encryption. If this computer is lost or stolen, anyone can read its files.",
                "Upgrade to Windows Pro to use BitLocker, or use another full-drive encryption the business is comfortable with.", 1);
        else
            Add("bitlocker", Dev, "Drive encryption (BitLocker)", CheckStatus.Fail, "The Windows drive isn't encrypted. If this computer is lost or stolen, anyone can read its files.",
                "Turn on BitLocker (or Device Encryption) and save the recovery key somewhere safe, off this computer.", 1);

        // Defender's numbers only count when Defender is the antivirus doing the work.
        var enabledAv = f.Antivirus.Where(a => a.Enabled).ToList();
        bool defenderActive = enabledAv.Any(a => IsMicrosoftDefender(a.Name))
                              || (f.Antivirus.Count == 0 && f.DefenderRealTime == true);
        int? sigAge = defenderActive ? f.DefenderSignatureAgeDays : null;
        if (f.Antivirus.Count == 0 && f.DefenderRealTime is null)
            NotChecked("antivirus", Dev, "Antivirus", "Windows Security Center didn't report any antivirus. Check it by hand.");
        else if (f.Antivirus.Count > 0 && enabledAv.Count == 0)
            Add("antivirus", Dev, "Antivirus", CheckStatus.Fail, "No antivirus is turned on: " + string.Join(", ", f.Antivirus.Select(a => a.Name)) + ".",
                "Turn antivirus back on (Microsoft Defender is built in) and find out why it was off.", 1);
        else if (f.Antivirus.Count == 0 && f.DefenderRealTime == false)
            Add("antivirus", Dev, "Antivirus", CheckStatus.Fail, "Microsoft Defender's real-time protection is off.", "Turn real-time protection back on.", 1);
        else if (enabledAv.Any(a => !a.UpToDate) || sigAge >= SignaturesFailDays)
            Add("antivirus", Dev, "Antivirus", CheckStatus.Fail, "Antivirus is on but its virus definitions are out of date" + (sigAge is { } age ? $" ({age} days old)." : "."),
                "Update the antivirus and check that its updates (or Windows Update) are working.", 1);
        else if (sigAge >= SignaturesWarnDays)
            Add("antivirus", Dev, "Antivirus", CheckStatus.Warn, $"Virus definitions are {sigAge} days old.", "Run Windows Update to refresh them.", 2);
        else
            Add("antivirus", Dev, "Antivirus", CheckStatus.Pass, "On and up to date: " + (enabledAv.Count > 0 ? string.Join(", ", enabledAv.Select(a => a.Name)) : "Microsoft Defender") + ".");

        if (defenderActive && f.DefenderRealTime == false && f.Antivirus.Count > 0)
            Add("realtime", Dev, "Real-time protection", CheckStatus.Fail, "Microsoft Defender's real-time protection is off.", "Turn real-time protection back on in Windows Security.", 1);
        if (defenderActive && f.DefenderTamperProtected == false)
            Add("tamper", Dev, "Tamper protection", CheckStatus.Warn, "Defender's tamper protection is off, so malware could switch Defender off.",
                "Turn on Tamper Protection in Windows Security, Virus & threat protection settings.", 2);

        var otherFw = f.OtherFirewalls.Where(x => x.Enabled).ToList();
        var profiles = new List<(string Name, bool? On)> { ("Private", f.FirewallPrivate), ("Public", f.FirewallPublic) };
        if (f.DomainJoined == true) profiles.Insert(0, ("Domain", f.FirewallDomain));
        if (otherFw.Count > 0)
            Add("firewall", Dev, "Firewall", CheckStatus.Pass, "On: " + string.Join(", ", otherFw.Select(x => x.Name)) + ".");
        else if (f.FirewallServiceRunning == false)
            Add("firewall", Dev, "Firewall", CheckStatus.Fail, "The Windows Firewall service isn't running, so no firewall is protecting this computer.",
                "Start the Windows Defender Firewall service and set it to start automatically.", 1);
        else if (profiles.All(x => x.On is null))
            NotChecked("firewall", Dev, "Firewall", Unknown);
        else if (profiles.Any(x => x.On == false))
            Add("firewall", Dev, "Firewall", CheckStatus.Fail, "The firewall is off for: " + string.Join(", ", profiles.Where(x => x.On == false).Select(x => x.Name)) + " networks.",
                "Turn the Windows Firewall on for every network type.", 1);
        else Add("firewall", Dev, "Firewall", CheckStatus.Pass, "On for every network type.");

        if (f.OsName.Length == 0 && f.OsBuild.Length == 0) NotChecked("os_support", Dev, "Windows still supported", Unknown);
        else
        {
            var sup = WindowsSupport.For(f.OsName, f.OsBuild, f.OsEdition);
            if (sup.Ends is not { } ends)
                Add("os_support", Dev, "Windows still supported", CheckStatus.Info, $"{sup.Version}. Check Microsoft's support dates for this version.");
            else if (ends <= now)
                Add("os_support", Dev, "Windows still supported", CheckStatus.Fail,
                    $"{sup.Version} stopped getting security updates on {ends:MMMM d, yyyy}." + (sup.Note.Length > 0 ? " " + sup.Note : ""),
                    "Update to the current version of Windows 11 if the computer supports it (free through Windows Update), or plan to replace it.", 1);
            else if ((ends - now).TotalDays <= 90)
                Add("os_support", Dev, "Windows still supported", CheckStatus.Warn, $"{sup.Version} stops getting security updates on {ends:MMMM d, yyyy}.",
                    "Install the latest Windows 11 version through Windows Update before then.", 2);
            else
                Add("os_support", Dev, "Windows still supported", CheckStatus.Pass, $"{sup.Version}, supported until {ends:MMMM yyyy}.");
        }

        if (f.LastUpdateInstalled is { } upd)
        {
            var days = Math.Max(0, (int)(now - upd).TotalDays);
            var st = days > UpdatesFailDays ? CheckStatus.Fail : days > UpdatesWarnDays ? CheckStatus.Warn : CheckStatus.Pass;
            Add("updates", Dev, "Windows updates", st, $"The newest update was installed {days} days ago.",
                "Run Windows Update and find out why updates stopped.", st == CheckStatus.Fail ? 1 : 2);
        }
        else NotChecked("updates", Dev, "Windows updates", Unknown);

        if (f.SecureBoot is { } sb)
            Add("secureboot", Dev, "Secure Boot", sb ? CheckStatus.Pass : CheckStatus.Warn,
                sb ? "On: only trusted software can start the computer." : "Off: harmful software could load before Windows starts.",
                "Turn on Secure Boot in the computer's firmware (UEFI) settings.", 3);
        else NotChecked("secureboot", Dev, "Secure Boot", Unknown);
        if (f.TpmReady is { } tpm)
            Add("tpm", Dev, "Security chip (TPM)", tpm ? CheckStatus.Pass : CheckStatus.Warn,
                tpm ? "Present and ready." : "Missing or not ready. It's needed for BitLocker without a startup password, and for Windows 11.",
                "Turn on the TPM (sometimes called PTT or fTPM) in the firmware settings.", 3);
        else NotChecked("tpm", Dev, "Security chip (TPM)", NeedsAdmin("the security chip"));

        // ---------- Accounts ----------
        if (f.UacEnabled == false)
            Add("uac", Acc, "Admin prompts (UAC)", CheckStatus.Fail, "User Account Control is off, so every program runs with full control of the computer.",
                "Turn User Account Control back on.", 1);
        else if (f.UacEnabled == true && f.UacNeverNotify == true)
            Add("uac", Acc, "Admin prompts (UAC)", CheckStatus.Warn, "User Account Control is set to never ask before programs make changes.",
                "Set User Account Control to notify (the default level).", 2);
        else if (f.UacEnabled == true) Add("uac", Acc, "Admin prompts (UAC)", CheckStatus.Pass, "On.");
        else NotChecked("uac", Acc, "Admin prompts (UAC)", Unknown);

        if (f.CurrentUserIsAdmin == true)
            Add("daily_admin", Acc, "Daily account isn't an admin", CheckStatus.Warn,
                "The person signed in uses an administrator account for everyday work. Anything they click on gets admin power too.",
                "Use a standard account for daily work, and a separate admin account only when installing or changing things.", 2);
        else if (f.CurrentUserIsAdmin == false) Add("daily_admin", Acc, "Daily account isn't an admin", CheckStatus.Pass, "The signed-in account is a standard account.");
        else NotChecked("daily_admin", Acc, "Daily account isn't an admin",
            f.AccountsChecked ? "Couldn't tell: the admin group includes domain or work-account groups. Check the signed-in account by hand." : Unknown);

        if (!f.AccountsChecked) NotChecked("admins", Acc, "Admin accounts", Unknown);
        else if (f.LocalAdmins.Count > 0)
            Add("admins", Acc, "Admin accounts", f.LocalAdmins.Count > 2 ? CheckStatus.Warn : CheckStatus.Info,
                $"{f.LocalAdmins.Count} account(s) or group(s) can administer this computer: {string.Join(", ", f.LocalAdmins)}." +
                (f.AdminListIncomplete ? " Some members couldn't be named." : ""),
                "Remove admin rights from anyone who doesn't need them.", 2);
        if (f.BuiltInAdminEnabled == true)
            Add("builtin_admin", Acc, "Built-in Administrator account", CheckStatus.Warn,
                "The built-in Administrator account is turned on. Attackers know its name, so it's a common target.",
                "Turn it off and use a named admin account instead.", 2);
        if (f.GuestEnabled == true)
            Add("guest", Acc, "Guest account", CheckStatus.Fail, "The Guest account is turned on, so anyone can sign in without a password.",
                "Turn off the Guest account.", 1);
        if (f.PasswordNotRequired.Count > 0)
            Add("pw_required", Acc, "Accounts allowed a blank password", CheckStatus.Info,
                "Windows' setting allows these accounts a blank password: " + string.Join(", ", f.PasswordNotRequired) +
                ". Windows setup often leaves this on; make sure each one actually has a password.");

        if (managedSignIn)
            Add("pw_policy", Acc, "Password rules", CheckStatus.Info,
                f.EntraJoined == true ? "Signed in with work accounts (Microsoft Entra). Password rules come from Microsoft 365, not this computer."
                                      : "This computer is on a domain; password rules come from the domain.");
        else
        {
            if (f.MinPasswordLength is { } len)
                Add("pw_length", Acc, "Password length rule", len >= MinGoodPasswordLength ? CheckStatus.Pass : CheckStatus.Warn,
                    len == 0 ? "Windows doesn't require any minimum password length." : $"Windows requires at least {len} characters.",
                    $"Require at least {MinGoodPasswordLength} characters (a few random words is easy to remember).", 2);
            else NotChecked("pw_length", Acc, "Password length rule", Unknown);
            if (f.LockoutThreshold is { } lt)
                Add("lockout", Acc, "Lock out after wrong passwords", lt is > 0 and <= 10 ? CheckStatus.Pass : CheckStatus.Warn,
                    lt == 0 ? "Wrong passwords never lock the account, so someone can keep guessing." : $"The account locks after {lt} wrong passwords.",
                    "Lock accounts for a few minutes after 10 or fewer wrong passwords.", 2);
            else NotChecked("lockout", Acc, "Lock out after wrong passwords", Unknown);
        }

        if (f.AutoLogon == true)
            Add("autologon", Acc, "Automatic sign-in", f.AutoLogonPasswordStored == true ? CheckStatus.Fail : CheckStatus.Warn,
                "Windows signs in by itself when it starts" + (f.AutoLogonPasswordStored == true ? ", with the password stored in the registry." : "."),
                "Turn off automatic sign-in so the computer asks for a password.", f.AutoLogonPasswordStored == true ? 1 : 2);

        if (!f.ScreenLockChecked) NotChecked("screenlock", Acc, "Screen locks when away", Unknown);
        else if (f.ScreenLockSeconds is { } lockSecs)
            Add("screenlock", Acc, "Screen locks when away", lockSecs <= ScreenLockMaxSeconds ? CheckStatus.Pass : CheckStatus.Warn,
                $"The computer locks after {Math.Max(1, lockSecs / 60)} minute(s) of no use (plugged in).", "Lock the screen after 15 minutes or less.", 3);
        else
            Add("screenlock", Acc, "Screen locks when away", CheckStatus.Warn,
                "The computer never locks by itself when plugged in: it doesn't sleep with sign-in required, and no password-protected screen saver is set.",
                "Set it to sleep (or show a screen saver) after 15 minutes or less, with sign-in required on wake.", 3);

        // ---------- Network exposure ----------
        if (f.RemoteDesktopOn == true)
            Add("rdp", Exp, "Remote Desktop", f.RemoteDesktopNla == false ? CheckStatus.Fail : CheckStatus.Warn,
                "Remote Desktop is turned on" + (f.RemoteDesktopNla == false ? " without requiring sign-in first (Network Level Authentication)." : "."),
                "Turn Remote Desktop off unless it's needed. If it is, require Network Level Authentication and never open it to the internet on the router.",
                f.RemoteDesktopNla == false ? 1 : 2);
        else if (f.RemoteDesktopOn == false) Add("rdp", Exp, "Remote Desktop", CheckStatus.Pass, "Off.");
        else NotChecked("rdp", Exp, "Remote Desktop", Unknown);

        if (f.Smb1On == true)
            Add("smb1", Exp, "Old file-sharing protocol (SMBv1)", CheckStatus.Fail, "SMBv1 is turned on. Ransomware like WannaCry spread through it.",
                "Turn off SMB 1.0 in Windows Features (check first that no very old copier or NAS needs it).", 1);
        else if (f.Smb1On == false) Add("smb1", Exp, "Old file-sharing protocol (SMBv1)", CheckStatus.Pass, "Off.");
        else NotChecked("smb1", Exp, "Old file-sharing protocol (SMBv1)", Unknown);

        if (f.PowerShell2On == true)
            Add("ps2", Exp, "Old PowerShell 2.0", CheckStatus.Warn, "PowerShell 2.0 is installed. Attackers use it to get around newer security logging.",
                "Turn off Windows PowerShell 2.0 in Windows Features.", 3);

        var risky = f.ListeningPorts.Intersect(RiskyPorts).OrderBy(p => p).ToList();
        if (!f.PortsChecked) NotChecked("ports", Exp, "Risky services listening", Unknown);
        else if (risky.Count > 0)
            Add("ports", Exp, "Risky services listening", CheckStatus.Fail,
                "These services accept connections: " + string.Join(", ", risky.Select(PortName)) + ". They send data without encryption or are often attacked.",
                "Turn off these services, or replace them with encrypted ones.", 1);
        else Add("ports", Exp, "Risky services listening", CheckStatus.Pass, "No FTP, Telnet or VNC services are listening.");

        if (f.Shares.Count > 0)
            Add("shares", Exp, "Shared folders", CheckStatus.Info, "Shared with the network: " + string.Join(", ", f.Shares) + ". Make sure only the right people can open them.");

        if (f.AutoRunOff == true) Add("autorun", Exp, "AutoRun", CheckStatus.Pass, "Off for every kind of drive.");
        else if (f.AutoRunOff == false)
            Add("autorun", Exp, "AutoRun", CheckStatus.Info, "AutoRun is on for CDs and DVDs (Windows' default). USB drives can't start programs by themselves on current Windows.");

        // ---------- Software ----------
        if (!f.SoftwareChecked) NotChecked("remote_apps", Sw, "Remote-control programs", Unknown);
        else if (f.RemoteAccessApps.Count > 0)
            Add("remote_apps", Sw, "Remote-control programs", CheckStatus.Warn,
                "Installed: " + string.Join(", ", f.RemoteAccessApps) + ". Scammers often install these during fake \"tech support\" calls.",
                "Confirm with the owner that each one is expected and used. Remove any that aren't.", 2);
        else Add("remote_apps", Sw, "Remote-control programs", CheckStatus.Pass, "None found.");

        if (f.EndOfLifeApps.Count > 0)
            Add("eol_apps", Sw, "Software that no longer gets security fixes", CheckStatus.Fail,
                "Installed: " + string.Join(", ", f.EndOfLifeApps) + ".", "Uninstall them, or upgrade to a supported version.", 1);

        // ---------- Owner's answers ----------
        var noBackup = answers.TryGetValue("backup_offsite", out var bk) && bk == Answer.No;
        foreach (var q in Questions)
        {
            if (q.Id == "backup_tested" && noBackup) continue; // nothing to test yet; the backup fix covers it
            var a = answers.TryGetValue(q.Id, out var v) ? v : Answer.NotAsked;
            switch (a)
            {
                case Answer.Yes: Add("q_" + q.Id, q.Area, q.Title, CheckStatus.Pass, "The owner said yes."); break;
                case Answer.No: Add("q_" + q.Id, q.Area, q.Title, q.Priority == 1 ? CheckStatus.Fail : CheckStatus.Warn, "The owner said no.", q.FixIfNot, q.Priority); break;
                case Answer.NotSure: Add("q_" + q.Id, q.Area, q.Title, CheckStatus.Warn, "The owner wasn't sure.", "Find out, and if not: " + q.FixIfNot, q.Priority); break;
                default: NotChecked("q_" + q.Id, q.Area, q.Title, "Not asked."); break;
            }
        }
        return r;
    }

    /// <summary>Microsoft's own antivirus ("Microsoft Defender Antivirus", "Windows Defender"), not products like Bitdefender.</summary>
    public static bool IsMicrosoftDefender(string name) =>
        name.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase) || name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase);

    public static string PortName(int port) => port switch
    {
        21 => "FTP (port 21)", 23 => "Telnet (port 23)", 5900 => "VNC (port 5900)", 5800 => "VNC web (port 5800)",
        3389 => "Remote Desktop (port 3389)", _ => $"port {port}",
    };

    /// <summary>The fixes, most important first: Fail before Warn, then by priority.</summary>
    public static List<CheckResult> TopFixes(IEnumerable<CheckResult> results) => results
        .Where(x => x.Status is CheckStatus.Fail or CheckStatus.Warn)
        .OrderBy(x => x.Status == CheckStatus.Fail ? 0 : 1).ThenBy(x => x.Priority).ToList();

    // ---------- Software lists ----------

    /// <summary>Remote-control programs worth confirming with the owner (matched by name).</summary>
    public static readonly string[] RemoteAccessNames =
    {
        "TeamViewer", "AnyDesk", "ConnectWise Control", "ScreenConnect", "LogMeIn", "GoToAssist", "GoTo Resolve", "Splashtop",
        "RustDesk", "UltraViewer", "Ammyy", "RealVNC", "TightVNC", "UltraVNC", "Chrome Remote Desktop", "Zoho Assist", "Atera",
        "SupRemo", "AeroAdmin", "Remote Utilities", "NinjaOne", "Kaseya", "N-able",
    };

    /// <summary>Software whose makers stopped security fixes (matched by name).</summary>
    public static readonly string[] EndOfLifeNames =
    {
        "Adobe Flash Player", "Microsoft Silverlight", "QuickTime 7", "Java(TM) 6", "Java 6 Update", "Java(TM) 7", "Java 7 Update",
        "Adobe Reader 9", "Adobe Reader X", "Adobe Reader XI", "Adobe Acrobat XI",
    };

    private static readonly System.Text.RegularExpressions.Regex OldOffice = new(
        @"^Microsoft Office\b.*\b(2007|2010|2013|2016|2019)\b", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    private static readonly string[] OfficeNotProducts = { "Interop", "Runtime", "Viewer", "Proofing", "Language", "Shared", "Components", "Click-to-Run", "Access database engine", "Compatibility Pack", "Validation" };

    /// <summary>End-of-life software: the name list plus Microsoft Office 2007 to 2019 suites (support for 2016 and 2019 ended October 14, 2025).</summary>
    public static List<string> EndOfLife(IEnumerable<string> installed)
    {
        var list = installed.ToList();
        var office = list.Where(p => OldOffice.IsMatch(p) && !OfficeNotProducts.Any(n => p.Contains(n, StringComparison.OrdinalIgnoreCase)));
        return Match(list, EndOfLifeNames).Concat(office).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static List<string> Match(IEnumerable<string> installed, IEnumerable<string> names) =>
        installed.Where(p => names.Any(n => p.Contains(n, StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
}
