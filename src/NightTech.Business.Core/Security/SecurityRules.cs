namespace NightTech.Business.Core.Security;

/// <summary>
/// Turns what a computer showed, plus the owner's answers, into plain-language results with fixes.
/// Results describe what was checked at the time; they are not a guarantee the business is secure.
/// </summary>
public static class SecurityRules
{
    public static readonly DateTime Windows10EndOfSupport = new(2025, 10, 14);
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
        const string Dev = "Device protection", Acc = "Accounts", Exp = "Network exposure", Sw = "Software";
        string NeedsAdmin(string what) => f.RanAsAdministrator ? $"Windows didn't report {what}." : $"Run as administrator to check {what}.";

        // ---------- Device protection ----------
        var bl = f.BitLockerSystemDrive;
        if (bl.Length == 0) Add("bitlocker", Dev, "Drive encryption (BitLocker)", CheckStatus.NotChecked, NeedsAdmin("drive encryption"));
        else if (bl.StartsWith("On", StringComparison.OrdinalIgnoreCase))
            Add("bitlocker", Dev, "Drive encryption (BitLocker)", CheckStatus.Pass, "The Windows drive is encrypted. Make sure the recovery key is saved somewhere safe.");
        else if (bl.StartsWith("Suspended", StringComparison.OrdinalIgnoreCase))
            Add("bitlocker", Dev, "Drive encryption (BitLocker)", CheckStatus.Warn, "The drive is encrypted, but protection is paused.",
                "Resume BitLocker protection (it pauses for some updates and should resume on its own).", 2);
        else
            Add("bitlocker", Dev, "Drive encryption (BitLocker)", CheckStatus.Fail, "The Windows drive isn't encrypted. If this computer is lost or stolen, anyone can read its files.",
                "Turn on BitLocker (or Device Encryption) and save the recovery key somewhere safe, off this computer.", 1);

        if (f.Antivirus.Count == 0)
            Add("antivirus", Dev, "Antivirus", CheckStatus.NotChecked, "Windows Security Center didn't report any antivirus (normal on Windows Server).");
        else if (!f.Antivirus.Any(a => a.Enabled))
            Add("antivirus", Dev, "Antivirus", CheckStatus.Fail, "No antivirus is turned on: " + string.Join(", ", f.Antivirus.Select(a => a.Name)) + ".",
                "Turn antivirus back on (Microsoft Defender is built in) and find out why it was off.", 1);
        else if (f.Antivirus.Where(a => a.Enabled).Any(a => !a.UpToDate) || f.DefenderSignatureAgeDays >= SignaturesFailDays)
            Add("antivirus", Dev, "Antivirus", CheckStatus.Fail, "Antivirus is on but its virus definitions are out of date" +
                (f.DefenderSignatureAgeDays is { } age ? $" ({age} days old)." : "."), "Update the antivirus and check that Windows Update is working.", 1);
        else if (f.DefenderSignatureAgeDays >= SignaturesWarnDays)
            Add("antivirus", Dev, "Antivirus", CheckStatus.Warn, $"Virus definitions are {f.DefenderSignatureAgeDays} days old.", "Run Windows Update to refresh them.", 2);
        else
            Add("antivirus", Dev, "Antivirus", CheckStatus.Pass, "On and up to date: " + string.Join(", ", f.Antivirus.Where(a => a.Enabled).Select(a => a.Name)) + ".");

        if (f.DefenderRealTime == false && f.Antivirus.Count(a => a.Enabled) <= 1 && f.Antivirus.Any(a => a.Enabled && a.Name.Contains("Defender", StringComparison.OrdinalIgnoreCase)))
            Add("realtime", Dev, "Real-time protection", CheckStatus.Fail, "Microsoft Defender's real-time protection is off.", "Turn real-time protection back on in Windows Security.", 1);
        if (f.DefenderTamperProtected == false && f.Antivirus.Any(a => a.Enabled && a.Name.Contains("Defender", StringComparison.OrdinalIgnoreCase)))
            Add("tamper", Dev, "Tamper protection", CheckStatus.Warn, "Defender's tamper protection is off, so malware could switch Defender off.",
                "Turn on Tamper Protection in Windows Security, Virus & threat protection settings.", 2);

        var fw = new[] { ("Domain", f.FirewallDomain), ("Private", f.FirewallPrivate), ("Public", f.FirewallPublic) };
        if (fw.All(x => x.Item2 is null))
            Add("firewall", Dev, "Firewall", CheckStatus.NotChecked, "Windows didn't report its firewall settings.");
        else if (fw.Any(x => x.Item2 == false))
            Add("firewall", Dev, "Firewall", CheckStatus.Fail, "The firewall is off for: " + string.Join(", ", fw.Where(x => x.Item2 == false).Select(x => x.Item1)) + " networks.",
                "Turn the Windows Firewall on for every network type.", 1);
        else Add("firewall", Dev, "Firewall", CheckStatus.Pass, "On for every network type.");

        var ltsc = f.OsName.Contains("LTSC", StringComparison.OrdinalIgnoreCase) || f.OsName.Contains("LTSB", StringComparison.OrdinalIgnoreCase);
        if (f.OsName.Contains("Windows 10", StringComparison.OrdinalIgnoreCase) && !ltsc && now >= Windows10EndOfSupport)
            Add("os_support", Dev, "Windows still supported", CheckStatus.Fail,
                "Windows 10 stopped getting regular security updates on October 14, 2025 (unless enrolled in Extended Security Updates).",
                "Upgrade to Windows 11 if the computer supports it, enroll in Extended Security Updates, or plan to replace it.", 1);
        else if (f.OsName.Length > 0)
            Add("os_support", Dev, "Windows still supported", CheckStatus.Pass, f.OsName + ".");

        if (f.LastUpdateInstalled is { } upd)
        {
            var days = (int)(now - upd).TotalDays;
            var s = days > UpdatesFailDays ? CheckStatus.Fail : days > UpdatesWarnDays ? CheckStatus.Warn : CheckStatus.Pass;
            Add("updates", Dev, "Windows updates", s, $"The newest update was installed {days} days ago.",
                "Run Windows Update and find out why updates stopped.", s == CheckStatus.Fail ? 1 : 2);
        }
        else Add("updates", Dev, "Windows updates", CheckStatus.NotChecked, "Windows didn't report its installed updates.");

        if (f.SecureBoot is { } sb)
            Add("secureboot", Dev, "Secure Boot", sb ? CheckStatus.Pass : CheckStatus.Warn,
                sb ? "On: only trusted software can start the computer." : "Off: harmful software could load before Windows starts.",
                "Turn on Secure Boot in the computer's firmware (UEFI) settings.", 3);
        if (f.TpmReady is { } tpm)
            Add("tpm", Dev, "Security chip (TPM)", tpm ? CheckStatus.Pass : CheckStatus.Warn,
                tpm ? "Present and ready." : "Missing or not ready. It's needed for BitLocker without a startup password, and for Windows 11.",
                "Turn on the TPM (sometimes called PTT or fTPM) in the firmware settings.", 3);

        // ---------- Accounts ----------
        if (f.UacEnabled == false)
            Add("uac", Acc, "Admin prompts (UAC)", CheckStatus.Fail, "User Account Control is off, so every program runs with full control of the computer.",
                "Turn User Account Control back on.", 1);
        else if (f.UacEnabled == true) Add("uac", Acc, "Admin prompts (UAC)", CheckStatus.Pass, "On.");

        if (f.CurrentUserIsAdmin == true)
            Add("daily_admin", Acc, "Daily account isn't an admin", CheckStatus.Warn,
                "The person signed in uses an administrator account for everyday work. Anything they click on gets admin power too.",
                "Use a standard account for daily work, and a separate admin account only when installing or changing things.", 2);
        else if (f.CurrentUserIsAdmin == false) Add("daily_admin", Acc, "Daily account isn't an admin", CheckStatus.Pass, "The signed-in account is a standard account.");

        if (f.LocalAdmins.Count > 0)
        {
            var many = f.LocalAdmins.Count > 2;
            Add("admins", Acc, "Number of admin accounts", many ? CheckStatus.Warn : CheckStatus.Info,
                $"{f.LocalAdmins.Count} account(s) can administer this computer: {string.Join(", ", f.LocalAdmins)}.",
                "Remove admin rights from anyone who doesn't need them.", 2);
        }
        if (f.BuiltInAdminEnabled == true)
            Add("builtin_admin", Acc, "Built-in Administrator account", CheckStatus.Warn,
                "The built-in Administrator account is turned on. Attackers know its name, so it's a common target.",
                "Turn it off and use a named admin account instead.", 2);
        if (f.GuestEnabled == true)
            Add("guest", Acc, "Guest account", CheckStatus.Fail, "The Guest account is turned on, so anyone can sign in without a password.",
                "Turn off the Guest account.", 1);

        if (f.PasswordNotRequired.Count > 0)
            Add("pw_required", Acc, "Every account needs a password", CheckStatus.Warn,
                "Windows allows these accounts to have a blank password: " + string.Join(", ", f.PasswordNotRequired) + ". (Windows setup often leaves this on.)",
                "Make sure each of these accounts has a password, or turn off accounts nobody uses.", 2);

        if (f.DomainJoined != true)
        {
            if (f.MinPasswordLength is { } len)
                Add("pw_length", Acc, "Password length rule", len >= MinGoodPasswordLength ? CheckStatus.Pass : CheckStatus.Warn,
                    len == 0 ? "Windows doesn't require any minimum password length." : $"Windows requires at least {len} characters.",
                    $"Require at least {MinGoodPasswordLength} characters (a few random words is easy to remember).", 2);
            if (f.LockoutThreshold is { } lt)
                Add("lockout", Acc, "Lock out after wrong passwords", lt is > 0 and <= 10 ? CheckStatus.Pass : CheckStatus.Warn,
                    lt == 0 ? "Wrong passwords never lock the account, so someone can keep guessing." : $"The account locks after {lt} wrong passwords.",
                    "Lock accounts for a few minutes after 10 or fewer wrong passwords.", 2);
        }
        else Add("pw_policy", Acc, "Password rules", CheckStatus.Info, "This computer is on a domain; password rules come from the domain.");

        if (f.AutoLogon == true)
            Add("autologon", Acc, "Automatic sign-in", f.AutoLogonPasswordStored == true ? CheckStatus.Fail : CheckStatus.Warn,
                "Windows signs in by itself when it starts" + (f.AutoLogonPasswordStored == true ? ", with the password stored in the registry." : "."),
                "Turn off automatic sign-in so the computer asks for a password.", f.AutoLogonPasswordStored == true ? 1 : 2);

        if (f.ScreenLockSeconds is { } lockSecs)
            Add("screenlock", Acc, "Screen locks when away", lockSecs <= ScreenLockMaxSeconds ? CheckStatus.Pass : CheckStatus.Warn,
                $"The screen locks after {lockSecs / 60} minute(s) of no use.", "Lock the screen after 15 minutes or less.", 3);
        else if (f.ComputerName.Length > 0)
            Add("screenlock", Acc, "Screen locks when away", CheckStatus.Warn, "No automatic screen lock was found for this account.",
                "Set the screen to lock after 15 minutes or less of no use.", 3);

        // ---------- Network exposure ----------
        if (f.RemoteDesktopOn == true)
            Add("rdp", Exp, "Remote Desktop", f.RemoteDesktopNla == false ? CheckStatus.Fail : CheckStatus.Warn,
                "Remote Desktop is turned on" + (f.RemoteDesktopNla == false ? " without requiring sign-in first (Network Level Authentication)." : "."),
                "Turn Remote Desktop off unless it's needed. If it is, require Network Level Authentication and never open it to the internet on the router.",
                f.RemoteDesktopNla == false ? 1 : 2);
        else if (f.RemoteDesktopOn == false) Add("rdp", Exp, "Remote Desktop", CheckStatus.Pass, "Off.");

        if (f.Smb1On == true)
            Add("smb1", Exp, "Old file-sharing protocol (SMBv1)", CheckStatus.Fail, "SMBv1 is turned on. Ransomware like WannaCry spread through it.",
                "Turn off SMB 1.0 in Windows Features (check first that no very old copier or NAS needs it).", 1);
        else if (f.Smb1On == false) Add("smb1", Exp, "Old file-sharing protocol (SMBv1)", CheckStatus.Pass, "Off.");

        if (f.PowerShell2On == true)
            Add("ps2", Exp, "Old PowerShell 2.0", CheckStatus.Warn, "PowerShell 2.0 is installed. Attackers use it to get around newer security logging.",
                "Turn off Windows PowerShell 2.0 in Windows Features.", 3);

        var risky = f.ListeningPorts.Intersect(RiskyPorts).OrderBy(p => p).ToList();
        if (risky.Count > 0)
            Add("ports", Exp, "Risky services listening", CheckStatus.Fail,
                "These services accept connections: " + string.Join(", ", risky.Select(PortName)) + ". They send data without encryption or are often attacked.",
                "Turn off these services, or replace them with encrypted ones.", 1);
        else if (f.ListeningPorts.Count > 0)
            Add("ports", Exp, "Risky services listening", CheckStatus.Pass, "No FTP, Telnet or VNC services are listening.");

        if (f.Shares.Count > 0)
            Add("shares", Exp, "Shared folders", CheckStatus.Info, "Shared with the network: " + string.Join(", ", f.Shares) + ". Make sure only the right people can open them.");

        if (f.AutoRunOff == true) Add("autorun", Exp, "AutoRun", CheckStatus.Pass, "Off for every kind of drive.");
        else if (f.AutoRunOff == false)
            Add("autorun", Exp, "AutoRun", CheckStatus.Info, "AutoRun is on for CDs and DVDs (Windows' default). USB drives can't start programs by themselves on current Windows.");

        // ---------- Software ----------
        if (f.RemoteAccessApps.Count > 0)
            Add("remote_apps", Sw, "Remote-control programs", CheckStatus.Warn,
                "Installed: " + string.Join(", ", f.RemoteAccessApps) + ". Scammers often install these during fake \"tech support\" calls.",
                "Confirm with the owner that each one is expected and used. Remove any that aren't.", 2);
        else Add("remote_apps", Sw, "Remote-control programs", CheckStatus.Pass, "None found.");

        if (f.EndOfLifeApps.Count > 0)
            Add("eol_apps", Sw, "Software that no longer gets security fixes", CheckStatus.Fail,
                "Installed: " + string.Join(", ", f.EndOfLifeApps) + ".", "Uninstall them. Their makers no longer fix security problems in them.", 1);

        // ---------- Owner's answers ----------
        foreach (var q in Questions)
        {
            var a = answers.TryGetValue(q.Id, out var v) ? v : Answer.NotAsked;
            switch (a)
            {
                case Answer.Yes: Add("q_" + q.Id, q.Area, q.Title, CheckStatus.Pass, "The owner said yes."); break;
                case Answer.No: Add("q_" + q.Id, q.Area, q.Title, q.Priority == 1 ? CheckStatus.Fail : CheckStatus.Warn, "The owner said no.", q.FixIfNot, q.Priority); break;
                case Answer.NotSure: Add("q_" + q.Id, q.Area, q.Title, CheckStatus.Warn, "The owner wasn't sure.", "Find out, and if not: " + q.FixIfNot, q.Priority); break;
                default: Add("q_" + q.Id, q.Area, q.Title, CheckStatus.NotChecked, "Not asked."); break;
            }
        }
        return r;
    }

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
        "Adobe Flash Player", "Microsoft Silverlight", "QuickTime 7", "Java(TM) 6", "Java 6", "Java(TM) 7", "Java 7",
        "Adobe Reader 9", "Adobe Reader X", "Adobe Reader XI", "Microsoft Office 2010", "Microsoft Office 2013",
        "Microsoft Office Professional Plus 2010", "Microsoft Office Professional Plus 2013",
    };

    public static List<string> Match(IEnumerable<string> installed, IEnumerable<string> names) =>
        installed.Where(p => names.Any(n => p.Contains(n, StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
}
