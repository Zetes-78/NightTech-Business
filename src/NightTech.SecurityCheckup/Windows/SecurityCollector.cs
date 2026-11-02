using System.Globalization;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using NightTech.Business.Core.Security;

namespace NightTech.SecurityCheckup.Windows;

/// <summary>
/// Reads security settings from Windows. Read only: it never changes a setting, and it never reads passwords
/// (for automatic sign-in it only notes whether a stored password exists).
/// </summary>
public static class SecurityCollector
{
    public static bool IsAdministrator
    {
        get
        {
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }

    private static readonly TimeSpan StepLimit = TimeSpan.FromSeconds(60);

    public static SecurityFacts Collect(IProgress<string> progress)
    {
        var f = new SecurityFacts { ComputerName = Environment.MachineName, RanAsAdministrator = IsAdministrator };
        Step(f, progress, "Windows and updates", () => Windows(f));
        Step(f, progress, "drive encryption", () => BitLocker(f));
        Step(f, progress, "antivirus", () => Antivirus(f));
        Step(f, progress, "the firewall", () => Firewall(f));
        Step(f, progress, "Secure Boot and the security chip", () => BootSecurity(f));
        Step(f, progress, "accounts", () => Accounts(f));
        Step(f, progress, "password rules", () => PasswordPolicy(f));
        Step(f, progress, "sign-in and screen lock", () => SignIn(f));
        Step(f, progress, "remote access and file sharing", () => Exposure(f));
        Step(f, progress, "Windows features", () => Features(f));
        Step(f, progress, "installed programs", () => Software(f));
        progress.Report("Checks finished.");
        return f;
    }

    private static void Step(SecurityFacts f, IProgress<string> progress, string label, Action check)
    {
        progress.Report($"Checking {label}...");
        try
        {
            var task = Task.Run(check);
            if (!task.Wait(StepLimit)) f.Notes.Add($"Checking {label} took too long and was skipped.");
        }
        catch (AggregateException ex) { f.Notes.Add($"Couldn't check {label}: {ex.InnerException?.Message ?? ex.Message}"); }
        catch (Exception ex) { f.Notes.Add($"Couldn't check {label}: {ex.Message}"); }
    }

    // ---------------- Helpers ----------------

    private static List<ManagementBaseObject> Query(string scope, string wql)
    {
        var list = new List<ManagementBaseObject>();
        using var searcher = new ManagementObjectSearcher(scope, wql);
        searcher.Options.Timeout = TimeSpan.FromSeconds(30);
        using var results = searcher.Get();
        foreach (ManagementBaseObject o in results) list.Add(o);
        return list;
    }

    private static object? Get(ManagementBaseObject o, string p) { try { return o[p]; } catch { return null; } }
    private static string Str(ManagementBaseObject o, string p) => Get(o, p)?.ToString()?.Trim() ?? "";
    private static long? Long(ManagementBaseObject o, string p)
    {
        var v = Get(o, p);
        if (v is null) return null;
        try { return Convert.ToInt64(v, CultureInfo.InvariantCulture); } catch { return null; }
    }
    private static bool? Bool(ManagementBaseObject o, string p) => Get(o, p) is bool b ? b : null;

    private static object? Reg(RegistryHive hive, string path, string name)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = root.OpenSubKey(path);
            return key?.GetValue(name);
        }
        catch { return null; }
    }

    private static int? RegInt(RegistryHive hive, string path, string name) => Reg(hive, path, name) switch
    {
        int i => i,
        string s when int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) => n,
        _ => null,
    };

    // ---------------- Checks ----------------

    private static void Windows(SecurityFacts f)
    {
        foreach (var o in Query(@"root\CIMV2", "SELECT Caption, BuildNumber FROM Win32_OperatingSystem"))
        {
            f.OsName = Str(o, "Caption");
            f.OsBuild = Str(o, "BuildNumber");
        }
        DateTime? newest = null;
        foreach (var o in Query(@"root\CIMV2", "SELECT InstalledOn FROM Win32_QuickFixEngineering"))
        {
            var s = Str(o, "InstalledOn");
            if ((DateTime.TryParse(s, CultureInfo.GetCultureInfo("en-US"), DateTimeStyles.None, out var d) ||
                 DateTime.TryParse(s, CultureInfo.CurrentCulture, DateTimeStyles.None, out d)) && d <= DateTime.Now.AddDays(1) && (newest is null || d > newest))
                newest = d;
        }
        f.LastUpdateInstalled = newest;
        foreach (var o in Query(@"root\CIMV2", "SELECT PartOfDomain FROM Win32_ComputerSystem")) f.DomainJoined = Bool(o, "PartOfDomain");
    }

    private static void BitLocker(SecurityFacts f)
    {
        if (!f.RanAsAdministrator) return;
        var letter = (Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\").TrimEnd('\\');
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\CIMV2\Security\MicrosoftVolumeEncryption",
                $"SELECT * FROM Win32_EncryptableVolume WHERE DriveLetter='{letter}'");
            using var results = searcher.Get();
            foreach (ManagementObject o in results)
            {
                if (Long(o, "ProtectionStatus") == 1) { f.BitLockerSystemDrive = "On"; return; }
                long? conversion = null;
                try
                {
                    using var outParams = o.InvokeMethod("GetConversionStatus", null, null);
                    conversion = outParams is null ? null : Long(outParams, "ConversionStatus");
                }
                catch { /* older Windows */ }
                f.BitLockerSystemDrive = conversion is null or 0 ? "Off" : "Suspended";
                return;
            }
            f.BitLockerSystemDrive = "Off";
        }
        catch (ManagementException)
        {
            f.BitLockerSystemDrive = "Off"; // this edition of Windows has no BitLocker information
            f.Notes.Add("This edition of Windows didn't report BitLocker, so it's treated as off.");
        }
    }

    private static void Antivirus(SecurityFacts f)
    {
        try
        {
            foreach (var o in Query(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct"))
                f.Antivirus.Add(AntivirusInfo.FromProductState(Str(o, "displayName"), (uint)(Long(o, "productState") ?? 0)));
        }
        catch (ManagementException) { /* Windows Server has no Security Center */ }
        try
        {
            foreach (var o in Query(@"root\Microsoft\Windows\Defender", "SELECT RealTimeProtectionEnabled, AntivirusSignatureAge, IsTamperProtected FROM MSFT_MpComputerStatus"))
            {
                f.DefenderRealTime = Bool(o, "RealTimeProtectionEnabled");
                var age = Long(o, "AntivirusSignatureAge");
                f.DefenderSignatureAgeDays = age is >= 0 and < 65535 ? (int)age : null;
                f.DefenderTamperProtected = Bool(o, "IsTamperProtected");
            }
        }
        catch (ManagementException) { /* Defender not installed or replaced */ }
    }

    private static void Firewall(SecurityFacts f)
    {
        // Group Policy settings win over local ones.
        bool? Profile(string local, string policy)
        {
            var p = RegInt(RegistryHive.LocalMachine, $@"SOFTWARE\Policies\Microsoft\WindowsFirewall\{policy}", "EnableFirewall");
            var l = RegInt(RegistryHive.LocalMachine, $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{local}", "EnableFirewall");
            return (p ?? l) is { } v ? v != 0 : null;
        }
        f.FirewallDomain = Profile("DomainProfile", "DomainProfile");
        f.FirewallPrivate = Profile("StandardProfile", "PrivateProfile");
        f.FirewallPublic = Profile("PublicProfile", "PublicProfile");
    }

    private static void BootSecurity(SecurityFacts f)
    {
        using (var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (var key = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State"))
        {
            // No key: the PC starts in legacy BIOS mode, where Secure Boot isn't available.
            f.SecureBoot = key is null ? false : key.GetValue("UEFISecureBootEnabled") is int sb ? sb == 1 : null;
        }
        if (!f.RanAsAdministrator) return;
        try
        {
            var tpms = Query(@"root\CIMV2\Security\MicrosoftTpm", "SELECT IsEnabled_InitialValue, IsActivated_InitialValue FROM Win32_Tpm");
            f.TpmReady = tpms.Count > 0 && tpms.Any(o => Bool(o, "IsEnabled_InitialValue") == true && Bool(o, "IsActivated_InitialValue") == true);
        }
        catch (ManagementException) { f.TpmReady = false; }
    }

    private static void Accounts(SecurityFacts f)
    {
        f.UacEnabled = (RegInt(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA") ?? 1) != 0;

        foreach (var o in Query(@"root\CIMV2", "SELECT Name, SID, Disabled, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount=True"))
        {
            var sid = Str(o, "SID");
            var name = Str(o, "Name");
            var enabled = Bool(o, "Disabled") == false;
            if (sid.EndsWith("-500", StringComparison.Ordinal)) f.BuiltInAdminEnabled = enabled;
            if (sid.EndsWith("-501", StringComparison.Ordinal)) f.GuestEnabled = enabled;
            if (enabled && Bool(o, "PasswordRequired") == false && !sid.EndsWith("-501", StringComparison.Ordinal)) f.PasswordNotRequired.Add(name);
        }

        // Members of the local Administrators group (found by its fixed SID, so it works in any language).
        var computer = Environment.MachineName;
        var adminGroup = Query(@"root\CIMV2", "SELECT Name FROM Win32_Group WHERE LocalAccount=True AND SID='S-1-5-32-544'").Select(o => Str(o, "Name")).FirstOrDefault();
        bool hasGroupMembers = false;
        if (!string.IsNullOrEmpty(adminGroup))
        {
            var path = $"Win32_Group.Domain='{computer.Replace("'", "\\'")}',Name='{adminGroup.Replace("'", "\\'")}'";
            foreach (var m in Query(@"root\CIMV2", $"ASSOCIATORS OF {{{path}}} WHERE AssocClass=Win32_GroupUser ResultRole=PartComponent"))
            {
                var cls = m.ClassPath?.ClassName ?? "";
                var domain = Str(m, "Domain");
                var name = Str(m, "Name");
                var display = string.Equals(domain, computer, StringComparison.OrdinalIgnoreCase) ? name : $@"{domain}\{name}";
                if (cls == "Win32_Group") { hasGroupMembers = true; f.LocalAdmins.Add(display + " (group)"); }
                else if (Bool(m, "Disabled") != true) f.LocalAdmins.Add(display);
            }
        }

        // Is the person signed in at the screen an admin? (Not this program's account, which may be an admin used to elevate.)
        var console = Query(@"root\CIMV2", "SELECT UserName FROM Win32_ComputerSystem").Select(o => Str(o, "UserName")).FirstOrDefault() ?? "";
        if (console.Length > 0)
        {
            var shortName = console.Contains('\\') ? console[(console.IndexOf('\\') + 1)..] : console;
            bool listed = f.LocalAdmins.Any(a => a.Equals(console, StringComparison.OrdinalIgnoreCase) || a.Equals(shortName, StringComparison.OrdinalIgnoreCase));
            f.CurrentUserIsAdmin = listed ? true : hasGroupMembers ? null : false;
            if (!console.Equals($@"{Environment.UserDomainName}\{Environment.UserName}", StringComparison.OrdinalIgnoreCase))
                f.Notes.Add($"Running as {Environment.UserName}, while {console} is signed in. The screen-lock check reflects {Environment.UserName}'s settings.");
        }
    }

    private static void PasswordPolicy(SecurityFacts f)
    {
        if (NetUserModalsGet(null, 0, out var p0) == 0 && p0 != IntPtr.Zero)
        {
            try { f.MinPasswordLength = Marshal.ReadInt32(p0, 0); } // USER_MODALS_INFO_0.usrmod0_min_passwd_len
            finally { NetApiBufferFree(p0); }
        }
        if (NetUserModalsGet(null, 3, out var p3) == 0 && p3 != IntPtr.Zero)
        {
            try { f.LockoutThreshold = Marshal.ReadInt32(p3, 8); } // USER_MODALS_INFO_3: duration, observation window, threshold
            finally { NetApiBufferFree(p3); }
        }
    }

    private static void SignIn(SecurityFacts f)
    {
        const string winlogon = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        f.AutoLogon = Reg(RegistryHive.LocalMachine, winlogon, "AutoAdminLogon") as string == "1";
        if (f.AutoLogon == true)
        {
            // Only whether a password is stored. Its value is never read.
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = root.OpenSubKey(winlogon);
            f.AutoLogonPasswordStored = key?.GetValueNames().Contains("DefaultPassword", StringComparer.OrdinalIgnoreCase) == true;
        }

        var machine = RegInt(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs");
        if (machine is > 0) { f.ScreenLockSeconds = machine; return; }
        foreach (var path in new[] { @"Software\Policies\Microsoft\Windows\Control Panel\Desktop", @"Control Panel\Desktop" })
        {
            var active = Reg(RegistryHive.CurrentUser, path, "ScreenSaveActive") as string;
            var secure = Reg(RegistryHive.CurrentUser, path, "ScreenSaverIsSecure") as string;
            var timeout = RegInt(RegistryHive.CurrentUser, path, "ScreenSaveTimeOut");
            if (active == "1" && secure == "1" && timeout is > 0) { f.ScreenLockSeconds = timeout; return; }
        }
    }

    private static void Exposure(SecurityFacts f)
    {
        const string ts = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
        const string tsPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
        var deny = RegInt(RegistryHive.LocalMachine, tsPolicy, "fDenyTSConnections") ?? RegInt(RegistryHive.LocalMachine, ts, "fDenyTSConnections");
        f.RemoteDesktopOn = deny is { } d ? d == 0 : null;
        if (f.RemoteDesktopOn == true)
        {
            var nla = RegInt(RegistryHive.LocalMachine, tsPolicy, "UserAuthentication") ?? RegInt(RegistryHive.LocalMachine, ts + @"\WinStations\RDP-Tcp", "UserAuthentication");
            f.RemoteDesktopNla = nla is { } n ? n == 1 : null;
        }

        f.ListeningPorts = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
            .Where(e => !IPAddress.IsLoopback(e.Address)).Select(e => e.Port).Distinct().OrderBy(p => p).ToList();

        foreach (var o in Query(@"root\CIMV2", "SELECT Name, Path, Type FROM Win32_Share"))
        {
            var name = Str(o, "Name");
            if (Long(o, "Type") == 0 && !name.EndsWith("$", StringComparison.Ordinal)) f.Shares.Add($"{name} ({Str(o, "Path")})");
        }

        int? Auto(RegistryHive h) => RegInt(h, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun");
        var noAuto = RegInt(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoAutorun");
        f.AutoRunOff = noAuto == 1 || (Auto(RegistryHive.LocalMachine) ?? Auto(RegistryHive.CurrentUser)) is 0xFF;
    }

    private static void Features(SecurityFacts f)
    {
        foreach (var o in Query(@"root\CIMV2",
                     "SELECT Name, InstallState FROM Win32_OptionalFeature WHERE Name='SMB1Protocol' OR Name='MicrosoftWindowsPowerShellV2Root'"))
        {
            var on = Long(o, "InstallState") == 1;
            if (Str(o, "Name") == "SMB1Protocol") f.Smb1On = on;
            else f.PowerShell2On = on;
        }
        // Not listed at all means the feature doesn't exist on this Windows (off).
        f.Smb1On ??= false;
        f.PowerShell2On ??= false;
    }

    private static void Software(SecurityFacts f)
    {
        const string uninstall = @"Software\Microsoft\Windows\CurrentVersion\Uninstall";
        var names = new List<string>();
        foreach (var (hive, view) in new[] { (RegistryHive.LocalMachine, RegistryView.Registry64), (RegistryHive.LocalMachine, RegistryView.Registry32), (RegistryHive.CurrentUser, RegistryView.Default) })
        {
            using var root = RegistryKey.OpenBaseKey(hive, view);
            using var key = root.OpenSubKey(uninstall);
            if (key is null) continue;
            foreach (var sub in key.GetSubKeyNames())
            {
                using var app = key.OpenSubKey(sub);
                if (app?.GetValue("DisplayName") is string n && !string.IsNullOrWhiteSpace(n) && app.GetValue("SystemComponent") is not 1)
                    names.Add(n.Trim());
            }
        }
        f.RemoteAccessApps = SecurityRules.Match(names, SecurityRules.RemoteAccessNames);
        f.EndOfLifeApps = SecurityRules.Match(names, SecurityRules.EndOfLifeNames);
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserModalsGet(string? server, int level, out IntPtr buffer);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
