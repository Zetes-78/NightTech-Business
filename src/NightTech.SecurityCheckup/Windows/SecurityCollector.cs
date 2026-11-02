using System.Globalization;
using System.Reflection;
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
        Step(f, progress, "Windows and updates", Windows);
        Step(f, progress, "drive encryption", BitLocker);
        Step(f, progress, "antivirus", Antivirus);
        Step(f, progress, "the firewall", Firewall);
        Step(f, progress, "Secure Boot and the security chip", BootSecurity);
        Step(f, progress, "accounts", Accounts);
        Step(f, progress, "password rules", PasswordPolicy);
        Step(f, progress, "sign-in and screen lock", SignIn);
        Step(f, progress, "remote access and file sharing", Exposure);
        Step(f, progress, "Windows features", Features);
        Step(f, progress, "installed programs", Software);
        progress.Report("Checks finished.");
        return f;
    }

    /// <summary>
    /// Runs one check on its own copy of the facts. Only a check that finishes in time is merged in, so a slow check
    /// that keeps running in the background can never change a report that's already been written.
    /// </summary>
    private static void Step(SecurityFacts f, IProgress<string> progress, string label, Action<SecurityFacts> check)
    {
        progress.Report($"Checking {label}...");
        var part = new SecurityFacts
        {
            ComputerName = f.ComputerName, RanAsAdministrator = f.RanAsAdministrator, OsEdition = f.OsEdition,
            DomainJoined = f.DomainJoined, EntraJoined = f.EntraJoined,
        };
        try
        {
            var task = Task.Run(() => check(part));
            if (!task.Wait(StepLimit)) { f.Notes.Add($"Checking {label} took too long and was skipped."); return; }
            Merge(f, part);
        }
        catch (AggregateException ex) { f.Notes.Add($"Couldn't check {label}: {ex.InnerException?.Message ?? ex.Message}"); }
        catch (Exception ex) { f.Notes.Add($"Couldn't check {label}: {ex.Message}"); }
    }

    /// <summary>Copies everything a finished check found (non-empty values) into the facts.</summary>
    private static void Merge(SecurityFacts into, SecurityFacts part)
    {
        foreach (var p in typeof(SecurityFacts).GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (!p.CanWrite || p.Name is nameof(SecurityFacts.ComputerName) or nameof(SecurityFacts.RanAsAdministrator)) continue;
            var v = p.GetValue(part);
            if (p.Name == nameof(SecurityFacts.Notes)) { into.Notes.AddRange(part.Notes); continue; }
            bool hasValue = v switch
            {
                null => false,
                string str => str.Length > 0,
                System.Collections.ICollection c => c.Count > 0,
                bool b when p.PropertyType == typeof(bool) => b,   // "checked" flags: only a true counts
                _ => true,                                          // nullable values: any answer counts, false included
            };
            if (hasValue) p.SetValue(into, v);
        }
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
        f.OsEdition = Reg(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "EditionID") as string ?? "";
        foreach (var o in Query(@"root\CIMV2", "SELECT PartOfDomain FROM Win32_ComputerSystem")) f.DomainJoined = Bool(o, "PartOfDomain");
        using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (var join = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"))
            f.EntraJoined = join is not null && join.SubKeyCount > 0;
        f.LastUpdateInstalled = LastUpdateFromHistory() ?? LastUpdateFromHotfixes();
    }

    /// <summary>Newest successful update in Windows Update's own history (dates come back as real dates, in any language).</summary>
    private static DateTime? LastUpdateFromHistory()
    {
        try
        {
            if (Type.GetTypeFromProgID("Microsoft.Update.Session") is not { } t) return null;
            dynamic session = Activator.CreateInstance(t)!;
            dynamic searcher = session.CreateUpdateSearcher();
            int total = searcher.GetTotalHistoryCount();
            if (total <= 0) return null;
            dynamic history = searcher.QueryHistory(0, Math.Min(total, 100));
            DateTime? newest = null;
            foreach (dynamic e in history)
            {
                // Operation 1 = installation; ResultCode 2 = succeeded, 3 = succeeded with errors.
                if ((int)e.Operation != 1 || ((int)e.ResultCode != 2 && (int)e.ResultCode != 3)) continue;
                DateTime d = ((DateTime)e.Date).ToLocalTime();
                if (newest is null || d > newest) newest = d;
            }
            return newest;
        }
        catch { return null; }
    }

    /// <summary>Fallback: the hotfix list. Only dates in an unambiguous format are trusted.</summary>
    private static DateTime? LastUpdateFromHotfixes()
    {
        DateTime? newest = null;
        foreach (var o in Query(@"root\CIMV2", "SELECT InstalledOn FROM Win32_QuickFixEngineering"))
        {
            var s = Str(o, "InstalledOn");
            if (DateTime.TryParseExact(s, new[] { "M/d/yyyy", "yyyyMMdd" }, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
                && d <= DateTime.Now.AddDays(1) && (newest is null || d > newest))
                newest = d;
        }
        return newest;
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
                // 0 decrypted, 1 encrypted, 2 encrypting, 3 decrypting, 4 encryption paused, 5 decryption paused
                f.BitLockerSystemDrive = conversion switch
                {
                    1 => "Suspended",
                    2 or 4 => "Encrypting",
                    _ => "Off",
                };
                return;
            }
            f.BitLockerSystemDrive = "Off";
        }
        catch (ManagementException)
        {
            // No BitLocker information at all: this edition of Windows doesn't offer drive encryption.
            f.BitLockerSystemDrive = "Unavailable";
        }
    }

    private static void Antivirus(SecurityFacts f)
    {
        try
        {
            foreach (var o in Query(@"root\SecurityCenter2", "SELECT displayName, productState FROM AntiVirusProduct"))
                f.Antivirus.Add(AntivirusInfo.FromProductState(Str(o, "displayName"), (uint)(Long(o, "productState") ?? 0)));
            foreach (var o in Query(@"root\SecurityCenter2", "SELECT displayName, productState FROM FirewallProduct"))
                f.OtherFirewalls.Add(AntivirusInfo.FromProductState(Str(o, "displayName"), (uint)(Long(o, "productState") ?? 0)));
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
        foreach (var o in Query(@"root\CIMV2", "SELECT State FROM Win32_Service WHERE Name='mpssvc'"))
            f.FirewallServiceRunning = Str(o, "State").Equals("Running", StringComparison.OrdinalIgnoreCase);

        // The settings in force right now (Group Policy included), from the firewall's own "active store".
        try
        {
            var ctx = new ManagementNamedValueCollection { { "PolicyStore", "ActiveStore" } };
            var scope = new ManagementScope(@"root\StandardCimv2");
            var options = new System.Management.EnumerationOptions { Context = ctx, Timeout = TimeSpan.FromSeconds(30) };
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT Name, Enabled FROM MSFT_NetFirewallProfile"), options);
            using var results = searcher.Get();
            foreach (ManagementBaseObject o in results)
            {
                // Enabled: 0 = False, 1 = True, 2 = not configured (which means on by default).
                bool on = Long(o, "Enabled") != 0;
                switch (Str(o, "Name"))
                {
                    case "Domain": f.FirewallDomain = on; break;
                    case "Private": f.FirewallPrivate = on; break;
                    case "Public": f.FirewallPublic = on; break;
                }
            }
        }
        catch (ManagementException) { /* fall back to the registry below */ }

        if (f.FirewallDomain is null && f.FirewallPrivate is null && f.FirewallPublic is null)
        {
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
        const string policy = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        f.UacEnabled = (RegInt(RegistryHive.LocalMachine, policy, "EnableLUA") ?? 1) != 0;
        f.UacNeverNotify = RegInt(RegistryHive.LocalMachine, policy, "ConsentPromptBehaviorAdmin") == 0;

        var localDisabled = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase); // SID -> disabled
        foreach (var o in Query(@"root\CIMV2", "SELECT Name, SID, Disabled, PasswordRequired FROM Win32_UserAccount WHERE LocalAccount=True"))
        {
            var sid = Str(o, "SID");
            var enabled = Bool(o, "Disabled") == false;
            localDisabled[sid] = !enabled;
            if (sid.EndsWith("-500", StringComparison.Ordinal)) f.BuiltInAdminEnabled = enabled;
            if (sid.EndsWith("-501", StringComparison.Ordinal)) f.GuestEnabled = enabled;
            if (enabled && Bool(o, "PasswordRequired") == false && !sid.EndsWith("-501", StringComparison.Ordinal)) f.PasswordNotRequired.Add(Str(o, "Name"));
        }

        // Members of the local Administrators group, by SID (works in any language and for work accounts).
        var adminsName = new SecurityIdentifier("S-1-5-32-544").Translate(typeof(NTAccount)).Value;
        adminsName = adminsName.Contains('\\') ? adminsName[(adminsName.IndexOf('\\') + 1)..] : adminsName;
        var memberSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool hasGroups = false;
        int rc = NetLocalGroupGetMembers(null, adminsName, 2, out var buf, -1, out int read, out _, IntPtr.Zero);
        if (rc != 0 || buf == IntPtr.Zero) throw new InvalidOperationException($"couldn't list the Administrators group (error {rc})");
        try
        {
            int size = Marshal.SizeOf<LOCALGROUP_MEMBERS_INFO_2>();
            for (int i = 0; i < read; i++)
            {
                var m = Marshal.PtrToStructure<LOCALGROUP_MEMBERS_INFO_2>(buf + i * size);
                string sid;
                try { sid = new SecurityIdentifier(m.Sid).Value; } catch { f.AdminListIncomplete = true; continue; }
                memberSids.Add(sid);
                var name = Marshal.PtrToStringUni(m.DomainAndName) ?? "";
                // SidTypeUser = 1. Everything else (groups, aliases, well-known groups, unknown) is treated as a group.
                if (m.SidUsage != 1)
                {
                    hasGroups = true;
                    if (name.Length == 0 || m.SidUsage == 8) f.AdminListIncomplete = true;
                    f.LocalAdmins.Add((name.Length > 0 ? ShortName(name) : sid) + " (group)");
                    continue;
                }
                if (localDisabled.TryGetValue(sid, out var disabled) && disabled) continue;
                if (name.Length == 0) f.AdminListIncomplete = true;
                f.LocalAdmins.Add(name.Length > 0 ? ShortName(name) : sid);
            }
        }
        finally { NetApiBufferFree(buf); }

        // Is the person signed in at the screen an admin? (Not this program's account, which may be an admin used to elevate.)
        var console = Query(@"root\CIMV2", "SELECT UserName FROM Win32_ComputerSystem").Select(o => Str(o, "UserName")).FirstOrDefault() ?? "";
        if (console.Length > 0)
        {
            string? consoleSid = null;
            try { consoleSid = new NTAccount(console).Translate(typeof(SecurityIdentifier)).Value; } catch { /* couldn't resolve */ }
            if (consoleSid is not null && memberSids.Contains(consoleSid)) f.CurrentUserIsAdmin = true;
            else if (consoleSid is not null && !hasGroups && !f.AdminListIncomplete) f.CurrentUserIsAdmin = false;
            // Otherwise it might be an admin through a group: leave it unknown.
            if (!console.Equals($@"{Environment.UserDomainName}\{Environment.UserName}", StringComparison.OrdinalIgnoreCase))
                f.Notes.Add($"Running as {Environment.UserName} while {console} is signed in. Screen lock and per-user programs were read for {Environment.UserName}.");
        }
        f.AccountsChecked = true;
    }

    private static string ShortName(string domainAndName)
    {
        var computer = Environment.MachineName + "\\";
        return domainAndName.StartsWith(computer, StringComparison.OrdinalIgnoreCase) ? domainAndName[computer.Length..] : domainAndName;
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

        // The shortest of: the machine inactivity limit, a password-protected screen saver, or sleep with sign-in required on wake.
        var candidates = new List<int>();
        var machine = RegInt(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs");
        if (machine is > 0) candidates.Add(machine.Value);
        foreach (var path in new[] { @"Software\Policies\Microsoft\Windows\Control Panel\Desktop", @"Control Panel\Desktop" })
        {
            var active = Reg(RegistryHive.CurrentUser, path, "ScreenSaveActive") as string;
            var secure = Reg(RegistryHive.CurrentUser, path, "ScreenSaverIsSecure") as string;
            var exe = Reg(RegistryHive.CurrentUser, @"Control Panel\Desktop", "SCRNSAVE.EXE") as string;
            var timeout = RegInt(RegistryHive.CurrentUser, path, "ScreenSaveTimeOut");
            if (active == "1" && secure == "1" && !string.IsNullOrWhiteSpace(exe) && timeout is > 0) { candidates.Add(timeout.Value); break; }
        }
        if (PowerValue(SubSleep, StandbyIdle) is { } sleep and > 0 && PowerValue(SubNone, ConsoleLock) is not 0)
            candidates.Add((int)Math.Min(sleep, int.MaxValue));
        f.ScreenLockSeconds = candidates.Count > 0 ? candidates.Min() : null;
        f.ScreenLockChecked = true;
    }

    private static readonly Guid SubSleep = new("238C9FA8-0AAD-41ED-83F4-97BE242C8F20");
    private static readonly Guid StandbyIdle = new("29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA");
    private static readonly Guid SubNone = new("FEA3413E-7E05-4911-9A71-700331F1C294");
    private static readonly Guid ConsoleLock = new("0E796BDB-100D-47D6-A2D5-F7D2DAA51F51");

    /// <summary>A setting of the active power plan when plugged in (seconds, or 1/0), or null if Windows won't say.</summary>
    private static uint? PowerValue(Guid subgroup, Guid setting)
    {
        if (PowerGetActiveScheme(IntPtr.Zero, out var schemePtr) != 0 || schemePtr == IntPtr.Zero) return null;
        try
        {
            var scheme = Marshal.PtrToStructure<Guid>(schemePtr);
            return PowerReadACValueIndex(IntPtr.Zero, ref scheme, ref subgroup, ref setting, out uint value) == 0 ? value : null;
        }
        finally { LocalFree(schemePtr); }
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
        f.PortsChecked = true;

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
        try
        {
            foreach (var o in Query(@"root\Microsoft\Windows\SMB", "SELECT EnableSMB1Protocol FROM MSFT_SmbServerConfiguration"))
                f.Smb1On = Bool(o, "EnableSMB1Protocol");
        }
        catch (ManagementException) { /* older Windows */ }
        if (f.Smb1On is null && RegInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1") is { } smb1)
            f.Smb1On = smb1 != 0;

        var ps2 = Query(@"root\CIMV2", "SELECT InstallState FROM Win32_OptionalFeature WHERE Name='MicrosoftWindowsPowerShellV2Root'");
        if (ps2.Count > 0) f.PowerShell2On = Long(ps2[0], "InstallState") == 1;
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
        f.EndOfLifeApps = SecurityRules.EndOfLife(names);
        f.SoftwareChecked = true;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserModalsGet(string? server, int level, out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupGetMembers(string? server, string group, int level, out IntPtr buffer, int prefMaxLen,
        out int entriesRead, out int totalEntries, IntPtr resumeHandle);

    [StructLayout(LayoutKind.Sequential)]
    private struct LOCALGROUP_MEMBERS_INFO_2
    {
        public IntPtr Sid;
        public int SidUsage;
        public IntPtr DomainAndName;
    }

    [DllImport("powrprof.dll")]
    private static extern uint PowerGetActiveScheme(IntPtr userRootPowerKey, out IntPtr activePolicyGuid);

    [DllImport("powrprof.dll")]
    private static extern uint PowerReadACValueIndex(IntPtr rootPowerKey, ref Guid schemeGuid, ref Guid subGroupOfPowerSettingsGuid,
        ref Guid powerSettingGuid, out uint acValueIndex);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr mem);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
