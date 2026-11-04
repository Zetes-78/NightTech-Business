using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Management;
using System.Text.Json;
using Microsoft.Win32;
using NightTech.Business.Core.Sentinel;
using NightTech.Shield.Windows;
using ShieldCore = NightTech.Shield.Core;

namespace NightTech.Sentinel.Agent;

/// <summary>Reads the PC's health for a check-in. Only reads; each part that fails becomes a note, not a crash.</summary>
public static class HealthCollector
{
    public static HealthReport Collect(AgentConfig cfg, string version, ShieldCore.ScanResult? shield)
    {
        var r = new HealthReport { DeviceId = cfg.DeviceId, TakenUtc = DateTime.UtcNow, AgentVersion = version, Computer = Environment.MachineName, Policy = cfg.Policy };
        Try(r, "Computer", () => Computer(r));
        Try(r, "Signed-in user", () => r.LoggedOnUser = TargetUser.Find().Name);
        Try(r, "Drives", () => Drives(r));
        Try(r, "Disk space", () => Volumes(r));
        Try(r, "Updates", () => Updates(r));
        Try(r, "Firewall", () => Firewall(r));
        Try(r, "Battery", () => Battery(r));
        Try(r, "Event log", () => Events(r));
        Try(r, "Backup", () => Backup(r));
        if (shield is not null) FromShield(r, shield);
        return r;
    }

    private static void Try(HealthReport r, string what, Action a)
    {
        try { a(); }
        catch (Exception e) when (e is ManagementException or System.Runtime.InteropServices.COMException or IOException or UnauthorizedAccessException
                                      or InvalidOperationException or EventLogException or JsonException or FormatException)
        {
            r.Notes.Add($"{what}: couldn't check ({e.Message.Trim()}).");
        }
    }

    private static List<ManagementBaseObject> Query(string scope, string wql)
    {
        using var s = new ManagementObjectSearcher(new ManagementScope(scope), new ObjectQuery(wql),
            new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(30), ReturnImmediately = false });
        return s.Get().Cast<ManagementBaseObject>().ToList();
    }

    private static object? Get(ManagementBaseObject o, string p) { try { return o[p]; } catch (ManagementException) { return null; } }
    private static string Str(ManagementBaseObject o, string p) => Get(o, p)?.ToString()?.Trim() ?? "";
    private static long? Num(ManagementBaseObject o, string p) => Get(o, p) is IConvertible c ? c.ToInt64(CultureInfo.InvariantCulture) : null;

    private static void Computer(HealthReport r)
    {
        foreach (var o in Query(@"root\cimv2", "SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem"))
        {
            r.Make = Str(o, "Manufacturer");
            r.Model = Str(o, "Model");
            r.RamBytes = Num(o, "TotalPhysicalMemory") ?? 0;
        }
        foreach (var o in Query(@"root\cimv2", "SELECT SerialNumber FROM Win32_BIOS")) r.Serial = Str(o, "SerialNumber");
        foreach (var o in Query(@"root\cimv2", "SELECT Caption, BuildNumber, LastBootUpTime FROM Win32_OperatingSystem"))
        {
            r.WindowsBuild = Str(o, "BuildNumber");
            var caption = Str(o, "Caption").Replace("Microsoft ", "", StringComparison.Ordinal);
            using var cv = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var display = cv?.GetValue("DisplayVersion") as string ?? "";
            r.Windows = caption + (display.Length > 0 ? " " + display : "");
            if (Get(o, "LastBootUpTime") is string boot && boot.Length > 0) r.LastBootUtc = ManagementDateTimeConverter.ToDateTime(boot).ToUniversalTime();
        }
    }

    private static void Drives(HealthReport r)
    {
        const string ns = @"root\Microsoft\Windows\Storage";
        var counters = new Dictionary<string, ManagementBaseObject>();
        try
        {
            foreach (var c in Query(ns, "SELECT DeviceId, Wear, Temperature, ReadErrorsUncorrected, PowerOnHours FROM MSFT_StorageReliabilityCounter"))
                counters[Str(c, "DeviceId")] = c;
        }
        catch (ManagementException) { r.Notes.Add("Drive wear: Windows didn't report it."); }
        foreach (var d in Query(ns, "SELECT DeviceId, FriendlyName, SerialNumber, MediaType, HealthStatus, Size FROM MSFT_PhysicalDisk"))
        {
            var drive = new DriveHealth
            {
                Name = Str(d, "FriendlyName"), Serial = Str(d, "SerialNumber"), SizeBytes = Num(d, "Size"),
                MediaType = Num(d, "MediaType") switch { 3 => "HDD", 4 => "SSD", 5 => "SCM", _ => "" },
                Health = Num(d, "HealthStatus") switch { 0 => "Healthy", 1 => "Warning", 2 => "Unhealthy", _ => "Unknown" },
            };
            if (drive.Serial.Length == 0) drive.Serial = Str(d, "DeviceId");
            if (counters.TryGetValue(Str(d, "DeviceId"), out var c))
            {
                drive.WearPercent = Num(c, "Wear") is long w && w is > 0 and <= 100 ? (int)w : null;
                drive.TemperatureC = Num(c, "Temperature") is long t && t is > 0 and < 120 ? (int)t : null;
                drive.ReadErrorsUncorrected = Num(c, "ReadErrorsUncorrected");
                drive.PowerOnHours = Num(c, "PowerOnHours");
            }
            r.Drives.Add(drive);
        }
    }

    private static void Volumes(HealthReport r)
    {
        var system = Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
        foreach (var d in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady))
            r.Volumes.Add(new VolumeSpace
            {
                Name = d.Name.TrimEnd('\\'), Label = d.VolumeLabel, SizeBytes = d.TotalSize, FreeBytes = d.AvailableFreeSpace,
                IsSystem = string.Equals(d.Name, system, StringComparison.OrdinalIgnoreCase),
            });
    }

    private static void Updates(HealthReport r)
    {
        DateTime? latest = null;
        foreach (var o in Query(@"root\cimv2", "SELECT InstalledOn FROM Win32_QuickFixEngineering"))
            if (DateTime.TryParse(Str(o, "InstalledOn"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var d) && d <= DateTime.Now.AddDays(1) && (latest is null || d > latest))
                latest = d;
        r.Updates.LastInstalledUtc = latest?.ToUniversalTime();
        using var lm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        r.Updates.RebootPending =
            lm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") is not null
            || lm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") is not null;
    }

    private static void Firewall(HealthReport r)
    {
        var profiles = Query(@"root\StandardCimv2", "SELECT Name, Enabled FROM MSFT_NetFirewallProfile");
        if (profiles.Count == 0) return;
        r.FirewallOn = profiles.All(p => Num(p, "Enabled") == 1);
    }

    private static void Battery(HealthReport r)
    {
        long? full = null, design = null;
        try
        {
            foreach (var o in Query(@"root\wmi", "SELECT FullChargedCapacity FROM BatteryFullChargedCapacity")) full = Num(o, "FullChargedCapacity");
            foreach (var o in Query(@"root\wmi", "SELECT DesignedCapacity FROM BatteryStaticData")) design = Num(o, "DesignedCapacity");
        }
        catch (ManagementException) { return; }   // desktops have no battery classes
        if (full is > 0 && design is > 0) r.BatteryHealthPercent = (int)Math.Clamp(full.Value * 100 / design.Value, 0, 100);
    }

    private static void Events(HealthReport r)
    {
        long since = (long)TimeSpan.FromDays(7).TotalMilliseconds;
        int Count(string xpath)
        {
            var q = new EventLogQuery("System", PathType.LogName, xpath) { ReverseDirection = true };
            using var reader = new EventLogReader(q);
            int n = 0;
            for (var e = reader.ReadEvent(); e is not null && n < 1000; e = reader.ReadEvent()) { e.Dispose(); n++; }
            return n;
        }
        string Recent(string filter) => $"*[System[{filter} and TimeCreated[timediff(@SystemTime) <= {since}]]]";
        r.UnexpectedShutdowns7d = Count(Recent("Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41)"));
        r.BlueScreens7d = Count(Recent("Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and (EventID=1001)"));
        r.DiskErrors7d = Count(Recent("(Provider[@Name='disk'] and (EventID=7 or EventID=51 or EventID=153)) or (Provider[@Name='Ntfs'] and (EventID=55))"));
    }

    /// <summary>Backup Buddy's status file for the signed-in person.</summary>
    private static void Backup(HealthReport r)
    {
        var user = TargetUser.Find();
        var path = Path.Combine(user.Roaming, "Night Tech Solutions", "Backup Buddy", "settings.json");
        if (!File.Exists(path)) return;
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var root = doc.RootElement;
        r.Backup.Tool = "Backup Buddy";
        if (root.TryGetProperty("lastSuccess", out var ok) && ok.ValueKind == JsonValueKind.Object)
        {
            if (ok.TryGetProperty("when", out var w) && w.TryGetDateTime(out var when)) r.Backup.LastSuccessUtc = when.ToUniversalTime();
            if (ok.TryGetProperty("destination", out var d) && d.ValueKind == JsonValueKind.String) r.Backup.Destination = d.GetString() ?? "";
        }
        if (root.TryGetProperty("lastRun", out var run) && run.ValueKind == JsonValueKind.Object)
        {
            if (run.TryGetProperty("when", out var w) && w.TryGetDateTime(out var when)) r.Backup.LastRunUtc = when.ToUniversalTime();
            if (run.TryGetProperty("success", out var s) && s.ValueKind == JsonValueKind.False) r.Backup.LastRunFailed = true;
            if (r.Backup.Destination.Length == 0 && run.TryGetProperty("destination", out var d) && d.ValueKind == JsonValueKind.String) r.Backup.Destination = d.GetString() ?? "";
        }
    }

    /// <summary>Antivirus and security findings come from Night Tech Shield's own scan.</summary>
    private static void FromShield(HealthReport r, ShieldCore.ScanResult s)
    {
        var f = s.Facts;
        var on = f.SecurityCenter.Where(p => p.Enabled).ToList();
        r.Antivirus.Products = f.SecurityCenter.Select(p => p.Name).ToList();
        bool defenderInCharge = f.Defender.Present && !f.Defender.IsPassive;
        r.Antivirus.Enabled = on.Count > 0 || defenderInCharge && f.Defender.AntivirusEnabled == true;
        r.Antivirus.UpToDate = on.Count > 0 ? on.All(p => p.UpToDate) : null;
        if (defenderInCharge)
        {
            r.Antivirus.RealTime = f.Defender.RealTime;
            r.Antivirus.DefenderSignatureAgeDays = f.Defender.SignatureAgeDays;
            r.Antivirus.DefenderQuickScanAgeDays = f.Defender.QuickScanAgeDays;
        }
        r.SecurityCheckedUtc = f.TakenUtc;
        r.Security = s.Findings.Select(x => new SecurityItem
        {
            Id = x.Id, Area = x.Area, Severity = x.Severity.ToString(), Title = x.Title, Detail = x.Detail,
            Fixable = x.Fix != ShieldCore.FixKind.None, Recommended = x.Recommended,
        }).ToList();
        foreach (var n in f.Notes) r.Notes.Add("Shield: " + n);
    }
}
