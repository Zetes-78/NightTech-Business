using System.Text;
using System.Text.Json;

namespace NightTech.Business.Core.Sentinel;

/// <summary>Turns a PC's health report into alerts a technician should look at. Plain words; no guesses.</summary>
public static class AlertRules
{
    public const double DiskWarnPercent = 15, DiskCriticalPercent = 5;
    public const int UpdatesWarnDays = 35, UpdatesCriticalDays = 60;
    public const int RebootWarnDays = 7;
    public const int BackupWarnDays = 3, BackupCriticalDays = 7;
    public const int BatteryWarnPercent = 60, BatteryCriticalPercent = 40;
    public const int DriveWearWarn = 80, DriveWearCritical = 95;
    public const int DefinitionsWarnDays = 3, DefinitionsCriticalDays = 7;
    public const int OfflineWarnHours = 24, OfflineCriticalHours = 72;

    public static List<Alert> Evaluate(HealthReport r, DateTime nowUtc)
    {
        var a = new List<Alert>();
        void Add(string key, AlertLevel level, string title, string detail) =>
            a.Add(new Alert { Key = key, Level = level, Title = title, Detail = detail, FirstSeenUtc = nowUtc, LastSeenUtc = nowUtc });

        if (r.HelpRequest.Length > 0)
            Add("help", AlertLevel.Critical, "Asked for help", $"{(r.LoggedOnUser.Length > 0 ? r.LoggedOnUser : "Someone")} sent: “{Short(r.HelpRequest, 500)}”");

        // Drives
        foreach (var d in r.Drives)
        {
            var name = d.Name.Length > 0 ? d.Name : "A drive";
            if (d.Health.Equals("Unhealthy", StringComparison.OrdinalIgnoreCase))
                Add("drive-health:" + d.Serial, AlertLevel.Critical, $"{name} is failing", "Windows reports the drive as unhealthy. Back up now and plan to replace it.");
            else if (d.Health.Equals("Warning", StringComparison.OrdinalIgnoreCase))
                Add("drive-health:" + d.Serial, AlertLevel.Warning, $"{name} reports a warning", "Windows reports a drive warning. Check its health and the backup.");
            if (d.WearPercent is int w && w >= DriveWearWarn)
                Add("drive-wear:" + d.Serial, w >= DriveWearCritical ? AlertLevel.Critical : AlertLevel.Warning, $"{name} is {w}% worn", "The SSD is near the end of its rated life. Plan to replace it.");
            if (d.ReadErrorsUncorrected is long e && e > 0)
                Add("drive-errors:" + d.Serial, AlertLevel.Critical, $"{name} has read errors", $"{e} uncorrected read error{(e == 1 ? "" : "s")}. Back up now.");
        }
        foreach (var v in r.Volumes.Where(v => v.SizeBytes > 0))
        {
            var pct = v.FreePercent;
            if (pct < DiskWarnPercent)
                Add("disk:" + v.Name, pct < DiskCriticalPercent ? AlertLevel.Critical : AlertLevel.Warning, $"{v.Name} is almost full",
                    $"{Format.Bytes(v.FreeBytes)} free of {Format.Bytes(v.SizeBytes)} ({pct:0}%).{(v.IsSystem ? " Windows slows down and updates fail when the system drive is full." : "")}");
        }
        if (r.DiskErrors7d > 0)
            Add("disk-events", AlertLevel.Warning, "Disk errors in the event log", $"{r.DiskErrors7d} disk error{(r.DiskErrors7d == 1 ? "" : "s")} in the last 7 days.");

        // Protection
        var av = r.Antivirus;
        if (av.Products.Count == 0 && av.Enabled is null) { }
        else if (av.Enabled == false)
            Add("av-off", AlertLevel.Critical, "Antivirus is off", av.Products.Count > 0 ? "Installed but turned off: " + string.Join(", ", av.Products) + "." : "No antivirus is turned on.");
        else if (av.RealTime == false)
            Add("av-realtime", AlertLevel.Critical, "Real-time protection is off", "Defender only checks files when asked.");
        if (av.UpToDate == false || av.DefenderSignatureAgeDays is int sig && sig >= DefinitionsWarnDays)
            Add("av-definitions", (av.DefenderSignatureAgeDays ?? 0) >= DefinitionsCriticalDays || av.UpToDate == false && av.DefenderSignatureAgeDays is null ? AlertLevel.Critical : AlertLevel.Warning,
                "Antivirus definitions are out of date", av.DefenderSignatureAgeDays is int d2 ? $"Last updated {d2} days ago." : "Windows says the antivirus isn't up to date.");
        if (r.FirewallOn == false)
            Add("firewall", AlertLevel.Critical, "Windows Firewall is off", "At least one firewall profile is turned off.");

        foreach (var s in r.Security.Where(s => s.Severity == "Risk"))
            Add("shield:" + s.Id, AlertLevel.Critical, s.Title, Short(s.Detail, 400));
        int warnings = r.Security.Count(s => s.Severity == "Warning");
        if (warnings > 0)
            Add("shield-warnings", AlertLevel.Warning, $"Night Tech Shield: {warnings} thing{(warnings == 1 ? "" : "s")} worth fixing",
                string.Join("; ", r.Security.Where(s => s.Severity == "Warning").Take(6).Select(s => s.Title)) + (warnings > 6 ? "; and more" : "") + ".");

        // Updates and stability
        if (r.Updates.LastInstalledUtc is { } li)
        {
            int days = (int)(nowUtc - li).TotalDays;
            if (days >= UpdatesWarnDays)
                Add("updates", days >= UpdatesCriticalDays ? AlertLevel.Critical : AlertLevel.Warning, "Windows updates are behind", $"The last update was installed {days} days ago.");
        }
        if (r.Updates.RebootPending && r.UptimeHours is long up && up >= RebootWarnDays * 24)
            Add("reboot", AlertLevel.Warning, "Restart needed", $"Updates are waiting for a restart, and the PC has been on for {up / 24} days.");
        if (r.BlueScreens7d > 0)
            Add("bsod", r.BlueScreens7d >= 3 ? AlertLevel.Critical : AlertLevel.Warning, "Blue screen crashes", $"{r.BlueScreens7d} in the last 7 days.");
        if (r.UnexpectedShutdowns7d >= 2)
            Add("shutdowns", AlertLevel.Warning, "Unexpected shutdowns", $"{r.UnexpectedShutdowns7d} in the last 7 days (power loss, freezes or a failing power supply).");

        // Backup
        var b = r.Backup;
        if (b.Tool.Length == 0)
            Add("backup-none", AlertLevel.Warning, "No backup set up", "No backup program Sentinel knows about is set up on this PC.");
        else
        {
            if (b.LastRunFailed)
                Add("backup-failed", AlertLevel.Warning, $"{b.Tool}: last backup failed", b.Destination.Length > 0 ? $"Backing up to {b.Destination}." : "");
            var last = b.LastSuccessUtc;
            int age = last is { } l ? (int)(nowUtc - l).TotalDays : int.MaxValue;
            if (age >= BackupWarnDays)
                Add("backup-old", age >= BackupCriticalDays ? AlertLevel.Critical : AlertLevel.Warning, $"{b.Tool}: no backup lately",
                    last is null ? "It has never finished a backup." : $"The last good backup was {age} days ago.");
        }

        if (r.BatteryHealthPercent is int bat && bat < BatteryWarnPercent)
            Add("battery", bat < BatteryCriticalPercent ? AlertLevel.Critical : AlertLevel.Warning, "Battery is worn", $"It holds {bat}% of its original charge.");

        return a;
    }

    /// <summary>An alert for a PC that hasn't checked in. Null while it's within its normal time.</summary>
    public static Alert? Offline(DateTime? lastSeenUtc, DateTime nowUtc)
    {
        if (lastSeenUtc is not { } seen) return null;
        double hours = (nowUtc - seen).TotalHours;
        if (hours < OfflineWarnHours) return null;
        return new Alert
        {
            Key = "offline", Level = hours >= OfflineCriticalHours ? AlertLevel.Critical : AlertLevel.Warning, Title = "Not checking in",
            Detail = $"Last heard from {(int)(hours / 24)} day{((int)(hours / 24) == 1 ? "" : "s")} ago. It may be off, unplugged from the internet, or Sentinel may have stopped.",
            FirstSeenUtc = nowUtc, LastSeenUtc = nowUtc,
        };
    }

    /// <summary>
    /// Merges fresh alerts into a PC's alert list: ongoing ones keep when they started (and whether someone acknowledged
    /// them), new ones are added, and ones that went away are marked cleared.
    /// </summary>
    public static (List<Alert> All, List<Alert> New) Merge(IEnumerable<Alert> existing, IEnumerable<Alert> fresh, DateTime nowUtc, bool includeOffline = false)
    {
        var all = existing.ToList();
        var news = new List<Alert>();
        var freshList = fresh.ToList();
        foreach (var f in freshList)
        {
            var open = all.FirstOrDefault(x => x.Key == f.Key && x.ClearedUtc is null);
            if (open is null)
            {
                all.Add(f);
                news.Add(f);
                continue;
            }
            bool worse = f.Level > open.Level;
            open.Level = f.Level;
            open.Title = f.Title;
            open.Detail = f.Detail;
            open.LastSeenUtc = nowUtc;
            if (worse) { open.Acknowledged = false; news.Add(open); }
        }
        foreach (var open in all.Where(x => x.ClearedUtc is null && freshList.All(f => f.Key != x.Key)))
            if (includeOffline || open.Key != "offline") open.ClearedUtc = nowUtc;
        // Keep 90 days of cleared alerts for the monthly report.
        all.RemoveAll(x => x.ClearedUtc is { } c && (nowUtc - c).TotalDays > 90);
        return (all, news);
    }

    private static string Short(string s, int n) => s.Length <= n ? s : s[..n] + "...";
}

/// <summary>
/// What the tech hands to the installer: the server's address, a one-time code, and the IDs of the tech keys this PC
/// should trust. The PC only trusts keys named here, so the server can't slip in a key of its own.
/// Written as "NTS1." plus base64url JSON so it can be pasted or typed.
/// </summary>
public sealed class EnrollToken
{
    public string Server { get; set; } = "";
    public string Code { get; set; } = "";
    public List<string> KeyIds { get; set; } = new();
    public string Client { get; set; } = "";

    public const string Prefix = "NTS1.";

    public string Encode() => Prefix + Base64Url(JsonSerializer.SerializeToUtf8Bytes(this, SignedCommand.Json));

    public static EnrollToken? Parse(string text)
    {
        text = (text ?? "").Trim();
        if (!text.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        try
        {
            var t = JsonSerializer.Deserialize<EnrollToken>(FromBase64Url(text[Prefix.Length..]), SignedCommand.Json);
            if (t is null || t.Code.Length < 8 || t.KeyIds.Count == 0 || t.KeyIds.Any(k => k.Length != 32)) return null;
            if (!Uri.TryCreate(t.Server, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) return null;
            return t;
        }
        catch (Exception e) when (e is FormatException or JsonException) { return null; }
    }

    public static string Base64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] FromBase64Url(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }
}
