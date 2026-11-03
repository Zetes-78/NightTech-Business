using System.Text.RegularExpressions;

namespace NightTech.Business.Core.Network;

/// <summary>One program across the business: how many PCs have it, and anything worth a note.</summary>
public sealed class SoftwareSummary
{
    public string Name { get; set; } = "";
    public string Publisher { get; set; } = "";
    public List<string> Versions { get; set; } = new();
    public List<string> Computers { get; set; } = new();
    public string Flag { get; set; } = "";
    public NoteLevel Level { get; set; }
    /// <summary>The PCs the flag applies to (a merged name can cover a clean version on other PCs).</summary>
    public List<string> FlaggedComputers { get; set; } = new();
}

/// <summary>Programs used across the business's Windows PCs: one list, with remote-access tools, unsupported software and duplicates noted.</summary>
public static class Software
{
    /// <summary>Windows parts, drivers and runtimes: left out of the business-wide list (they're on every PC and mean nothing to the owner).</summary>
    private static readonly string[] Noise =
    {
        "Microsoft Visual C++", "Microsoft .NET", ".NET Runtime", "Windows SDK", "Microsoft Update Health", "Microsoft Edge WebView", "WebView2",
        "Windows Driver Package", "Intel(R) ", "Realtek", "NVIDIA ", "AMD Software", "Microsoft GameInput", "Microsoft ODBC", "Microsoft OLE DB",
        "vs_", "Microsoft Windows Desktop Runtime", "Microsoft ASP.NET", "Windows PC Health Check", "Update for ", "Security Update for",
    };

    private static readonly (string Pattern, NoteLevel Level, string Why)[] Rules =
    {
        (@"\bAnyDesk\b", NoteLevel.Warning, "Remote-control program: make sure the owner knows who uses it"),
        (@"\bTeamViewer\b", NoteLevel.Warning, "Remote-control program: make sure the owner knows who uses it"),
        (@"ScreenConnect|ConnectWise Control", NoteLevel.Warning, "Remote-control program: make sure the owner knows who installed it"),
        (@"\bLogMeIn\b|\bGoTo (Resolve|Assist)", NoteLevel.Warning, "Remote-control program: make sure the owner knows who uses it"),
        (@"\bRustDesk\b|\bUltraViewer\b|\bSupremo\b|\bSplashtop\b", NoteLevel.Warning, "Remote-control program: make sure the owner knows who uses it"),
        (@"\b(Real|Tight|Ultra|Tiger)VNC\b", NoteLevel.Warning, "VNC remote control: needs a strong password"),
        (@"^Microsoft Office (Standard|Professional|Professional Plus|Home and Business|Home and Student|Home & Business|Home & Student|Small Business|Basic|LTSC Standard|LTSC Professional Plus)?\s*(2003|2007|2010|2013|2016|2019|2021|LTSC 2021)\b", NoteLevel.Risk, "This Office version no longer gets security updates (Office 2016 and 2019 ended October 14, 2025; Office 2021 ended October 13, 2026)"),
        (@"Adobe Flash", NoteLevel.Risk, "Adobe Flash has had no security updates since 2020: remove it"),
        (@"^Java ([67])\b|Java\(TM\) ([67])\b", NoteLevel.Risk, "Very old Java with known security holes: remove or update"),
        (@"QuickTime", NoteLevel.Warning, "Apple QuickTime for Windows is no longer supported: remove it"),
        (@"^Python 2\.", NoteLevel.Warning, "Python 2 is no longer supported"),
        (@"Driver Booster|DriverFix|Driver Support|Driver Updater|Driver Reviver|Outbyte", NoteLevel.Warning, "Paid driver updater: not needed, and can install wrong drivers"),
        (@"Reimage|Restoro|Fortect|PC Accelerate|MyCleanPC|Advanced SystemCare|Segurazo|Wave Browser|OneLaunch|WebDiscover|Web Companion", NoteLevel.Warning, "Adware or a scareware 'optimizer': remove it"),
    };

    /// <summary>Office parts and add-ons that come with an Office install: only the product itself gets the note.</summary>
    private static readonly Regex OfficePart = new(@"Shared|Components|MUI|Proofing|Language|Click-to-Run|Extensibility|Licensing|Visio Viewer|Interop|Primary Interop|Runtime|Add-in|Outlook Connector", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>WinRAR before 7.13 has a security hole that was exploited in 2025 (CVE-2025-8088).</summary>
    internal static bool OldWinRar(SoftwareItem p)
    {
        if (!Regex.IsMatch(p.Name, @"\bWinRAR\b", RegexOptions.IgnoreCase)) return false;
        var m = Regex.Match(p.Version.Length > 0 ? p.Version : p.Name, @"(\d+)\.(\d+)");
        return m.Success && (int.Parse(m.Groups[1].Value) < 7 || int.Parse(m.Groups[1].Value) == 7 && int.Parse(m.Groups[2].Value) < 13);
    }

    private static (NoteLevel Level, string Why)? Rule(SoftwareItem p)
    {
        if (OldWinRar(p)) return (NoteLevel.Warning, "WinRAR older than 7.13 has a security hole exploited in 2025: update it");
        (NoteLevel, string)? best = null;
        foreach (var (pat, level, why) in Rules)
        {
            if (pat.StartsWith("^Microsoft Office", StringComparison.Ordinal) && OfficePart.IsMatch(p.Name)) continue;
            if (Regex.IsMatch(p.Name, pat, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)) && (best is null || level > best.Value.Item1)) best = (level, why);
        }
        return best;
    }

    private static readonly Regex AvExtras = new(@"WebAdvisor|Browser|VPN|Password|Agent|Management|Security Scan|Updater|Tune|Cleanup|Driver", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly string[] Antivirus = { "McAfee", "Norton", "Avast", "AVG", "Bitdefender", "Kaspersky", "ESET", "Malwarebytes", "Webroot", "Sophos", "Trend Micro", "Avira", "TotalAV", "CrowdStrike", "SentinelOne" };

    /// <summary>"Adobe Acrobat (64-bit) 24.001" and "Adobe Acrobat (64-bit)" are the same program; versions are listed separately.</summary>
    public static string Key(string name) =>
        Regex.Replace(Regex.Replace(Regex.Replace(name ?? "", @"\s*\((x64|x86|64-bit|32-bit|en-us|English)\)", "", RegexOptions.IgnoreCase),
            @"\s+-\s+[a-z]{2}-[a-z]{2}\s*$", "", RegexOptions.IgnoreCase),   // "Microsoft 365 - en-us" and "- es-es" are one product
            @"\s+v?\d+(\.\d+){1,3}\s*$", "").Trim();

    public static bool IsNoise(string name) => string.IsNullOrWhiteSpace(name) || Regex.IsMatch(name, @"^KB\d{6,}") || Noise.Any(n => name.StartsWith(n, StringComparison.OrdinalIgnoreCase) || name.Contains(n, StringComparison.OrdinalIgnoreCase) && n.EndsWith(' '));

    public static List<SoftwareSummary> Summarize(IEnumerable<PcInventory> pcs)
    {
        var map = new Dictionary<string, SoftwareSummary>(StringComparer.OrdinalIgnoreCase);
        foreach (var pc in pcs)
            foreach (var p in pc.Programs.Where(p => !IsNoise(p.Name)))
            {
                var key = Key(p.Name);
                if (!map.TryGetValue(key, out var s)) map[key] = s = new SoftwareSummary { Name = key, Publisher = p.Publisher };
                if (!s.Computers.Contains(pc.Computer, StringComparer.OrdinalIgnoreCase)) s.Computers.Add(pc.Computer);
                if (p.Version.Length > 0 && !s.Versions.Contains(p.Version)) s.Versions.Add(p.Version);
                if (Rule(p) is { } r)
                {
                    if (r.Level >= s.Level) { s.Level = r.Level; s.Flag = r.Why; }
                    if (!s.FlaggedComputers.Contains(pc.Computer, StringComparer.OrdinalIgnoreCase)) s.FlaggedComputers.Add(pc.Computer);
                }
            }
        return map.Values.OrderByDescending(s => s.Level).ThenByDescending(s => s.Computers.Count).ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static List<NetFinding> Findings(IReadOnlyList<PcInventory> pcs, IReadOnlyList<SoftwareSummary> all)
    {
        var f = new List<NetFinding>();
        foreach (var s in all.Where(s => s.Level >= NoteLevel.Warning))
        {
            var who = s.FlaggedComputers.Count > 0 ? s.FlaggedComputers : s.Computers;
            f.Add(new(s.Level, $"{s.Name} on {who.Count} PC(s)", $"{s.Flag}. {string.Join(", ", who)}."));
        }
        foreach (var pc in pcs)
        {
            // One antivirus maker counts once (Bitdefender plus its agent, Avast plus its browser, are one product).
            var av = pc.Programs.Where(p => !AvExtras.IsMatch(p.Name))
                                .Select(p => Antivirus.FirstOrDefault(a => p.Name.StartsWith(a, StringComparison.OrdinalIgnoreCase)))
                                .Where(a => a is not null).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (av.Count > 1) f.Add(new(NoteLevel.Warning, $"{pc.Computer} has {av.Count} antivirus programs", $"{string.Join(", ", av)}. Two at once slow the PC and can conflict: keep one."));
            if (Regex.IsMatch(pc.Windows, @"Windows (7|8|8\.1|XP|Vista)\b") )
                f.Add(new(NoteLevel.Risk, $"{pc.Computer} runs {pc.Windows}", "No security updates: upgrade or replace it."));
            else if (Regex.IsMatch(pc.Windows, @"Windows 10\b") && !Regex.IsMatch(pc.Windows, @"\bLTS[BC]\b"))
                f.Add(new(NoteLevel.Warning, $"{pc.Computer} runs Windows 10", "Free security updates ended October 14, 2025. Upgrade to Windows 11, enroll in Extended Security Updates, or plan a replacement."));
        }
        var office = all.Where(s => s.Name.StartsWith("Microsoft Office", StringComparison.OrdinalIgnoreCase) || s.Name.StartsWith("Microsoft 365", StringComparison.OrdinalIgnoreCase)).Select(s => s.Name).ToList();
        if (office.Count > 1) f.Add(new(NoteLevel.Info, "Different Office versions are in use", string.Join(", ", office) + ". One version on every PC makes support and file sharing simpler."));
        return f.OrderByDescending(x => x.Level).ToList();
    }
}
