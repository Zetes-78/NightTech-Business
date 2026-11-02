using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace NightTech.Business.Core.Security;

/// <summary>Saves a Security Checkup as HTML (for the owner), TXT (for the Hub ticket) and JSON (to combine later).</summary>
public static class SecurityReportWriter
{
    public const string Disclaimer =
        "This report shows what these checks found when they were run, and what the owner told us. It is not a guarantee " +
        "that the business can't be breached, and it doesn't replace a full security audit.";

    public static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public sealed record Saved(string Html, string Text, string Json);

    public static string BaseName(SecurityReport r)
    {
        var parts = new List<string> { "security" };
        if (!string.IsNullOrWhiteSpace(r.Ticket)) parts.Add(r.Ticket);
        parts.Add(string.IsNullOrWhiteSpace(r.Facts.ComputerName) ? "computer" : r.Facts.ComputerName);
        parts.Add(r.Checked.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture));
        return Format.SafeFileName(string.Join("-", parts), 120);
    }

    public static Saved Save(SecurityReport r, string folder)
    {
        Directory.CreateDirectory(folder);
        var b = Path.Combine(folder, BaseName(r));
        var bom = new UTF8Encoding(true);
        File.WriteAllText(b + ".html", ToHtml(r), bom);
        File.WriteAllText(b + ".txt", ToText(r), bom);
        File.WriteAllText(b + ".json", JsonSerializer.Serialize(r, Json), bom);
        return new Saved(b + ".html", b + ".txt", b + ".json");
    }

    public static SecurityReport? Load(string path)
    {
        var rep = JsonSerializer.Deserialize<SecurityReport>(File.ReadAllText(path).TrimStart('﻿'), Json);
        return rep?.Tool == "Night Tech Security Checkup" ? rep : null;
    }

    public static (int Pass, int Warn, int Fail, int NotChecked) Counts(IEnumerable<CheckResult> results)
    {
        var list = results.ToList();
        return (list.Count(x => x.Status == CheckStatus.Pass), list.Count(x => x.Status == CheckStatus.Warn),
                list.Count(x => x.Status == CheckStatus.Fail), list.Count(x => x.Status == CheckStatus.NotChecked));
    }

    public static string Summary(IEnumerable<CheckResult> results)
    {
        var (pass, warn, fail, _) = Counts(results);
        var checkedCount = pass + warn + fail;
        var s = $"{pass} of {checkedCount} checks passed.";
        if (fail > 0) s += $" {fail} to fix soon.";
        if (warn > 0) s += $" {warn} worth improving.";
        return s;
    }

    public static string Label(CheckStatus s) => s switch
    {
        CheckStatus.Pass => "PASS",
        CheckStatus.Warn => "IMPROVE",
        CheckStatus.Fail => "FIX SOON",
        CheckStatus.Info => "NOTE",
        _ => "NOT CHECKED",
    };

    // ---------------- Text ----------------

    public static string ToText(SecurityReport r)
    {
        var s = new StringBuilder();
        s.AppendLine($"{Brand.Company}: Security Checkup");
        s.AppendLine(new string('=', 60));
        void Row(string k, string? v) { if (!string.IsNullOrWhiteSpace(v)) s.AppendLine($"  {k,-14} {v}"); }
        Row("Business", r.Business);
        Row("Ticket", r.Ticket);
        Row("Computer", r.Facts.ComputerName);
        Row("Windows", r.Facts.OsName);
        Row("Checked", Format.DateAndTime(r.Checked));
        Row("Technician", r.Technician);
        Row("Tool", $"{r.Tool} {r.ToolVersion}" + (r.Facts.RanAsAdministrator ? "" : " (not as administrator)"));
        s.AppendLine();
        s.AppendLine(Summary(r.Results));
        s.AppendLine();
        var fixes = SecurityRules.TopFixes(r.Results);
        if (fixes.Count > 0)
        {
            s.AppendLine("WHAT TO FIX, MOST IMPORTANT FIRST");
            int i = 1;
            foreach (var f in fixes) s.AppendLine($"  {i++}. [{Label(f.Status)}] {f.Title}: {f.Fix}");
            s.AppendLine();
        }
        foreach (var area in r.Results.GroupBy(x => x.Area))
        {
            s.AppendLine(area.Key.ToUpperInvariant());
            foreach (var x in area) s.AppendLine($"  [{Label(x.Status),-11}] {x.Title}: {x.Found}");
            s.AppendLine();
        }
        if (r.Facts.Notes.Count > 0)
        {
            s.AppendLine("NOTES");
            foreach (var n in r.Facts.Notes) s.AppendLine("  - " + n);
            s.AppendLine();
        }
        s.AppendLine(Disclaimer);
        s.AppendLine($"{Brand.Company} · {Brand.Phone} · {Brand.Website}");
        return s.ToString();
    }

    // ---------------- HTML ----------------

    private static string E(string? x) => WebUtility.HtmlEncode(x ?? "");

    public static string ToHtml(SecurityReport r)
    {
        var s = new StringBuilder();
        Head(s, "Security Checkup: " + (r.Business.Length > 0 ? r.Business : r.Facts.ComputerName));
        s.Append("<section class=\"meta\"><table>");
        Meta(s, "Business", r.Business); Meta(s, "Computer", r.Facts.ComputerName); Meta(s, "Windows", r.Facts.OsName);
        Meta(s, "Checked", Format.DateAndTime(r.Checked)); Meta(s, "Technician", r.Technician); Meta(s, "Ticket", r.Ticket);
        s.Append("</table></section>");
        Body(s, r.Results);
        if (r.Facts.Notes.Count > 0)
        {
            s.Append("<section><h2>Notes</h2><ul>");
            foreach (var n in r.Facts.Notes) s.Append("<li>").Append(E(n)).Append("</li>");
            s.Append("</ul></section>");
        }
        Foot(s, $"{r.Tool} {r.ToolVersion}");
        return s.ToString();
    }

    private static void Body(StringBuilder s, List<CheckResult> results)
    {
        var (pass, warn, fail, _) = Counts(results);
        var cls = fail > 0 ? "fail" : warn > 0 ? "warn" : "pass";
        s.Append("<section><h2>The short version</h2><p class=\"summary ").Append(cls).Append("\">").Append(E(Summary(results))).Append("</p>");
        s.Append("<div class=\"bars\"><span class=\"b pass\" style=\"flex:").Append(Math.Max(pass, 0)).Append("\"></span>")
         .Append("<span class=\"b warn\" style=\"flex:").Append(warn).Append("\"></span><span class=\"b fail\" style=\"flex:").Append(fail).Append("\"></span></div>");
        var fixes = SecurityRules.TopFixes(results);
        if (fixes.Count > 0)
        {
            s.Append("<h3>What to fix, most important first</h3><ol class=\"fixes\">");
            foreach (var f in fixes)
                s.Append("<li class=\"").Append(f.Status.ToString().ToLowerInvariant()).Append("\"><b>").Append(E(f.Title)).Append("</b> <span class=\"tag\">")
                 .Append(E(Label(f.Status))).Append("</span><div>").Append(E(f.Fix)).Append("</div></li>");
            s.Append("</ol>");
        }
        s.Append("</section>");
        foreach (var area in results.GroupBy(x => x.Area))
        {
            s.Append("<section><h2>").Append(E(area.Key)).Append("</h2><table class=\"checks\">");
            foreach (var x in area)
                s.Append("<tr class=\"").Append(x.Status.ToString().ToLowerInvariant()).Append("\"><td class=\"st\"><span class=\"tag\">").Append(E(Label(x.Status)))
                 .Append("</span></td><td><b>").Append(E(x.Title)).Append("</b><div>").Append(E(x.Found)).Append("</div></td></tr>");
            s.Append("</table></section>");
        }
    }

    // ---------------- Business summary (several computers) ----------------

    /// <summary>One page for the owner covering every computer checked: what's wrong on how many of them.</summary>
    public static string ToBusinessSummaryHtml(IReadOnlyList<SecurityReport> reports, string business)
    {
        var s = new StringBuilder();
        Head(s, "Security Checkup summary: " + business);
        var latest = reports.OrderBy(x => x.Checked).ToList();
        s.Append("<section class=\"meta\"><table>");
        Meta(s, "Business", business);
        Meta(s, "Computers checked", latest.Count.ToString(CultureInfo.InvariantCulture));
        Meta(s, "Dates", latest.Count == 0 ? "" : $"{Format.Date(latest.First().Checked)} to {Format.Date(latest.Last().Checked)}");
        s.Append("</table></section>");

        // Computer-specific checks: on how many computers each check failed, passed or couldn't be checked.
        var perPc = latest.SelectMany(rep => rep.Results.Where(x => !x.Id.StartsWith("q_", StringComparison.Ordinal))
                .Select(x => (Pc: rep.Facts.ComputerName, Res: x)))
            .GroupBy(x => x.Res.Id).ToList();
        int Rank(CheckStatus st) => st switch { CheckStatus.Fail => 0, CheckStatus.Warn => 1, CheckStatus.NotChecked => 2, CheckStatus.Pass => 3, _ => 4 };

        var combined = new List<CheckResult>();
        foreach (var g in perPc)
        {
            var worst = g.OrderBy(x => Rank(x.Res.Status)).First().Res;
            string Pcs(Func<CheckStatus, bool> pick) => string.Join(", ", g.Where(x => pick(x.Res.Status)).Select(x => x.Pc).Distinct());
            int Count(Func<CheckStatus, bool> pick) => g.Where(x => pick(x.Res.Status)).Select(x => x.Pc).Distinct().Count();
            var bad = Count(st => st is CheckStatus.Fail or CheckStatus.Warn);
            var unchecked_ = Count(st => st == CheckStatus.NotChecked);
            var ok = Count(st => st == CheckStatus.Pass);
            var missing = latest.Count - g.Select(x => x.Pc).Distinct().Count();
            string found;
            if (worst.Status == CheckStatus.Info)
                found = string.Join(" ", g.Select(x => $"{x.Pc}: {x.Res.Found}"));
            else
            {
                var parts = new List<string>();
                if (bad > 0) parts.Add($"needs attention on {bad} of {latest.Count} computer(s): {Pcs(st => st is CheckStatus.Fail or CheckStatus.Warn)}");
                if (ok > 0) parts.Add(bad == 0 && unchecked_ == 0 && missing == 0 ? "OK on every computer checked" : $"OK on {ok}");
                if (unchecked_ > 0) parts.Add($"not checked on {unchecked_} ({Pcs(st => st == CheckStatus.NotChecked)})");
                if (missing > 0) parts.Add($"not part of {missing} computer's report");
                found = char.ToUpperInvariant(parts[0][0]) + parts[0][1..] + (parts.Count > 1 ? "; " + string.Join("; ", parts.Skip(1)) : "") + ".";
            }
            combined.Add(new CheckResult { Id = worst.Id, Area = worst.Area, Title = worst.Title, Status = worst.Status, Priority = worst.Priority, Fix = worst.Fix, Found = found });
        }

        // Owner answers apply to the whole business: for each question, the most recent report where it was asked.
        foreach (var q in SecurityRules.Questions)
        {
            var answered = latest.LastOrDefault(rep => rep.Results.Any(x => x.Id == "q_" + q.Id && x.Status != CheckStatus.NotChecked))
                           ?? latest.LastOrDefault(rep => rep.Results.Any(x => x.Id == "q_" + q.Id));
            var res = answered?.Results.FirstOrDefault(x => x.Id == "q_" + q.Id);
            if (res is not null) combined.Add(res);
        }
        Body(s, combined);

        s.Append("<section><h2>Computers</h2><table class=\"checks\">");
        foreach (var rep in latest)
            s.Append("<tr><td><b>").Append(E(rep.Facts.ComputerName)).Append("</b><div>").Append(E(rep.Facts.OsName)).Append(" &middot; checked ")
             .Append(E(Format.DateAndTime(rep.Checked))).Append("</div></td><td>").Append(E(Summary(rep.Results))).Append("</td></tr>");
        s.Append("</table></section>");
        Foot(s, "Night Tech Security Checkup");
        return s.ToString();
    }

    // ---------------- Shared page parts ----------------

    private static void Meta(StringBuilder s, string k, string? v)
    {
        if (!string.IsNullOrWhiteSpace(v)) s.Append("<tr><th>").Append(E(k)).Append("</th><td>").Append(E(v)).Append("</td></tr>");
    }

    private static void Head(StringBuilder s, string title)
    {
        s.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        s.Append("<title>").Append(E(title)).Append("</title><style>").Append(Css).Append("</style></head><body>");
        s.Append("<header><div><strong>Night Tech</strong> Solutions</div><div class=\"sub\">Security Checkup</div></header><main>");
    }

    private static void Foot(StringBuilder s, string tool)
    {
        s.Append("<footer><p>").Append(E(Disclaimer)).Append("</p><p>").Append(E(Brand.Company)).Append(" &middot; ").Append(E(Brand.Phone))
         .Append(" &middot; nighttech.solutions &middot; ").Append(E(Brand.ServiceArea)).Append("</p><p class=\"tool\">").Append(E(tool))
         .Append("</p></footer></main></body></html>");
    }

    private const string Css = """
        body{margin:0;font-family:"Segoe UI",Arial,sans-serif;color:#1a202c;background:#f7fafc;font-size:15px;line-height:1.45}
        header{background:#1a365d;color:#fff;padding:18px 24px;font-size:22px}
        header .sub{font-size:14px;color:#dbe7f5}
        main{max-width:880px;margin:0 auto;padding:16px}
        section{background:#fff;border:1px solid #d1d5db;border-radius:8px;padding:14px 18px;margin-bottom:12px}
        h2{font-size:18px;color:#1a365d;margin:0 0 8px} h3{font-size:16px;color:#1a365d;margin:14px 0 6px}
        table{border-collapse:collapse;width:100%}
        th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #edf2f7;vertical-align:top}
        .meta th{width:24%;color:#4a5568;font-weight:600}
        td div{color:#4a5568;font-size:14px}
        td.st{width:110px}
        .summary{font-size:18px;font-weight:600;padding:8px 12px;border-radius:6px}
        .summary.pass{background:#dcfce7;color:#14532d}.summary.warn{background:#ffedd5;color:#7c2d12}.summary.fail{background:#fed7d7;color:#822727}
        .bars{display:flex;height:10px;border-radius:5px;overflow:hidden;margin:8px 0 4px;background:#edf2f7}
        .b.pass{background:#2f855a}.b.warn{background:#dd6b20}.b.fail{background:#c53030}
        .tag{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;padding:1px 6px;border-radius:4px;background:#e2e8f0;color:#1a202c}
        .fail .tag{background:#fed7d7;color:#822727}.warn .tag{background:#ffedd5;color:#7c2d12}.pass .tag{background:#dcfce7;color:#14532d}.info .tag{background:#e6f2ff;color:#1a365d}
        ol.fixes{padding-left:22px} ol.fixes li{margin-bottom:8px} ol.fixes li div{color:#4a5568}
        footer{font-size:12px;color:#4a5568;padding:8px 4px} footer .tool{color:#a0aec0}
        @media print{body{background:#fff}section{break-inside:avoid;border-color:#ccc}header,.tag,.summary,.b{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
        """;
}
