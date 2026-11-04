using System.Net;
using System.Text;

namespace NightTech.Business.Core.Sentinel;

/// <summary>One PC's month, for the client's report.</summary>
public sealed class DeviceMonth
{
    public string Computer { get; set; } = "";
    public string User { get; set; } = "";
    public DateTime? LastSeenUtc { get; set; }
    public HealthReport? Latest { get; set; }
    /// <summary>Alerts open at any point in the month.</summary>
    public List<Alert> Alerts { get; set; } = new();
    /// <summary>What Night Tech did on this PC this month (from command results).</summary>
    public List<CommandResult> Work { get; set; } = new();
}

/// <summary>The branded monthly care-plan report for a client: what was checked, what was found, what was done.</summary>
public static class MonthlyReport
{
    public static string Html(string client, DateTime monthStartUtc, IReadOnlyList<DeviceMonth> devices, DateTime nowUtc)
    {
        static string E(string s) => WebUtility.HtmlEncode(s);
        var monthEnd = monthStartUtc.AddMonths(1);
        int open = devices.Sum(d => d.Alerts.Count(a => a.ClearedUtc is null));
        int fixedCount = devices.Sum(d => d.Alerts.Count(a => a.ClearedUtc is { } c && c >= monthStartUtc && c < monthEnd));
        int work = devices.Sum(d => d.Work.Count(w => w.Outcome == "Done"));
        var sb = new StringBuilder();
        sb.Append($$"""
            <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>{{E(client)}} - Night Tech Sentinel report, {{monthStartUtc:MMMM yyyy}}</title>
            <style>
            body{font-family:Segoe UI,Arial,sans-serif;color:#1a202c;margin:0;background:#fff}
            header{background:{{Brand.Navy}};color:#fff;padding:22px 28px}header h1{margin:0;font-size:22px}header p{margin:4px 0 0;opacity:.85}
            main{max-width:900px;margin:0 auto;padding:20px 28px}
            .tiles{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0 20px}.tile{flex:1 1 160px;border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px}
            .tile b{display:block;font-size:26px;color:{{Brand.Navy}}}.tile span{color:#4a5568;font-size:13px}
            h2{font-size:17px;border-bottom:2px solid {{Brand.Orange}};padding-bottom:4px;margin-top:28px}
            table{border-collapse:collapse;width:100%;font-size:14px}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid #edf2f7;vertical-align:top}
            th{background:{{Brand.Gray}}}.Critical{color:#c53030;font-weight:600}.Warning{color:{{Brand.OrangeAccessible}};font-weight:600}.ok{color:#276749;font-weight:600}
            .muted{color:#4a5568;font-size:13px}footer{background:{{Brand.Gray}};border-top:1px solid #e2e8f0;padding:16px 28px;text-align:center;font-size:14px;margin-top:30px}
            footer a{color:{{Brand.OrangeAccessible}}}
            @media print{header{-webkit-print-color-adjust:exact;print-color-adjust:exact} }
            </style></head><body>
            <header><h1>Night Tech Sentinel monthly report</h1><p>{{E(client)}} &middot; {{monthStartUtc:MMMM yyyy}}</p></header>
            <main>
            <div class="tiles">
            <div class="tile"><b>{{devices.Count}}</b><span>computers monitored</span></div>
            <div class="tile"><b>{{fixedCount}}</b><span>problems found and resolved</span></div>
            <div class="tile"><b>{{work}}</b><span>maintenance jobs done</span></div>
            <div class="tile"><b>{{open}}</b><span>items still open</span></div>
            </div>
            """);

        sb.Append("<h2>Computers</h2><table><tr><th>Computer</th><th>Protection</th><th>Updates</th><th>Backup</th><th>Last check-in</th></tr>");
        foreach (var d in devices.OrderBy(d => d.Computer, StringComparer.OrdinalIgnoreCase))
        {
            var r = d.Latest;
            string prot = r is null ? "-" : r.Antivirus.Enabled == true && r.Antivirus.RealTime != false ? "<span class=\"ok\">On</span>" : "<span class=\"Critical\">Needs attention</span>";
            string upd = r?.Updates.LastInstalledUtc is { } u ? $"{u:MMM d}" + (r.Updates.RebootPending ? " (restart waiting)" : "") : "-";
            string bak = r is null ? "-" : r.Backup.Tool.Length == 0 ? "<span class=\"Warning\">None</span>" : r.Backup.LastSuccessUtc is { } bs ? $"{E(r.Backup.Tool)}, {bs:MMM d}" : $"<span class=\"Warning\">{E(r.Backup.Tool)}, never finished</span>";
            sb.Append($"<tr><td>{E(d.Computer)}{(d.User.Length > 0 ? $"<br><span class=\"muted\">{E(d.User)}</span>" : "")}</td><td>{prot}</td><td>{upd}</td><td>{bak}</td><td>{(d.LastSeenUtc is { } ls ? ls.ToString("MMM d") : "-")}</td></tr>");
        }
        sb.Append("</table>");

        var openAlerts = devices.SelectMany(d => d.Alerts.Where(a => a.ClearedUtc is null).Select(a => (d.Computer, a))).OrderByDescending(x => x.a.Level).ToList();
        sb.Append("<h2>Still open</h2>");
        if (openAlerts.Count == 0) sb.Append("<p class=\"ok\">Nothing open. Every computer was healthy at the end of the month.</p>");
        else
        {
            sb.Append("<table><tr><th>Computer</th><th>What</th><th>Since</th></tr>");
            foreach (var (pc, a) in openAlerts)
                sb.Append($"<tr><td>{E(pc)}</td><td><span class=\"{a.Level}\">{E(a.Title)}</span><br><span class=\"muted\">{E(a.Detail)}</span></td><td>{a.FirstSeenUtc:MMM d}</td></tr>");
            sb.Append("</table>");
        }

        var resolved = devices.SelectMany(d => d.Alerts.Where(a => a.ClearedUtc is { } c && c >= monthStartUtc && c < monthEnd).Select(a => (d.Computer, a))).ToList();
        if (resolved.Count > 0)
        {
            sb.Append("<h2>Found and resolved</h2><table><tr><th>Computer</th><th>What</th><th>Resolved</th></tr>");
            foreach (var (pc, a) in resolved.OrderBy(x => x.a.ClearedUtc))
                sb.Append($"<tr><td>{E(pc)}</td><td>{E(a.Title)}</td><td>{a.ClearedUtc:MMM d}</td></tr>");
            sb.Append("</table>");
        }

        var jobs = devices.SelectMany(d => d.Work.Where(w => w.FinishedUtc >= monthStartUtc && w.FinishedUtc < monthEnd).Select(w => (d.Computer, w))).ToList();
        if (jobs.Count > 0)
        {
            sb.Append("<h2>Work done</h2><table><tr><th>Date</th><th>Computer</th><th>Job</th><th>Result</th></tr>");
            foreach (var (pc, w) in jobs.OrderBy(x => x.w.FinishedUtc))
                sb.Append($"<tr><td>{w.FinishedUtc:MMM d}</td><td>{E(pc)}</td><td>{E(KindWords(w.Kind))}</td><td>{E(w.Outcome)}{(w.Detail.Length > 0 ? ": " + E(w.Detail) : "")}</td></tr>");
            sb.Append("</table>");
        }

        sb.Append($"""
            <p class="muted">This report shows what Night Tech Sentinel saw on each computer during the month. Monitoring helps catch problems early; it can't promise a computer won't fail or be attacked.</p>
            <p class="muted">Report made {nowUtc.ToLocalTime():MMMM d, yyyy}.</p></main>
            <footer><strong>Questions about this report?</strong> Call {Brand.Company} at <a href="{Brand.PhoneLink}">{Brand.Phone}</a>, text {Brand.TextPhone}, or email <a href="mailto:{Brand.Email}">{Brand.Email}</a>.<br>
            <span class="muted">{E(Brand.Verse)}</span></footer></body></html>
            """);
        return sb.ToString();
    }

    private static string KindWords(CommandKind k) => CommandWords.Describe(new Command { Kind = k }) switch
    {
        var s when s.Length > 0 => char.ToUpperInvariant(s[0]) + s[1..],
        var s => s,
    };
}
