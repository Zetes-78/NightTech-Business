using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using SoftwareRules = NightTech.Business.Core.Network.Software;

namespace NightTech.Business.Core.Network;

/// <summary>The network documenter's report: devices, Wi-Fi, programs and notes, for the owner and the Hub ticket.</summary>
public sealed class NetworkReport
{
    public string Tool { get; set; } = "Night Tech Network Scan";
    public string ToolVersion { get; set; } = "";
    public string Kind { get; set; } = "network-scan";
    public string Business { get; set; } = "";
    public string Site { get; set; } = "";
    public string Ticket { get; set; } = "";
    public string Technician { get; set; } = "";
    public string PermissionFrom { get; set; } = "";
    public DateTime Started { get; set; }
    public DateTime Finished { get; set; }
    public NetworkInfo Network { get; set; } = new();
    public List<Device> Devices { get; set; } = new();
    public List<PcInventory> Computers { get; set; } = new();
    public List<NetFinding> Findings { get; set; } = new();
    public string Notes { get; set; } = "";

    [JsonIgnore] public List<SoftwareSummary> Software => SoftwareRules.Summarize(Computers);

    /// <summary>Recomputes the notes from the devices, Wi-Fi and programs.</summary>
    public void Evaluate()
    {
        foreach (var d in Devices) if (d.Kind == DeviceKind.Unknown || d.KindReason.Length == 0) Classify.Apply(d);
        Findings = Classify.Findings(Devices, Network).Concat(SoftwareRules.Findings(Computers, Software)).OrderByDescending(f => f.Level).ToList();
    }

    public static readonly string[] Limits =
    {
        "This report describes what could be seen from one computer on the date shown. Devices that were off, asleep, on another network (guest Wi-Fi, VLAN) or that block every probe may be missing.",
        "Device types are worked out from the maker, name and services, and can be wrong: the owner should confirm anything unexpected.",
        "It is not a full security audit or a guarantee the network can't be breached.",
    };

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);
    public static NetworkReport? FromJson(string s) => JsonSerializer.Deserialize<NetworkReport>(s, Json);
    public static string InventoryJson(PcInventory pc) => JsonSerializer.Serialize(pc, Json);
    public static PcInventory? InventoryFromJson(string s)
    {
        // Accepts our own inventory files, and the Field Kit's report (its "programs" list).
        using var doc = JsonDocument.Parse(s);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("not a program list");
        if (root.TryGetProperty("programs", out var progs) && progs.ValueKind == JsonValueKind.Array
            && root.TryGetProperty("computer", out var comp) && comp.ValueKind == JsonValueKind.Object)
        {
            var pc = new PcInventory { Source = "Field Kit report", Computer = Str(comp, "name"), Windows = Str(comp, "osName") };
            foreach (var p in progs.EnumerateArray().Where(p => p.ValueKind == JsonValueKind.Object))
                pc.Programs.Add(new SoftwareItem { Name = Str(p, "name"), Version = Str(p, "version"), Publisher = Str(p, "publisher") });
            return Tidy(pc);
        }
        PcInventory? inv;
        try { inv = JsonSerializer.Deserialize<PcInventory>(s, Json); }
        catch (InvalidOperationException e) { throw new InvalidDataException("not a program list: " + e.Message); }
        return inv is null ? null : Tidy(inv);
    }

    /// <summary>Files can come from anywhere: no missing lists or empty values that would trip the report later.</summary>
    private static PcInventory Tidy(PcInventory pc)
    {
        pc.Computer = Scanner.Clean(pc.Computer ?? "");
        pc.Ip ??= ""; pc.Windows = Scanner.Clean(pc.Windows ?? ""); pc.Source ??= "";
        pc.Programs = (pc.Programs ?? new()).Where(p => p is not null && !string.IsNullOrWhiteSpace(p.Name)).Take(5000).Select(p => new SoftwareItem
        {
            Name = Scanner.Clean(p.Name), Version = Scanner.Clean(p.Version ?? ""), Publisher = Scanner.Clean(p.Publisher ?? ""), Installed = p.Installed,
        }).ToList();
        return pc;
    }
    private static string Str(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static string Mark(NoteLevel l) => l switch { NoteLevel.Risk => "FIX", NoteLevel.Warning => "CHECK", _ => "NOTE" };
    private static string Who(Device d) => d.Label.Length > 0 ? d.Label : d.Name.Length > 0 ? d.Name : d.Model.Length > 0 ? d.Model : "-";
    private static string Services(Device d) => string.Join(", ", d.Services.Select(s => s.Name + (s.Detail.Length > 0 ? $" \"{s.Detail}\"" : "")));

    public string ToText()
    {
        var s = new StringBuilder();
        s.AppendLine($"{Brand.Company.ToUpperInvariant()} - NETWORK REPORT");
        s.AppendLine(new string('=', 60));
        s.AppendLine($"Business:    {Business}{(Site.Length > 0 ? " - " + Site : "")}");
        if (Ticket.Length > 0) s.AppendLine($"Ticket:      {Ticket}");
        s.AppendLine($"Scanned:     {Started:yyyy-MM-dd HH:mm} by {Technician}, with permission from {PermissionFrom}");
        s.AppendLine($"Network:     {Network.ScannedRange}, gateway {Network.Gateway}, DNS {string.Join(", ", Network.DnsServers)}{(Network.DhcpServer.Length > 0 ? ", DHCP " + Network.DhcpServer : "")}");
        if (Network.ConnectedWifi is { } w) s.AppendLine($"Wi-Fi:       {w.Ssid}, {w.Security}, channel {w.Channel} ({w.Band}), signal {w.SignalPercent}%");
        s.AppendLine();
        s.AppendLine($"DEVICES ({Devices.Count})");
        foreach (var g in Devices.GroupBy(d => d.Kind).OrderBy(g => g.Key))
        {
            s.AppendLine($"  {Classify.Label(g.Key)} ({g.Count()})");
            foreach (var d in g)
                s.AppendLine($"    {d.Ip,-15} {Who(d),-28} {(d.RandomMac ? "private address" : d.Maker),-24} {d.Mac,-17} {Services(d)}");
        }
        if (Findings.Count > 0)
        {
            s.AppendLine(); s.AppendLine("WHAT TO LOOK AT");
            foreach (var f in Findings) s.AppendLine($"  [{Mark(f.Level)}] {f.Title}{(f.Detail.Length > 0 ? " - " + f.Detail : "")}");
        }
        if (Computers.Count > 0)
        {
            var sw = Software;
            s.AppendLine(); s.AppendLine($"PROGRAMS ({sw.Count} across {Computers.Count} Windows PC(s))");
            foreach (var p in sw) s.AppendLine($"  {p.Name}{(p.Versions.Count > 0 ? " " + string.Join(" / ", p.Versions.Take(3)) : "")}: {p.Computers.Count} PC(s){(p.Flag.Length > 0 ? "  [" + p.Flag + "]" : "")}");
        }
        if (Notes.Length > 0) { s.AppendLine(); s.AppendLine("NOTES"); s.AppendLine("  " + Notes); }
        s.AppendLine();
        foreach (var l in Limits) s.AppendLine("* " + l);
        s.AppendLine();
        s.AppendLine($"{Brand.Company} · {Brand.Phone} · {Brand.Website}   ({Tool} {ToolVersion})");
        return s.ToString();
    }

    public string ToHtml()
    {
        static string E(string? x) => WebUtility.HtmlEncode(x ?? "");
        var h = new StringBuilder();
        h.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        h.Append($"<title>Network report - {E(Business)}</title><style>");
        h.Append("body{font-family:Segoe UI,Arial,sans-serif;color:#1a202c;background:#f7fafc;margin:0}main{max-width:1000px;margin:0 auto;padding:28px 22px;background:#fff}");
        h.Append("header{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:3px solid #c2410c;padding-bottom:14px;margin-bottom:18px}h1{font-size:24px;margin:0;color:#1a365d}h2{font-size:17px;color:#1a365d;margin:26px 0 8px}h3{font-size:14px;margin:14px 0 4px;color:#1a365d}");
        h.Append("table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px 7px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:top}th{color:#4a5568;font-weight:600}");
        h.Append(".FIX{color:#c53030;font-weight:700}.CHECK{color:#c05621;font-weight:700}.NOTE{color:#2b6cb0;font-weight:700}.muted{color:#4a5568;font-size:13px}.tiles{display:flex;flex-wrap:wrap;gap:10px}.tile{border:1px solid #e2e8f0;border-radius:8px;padding:10px 14px;min-width:130px}.tile b{display:block;font-size:22px;color:#1a365d}");
        h.Append("@media print{body{background:#fff}main{padding:0}}</style></head><body><main>");
        h.Append($"<header><div><h1>{E(Brand.Company)}</h1><div class=\"muted\">Network report · {E(Finished.ToString("MMMM d, yyyy", CultureInfo.InvariantCulture))}</div></div>");
        h.Append($"<div class=\"muted\" style=\"text-align:right\">{E(Business)}{(Site.Length > 0 ? "<br>" + E(Site) : "")}{(Ticket.Length > 0 ? "<br>Ticket " + E(Ticket) : "")}</div></header>");

        h.Append("<div class=\"tiles\">");
        h.Append($"<div class=\"tile\"><b>{Devices.Count}</b>devices found</div>");
        foreach (var g in Devices.GroupBy(d => d.Kind).OrderByDescending(g => g.Count()).Take(5))
            h.Append($"<div class=\"tile\"><b>{g.Count()}</b>{E(Classify.Label(g.Key).Split(" (")[0].ToLowerInvariant())}</div>");
        int fix = Findings.Count(f => f.Level == NoteLevel.Risk);
        h.Append($"<div class=\"tile\"><b style=\"color:{(fix > 0 ? "#c53030" : "#2f855a")}\">{fix}</b>to fix</div></div>");

        h.Append("<h2>The network</h2><table>");
        void Row(string k, string v) { if (v.Length > 0) h.Append($"<tr><th style=\"width:180px\">{E(k)}</th><td>{E(v)}</td></tr>"); }
        Row("Address range", Network.ScannedRange);
        Row("Gateway (router)", Network.Gateway);
        Row("DNS servers", string.Join(", ", Network.DnsServers));
        Row("DHCP server", Network.DhcpServer);
        if (Network.ConnectedWifi is { } w) Row("Wi-Fi", $"{w.Ssid} · {w.Security} · channel {w.Channel} ({w.Band}) · signal {w.SignalPercent}%");
        Row("Nearby Wi-Fi networks", Network.NearbyWifi.Count > 0 ? Network.NearbyWifi.Select(n => n.Ssid).Distinct().Count().ToString(CultureInfo.InvariantCulture) : "");
        h.Append("</table>");

        if (Findings.Count > 0)
        {
            h.Append("<h2>What to look at</h2><table>");
            foreach (var f in Findings) h.Append($"<tr><td class=\"{Mark(f.Level)}\" style=\"width:60px\">{Mark(f.Level)}</td><td><strong>{E(f.Title)}</strong>{(f.Detail.Length > 0 ? $"<br><span class=\"muted\">{E(f.Detail)}</span>" : "")}</td></tr>");
            h.Append("</table>");
        }

        h.Append("<h2>Devices</h2>");
        foreach (var g in Devices.GroupBy(d => d.Kind).OrderBy(g => g.Key))
        {
            h.Append($"<h3>{E(Classify.Label(g.Key))} ({g.Count()})</h3><table><tr><th>Address</th><th>Name</th><th>Maker / model</th><th>Network address (MAC)</th><th>Services</th></tr>");
            foreach (var d in g)
                h.Append($"<tr><td>{E(d.Ip)}</td><td>{E(Who(d))}</td><td>{E(d.RandomMac ? "private address" : string.Join(" ", new[] { d.Maker, d.Model }.Where(x => x.Length > 0)))}</td><td>{E(d.Mac)}</td><td>{E(Services(d))}</td></tr>");
            h.Append("</table>");
        }

        if (Computers.Count > 0)
        {
            var sw = Software;
            h.Append($"<h2>Programs used ({sw.Count} across {Computers.Count} Windows PC(s))</h2><table><tr><th>Program</th><th>Version(s)</th><th>PCs</th><th>Note</th></tr>");
            foreach (var p in sw)
                h.Append($"<tr><td>{E(p.Name)}<br><span class=\"muted\">{E(p.Publisher)}</span></td><td>{E(string.Join(", ", p.Versions.Take(4)))}</td><td title=\"{E(string.Join(", ", p.Computers))}\">{p.Computers.Count}</td><td class=\"{(p.Level == NoteLevel.Info ? "" : Mark(p.Level))}\">{E(p.Flag)}</td></tr>");
            h.Append("</table><h3>Computers checked</h3><table><tr><th>Computer</th><th>Windows</th><th>Programs</th><th>How</th></tr>");
            foreach (var pc in Computers)
                h.Append($"<tr><td>{E(pc.Computer)}</td><td>{E(pc.Windows)}</td><td>{pc.Programs.Count(p => !SoftwareRules.IsNoise(p.Name))}</td><td>{E(pc.Source)}</td></tr>");
            h.Append("</table>");
        }
        if (Notes.Length > 0) h.Append($"<h2>Notes</h2><p>{E(Notes)}</p>");
        h.Append("<h2>Please note</h2><ul class=\"muted\">");
        foreach (var l in Limits) h.Append($"<li>{E(l)}</li>");
        h.Append("</ul>");
        h.Append($"<p class=\"muted\" style=\"margin-top:28px;text-align:center\">{E(Brand.Company)} · {E(Brand.Phone)} · {E(Brand.Website)}<br>Scanned by {E(Technician)} with permission from {E(PermissionFrom)} · {E(Tool)} {E(ToolVersion)}</p>");
        h.Append("</main></body></html>");
        return h.ToString();
    }

    private static string Csv(string? v)
    {
        v ??= "";
        if (v.Length > 0 && "=+-@\t\r".Contains(v[0])) v = "'" + v;   // spreadsheets would run a formula
        return v.Contains(',') || v.Contains('"') || v.Contains('\n') || v.Contains('\r') ? "\"" + v.Replace("\"", "\"\"") + "\"" : v;
    }

    public string DevicesCsv()
    {
        var s = new StringBuilder("IP,Name,Label,Type,Maker,Model,MAC,Private address,Answers ping,Services\r\n");
        foreach (var d in Devices)
            s.Append(string.Join(",", new[] { d.Ip, d.Name, d.Label, Classify.Label(d.Kind), d.Maker, d.Model, d.Mac, d.RandomMac ? "yes" : "", d.AnswersPing ? "yes" : "no", Services(d) }.Select(Csv))).Append("\r\n");
        return s.ToString();
    }

    public string SoftwareCsv()
    {
        var s = new StringBuilder("Computer,Program,Version,Publisher,Installed\r\n");
        foreach (var pc in Computers)
            foreach (var p in pc.Programs.Where(p => !SoftwareRules.IsNoise(p.Name)).OrderBy(p => p.Name))
                s.Append(string.Join(",", new[] { pc.Computer, p.Name, p.Version, p.Publisher, p.Installed?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "" }.Select(Csv))).Append("\r\n");
        return s.ToString();
    }

    public sealed record Saved(string Json, string Text, string Html, string DevicesCsv, string SoftwareCsv);

    public Saved Save(string folder)
    {
        Directory.CreateDirectory(folder);
        var b = Path.Combine(folder, Format.SafeFileName($"network-{(Ticket.Length > 0 ? Ticket : Business)}-{Started:yyyyMMdd-HHmm}"));
        var bom = new UTF8Encoding(true);
        File.WriteAllText(b + ".json", ToJson(), bom);
        File.WriteAllText(b + ".txt", ToText(), bom);
        File.WriteAllText(b + ".html", ToHtml(), new UTF8Encoding(false));
        File.WriteAllText(b + "-devices.csv", DevicesCsv(), bom);
        File.WriteAllText(b + "-programs.csv", SoftwareCsv(), bom);
        return new(b + ".json", b + ".txt", b + ".html", b + "-devices.csv", b + "-programs.csv");
    }
}
