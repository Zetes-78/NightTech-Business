using System.IO.Compression;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;

namespace NightTech.Business.Core.Network;

public static class Subnet
{
    /// <summary>Largest range scanned in one go (a /22). Bigger networks scan the /24 around this PC and the gateway.</summary>
    public const int MaxHosts = 1022;

    public static uint ToUInt(IPAddress ip) { var b = ip.GetAddressBytes(); return (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]); }
    public static IPAddress FromUInt(uint v) => new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    /// <summary>Host addresses to scan for this PC's address and prefix, and a short description of the range.</summary>
    public static (List<IPAddress> Hosts, string Range) Hosts(IPAddress local, int prefix, IPAddress? gateway = null)
    {
        prefix = Math.Clamp(prefix, 8, 32);
        if (prefix < 22) prefix = 24; // too big to sweep sensibly: the /24 we're in
        uint mask = prefix == 0 ? 0 : uint.MaxValue << (32 - prefix);
        uint net = ToUInt(local) & mask;
        uint bcast = net | ~mask;
        var hosts = new List<IPAddress>();
        if (prefix >= 31) { hosts.Add(local); return (hosts, $"{FromUInt(net)}/{prefix}"); }
        for (uint a = net + 1; a < bcast && hosts.Count < MaxHosts; a++) hosts.Add(FromUInt(a));
        if (gateway is not null && (ToUInt(gateway) & mask) != net) hosts.Add(gateway); // gateway outside the range: scan it too
        return (hosts, $"{FromUInt(net)}/{prefix}");
    }

    /// <summary>Private addresses (10.x, 172.16-31.x, 192.168.x, 169.254.x). The scanner refuses anything else.</summary>
    public static bool IsPrivate(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return b.Length == 4 && (b[0] == 10 || b[0] == 172 && b[1] is >= 16 and <= 31 || b[0] == 192 && b[1] == 168 || b[0] == 169 && b[1] == 254);
    }
}

/// <summary>Device makers from the first half of a network (MAC) address, using the IEEE's public list.</summary>
public static class Oui
{
    private static readonly Lazy<Dictionary<string, string>> Table = new(Load);

    private static Dictionary<string, string> Load()
    {
        var d = new Dictionary<string, string>(45000, StringComparer.Ordinal);
        using var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("NightTech.Business.Core.Network.oui.txt.gz");
        if (s is null) return d;
        using var gz = new GZipStream(s, CompressionMode.Decompress);
        using var r = new StreamReader(gz);
        for (var line = r.ReadLine(); line is not null; line = r.ReadLine())
        {
            int tab = line.IndexOf('\t');
            if (tab == 6) d[line[..6]] = Tidy(line[7..]);
        }
        return d;
    }

    private static readonly Regex Suffix = new(@"[,.]?\s*\b(co\.?,?\s*ltd\.?|corporation|corp\.?|inc\.?|incorporated|limited|ltd\.?|llc|gmbh|s\.?a\.?|technologies|technology|electronics)\b\.?\s*$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>"HON HAI PRECISION IND. CO.,LTD." becomes "Hon Hai Precision Ind."; known names keep their usual spelling.</summary>
    internal static string Tidy(string name)
    {
        var n = name.Trim();
        for (int i = 0; i < 3; i++) n = Suffix.Replace(n, "").Trim().TrimEnd(',', '.').Trim();
        if (n.Length == 0) n = name.Trim();
        if (n == n.ToUpperInvariant() && n.Length > 4)
            n = string.Join(' ', n.Split(' ').Select(w => string.Join('-', w.Split('-').Select(p => p.Length <= 2 ? p : char.ToUpperInvariant(p[0]) + p[1..].ToLowerInvariant()))));
        return n;
    }

    /// <summary>"AA:BB:CC:DD:EE:FF" from any common spelling (dashes, dots, no separators); "" if it isn't one.</summary>
    public static string Normalize(string mac)
    {
        var hex = new string((mac ?? "").Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
        if (hex.Length != 12 || hex == "000000000000" || hex == "FFFFFFFFFFFF") return "";
        return string.Join(':', Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
    }

    /// <summary>A randomized ("private") address: the locally administered bit is set.</summary>
    public static bool IsRandom(string mac) => Normalize(mac) is { Length: 17 } m && (Convert.ToByte(m[..2], 16) & 0x02) != 0;

    public static string Maker(string mac)
    {
        var m = Normalize(mac);
        if (m.Length == 0 || IsRandom(m)) return "";
        return Table.Value.TryGetValue(m.Replace(":", "")[..6], out var v) ? v : "";
    }
}

/// <summary>Reading what Windows' own commands print (arp, netsh wlan).</summary>
public static class Parse
{
    private static readonly Regex ArpLine = new(@"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})\s+(\w+)", RegexOptions.Compiled | RegexOptions.Multiline);

    /// <summary>IP to MAC from "arp -a" (Windows) or /proc/net/arp (Linux).</summary>
    public static Dictionary<string, string> Arp(string text)
    {
        var d = new Dictionary<string, string>();
        foreach (Match m in ArpLine.Matches(text ?? ""))
        {
            if (m.Groups[3].Value.Equals("static", StringComparison.OrdinalIgnoreCase) && m.Groups[2].Value.StartsWith("ff", StringComparison.OrdinalIgnoreCase)) continue;
            var mac = Oui.Normalize(m.Groups[2].Value);
            if (mac.Length > 0 && !mac.StartsWith("01:00:5E", StringComparison.Ordinal)) d[m.Groups[1].Value] = mac; // skip broadcast and multicast
        }
        foreach (Match m in Regex.Matches(text ?? "", @"^(\d{1,3}(?:\.\d{1,3}){3})\s+0x\w+\s+0x(\w+)\s+([0-9a-fA-F:]{17})", RegexOptions.Multiline))
            if (m.Groups[2].Value != "0" && Oui.Normalize(m.Groups[3].Value) is { Length: > 0 } mac) d[m.Groups[1].Value] = mac;
        return d;
    }

    private static string Field(string block, string label)
    {
        var m = Regex.Match(block, @"^\s*" + Regex.Escape(label) + @"\s*:\s*(.*)$", RegexOptions.Multiline | RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value.Trim() : "";
    }

    private static int Int(string s) => int.TryParse(new string(s.TakeWhile(char.IsDigit).ToArray()), out var n) ? n : 0;

    /// <summary>The connected Wi-Fi from "netsh wlan show interfaces" (English Windows).</summary>
    public static WifiNetwork? WlanInterface(string text)
    {
        if (string.IsNullOrWhiteSpace(text) || !Field(text, "State").StartsWith("connected", StringComparison.OrdinalIgnoreCase)) return null;
        var ch = Int(Field(text, "Channel"));
        return new WifiNetwork
        {
            Ssid = Field(text, "SSID"), Bssid = Oui.Normalize(Field(text, "BSSID")), SignalPercent = Int(Field(text, "Signal")),
            Channel = ch, Band = Band(ch, Field(text, "Band")), Security = Field(text, "Authentication"), Connected = true,
        };
    }

    /// <summary>Nearby access points from "netsh wlan show networks mode=bssid" (English Windows).</summary>
    public static List<WifiNetwork> WlanNetworks(string text)
    {
        var list = new List<WifiNetwork>();
        var blocks = Regex.Split(text ?? "", @"^SSID \d+ :", RegexOptions.Multiline).Skip(1);
        foreach (var block in blocks)
        {
            var ssid = block.Split('\n')[0].Trim();
            var auth = Field(block, "Authentication");
            foreach (var b in Regex.Split(block, @"^\s*BSSID \d+\s*:", RegexOptions.Multiline).Skip(1))
            {
                var bssid = Oui.Normalize(b.Split('\n')[0]);
                var ch = Int(Field(b, "Channel"));
                list.Add(new WifiNetwork { Ssid = ssid.Length > 0 ? ssid : "(hidden)", Bssid = bssid, SignalPercent = Int(Field(b, "Signal")), Channel = ch, Band = Band(ch, Field(b, "Band")), Security = auth });
            }
        }
        return list;
    }

    public static string Band(int channel, string reported = "") =>
        reported.Contains("6", StringComparison.Ordinal) && reported.Contains("GHz", StringComparison.OrdinalIgnoreCase) && !reported.Contains("2.4") ? "6 GHz"
        : channel is >= 1 and <= 14 ? "2.4 GHz" : channel >= 32 ? "5 GHz" : reported;

    /// <summary>A web page's title, tidied, from its HTML ("" if none).</summary>
    public static string Title(string html)
    {
        var m = Regex.Match(html ?? "", @"<title[^>]*>\s*([^<]{1,120})", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(200));
        return m.Success ? WebUtility.HtmlDecode(Regex.Replace(m.Groups[1].Value, @"\s+", " ")).Trim() : "";
    }

    /// <summary>The NetBIOS computer name from a node status reply (UDP 137), or "".</summary>
    public static string NetBiosName(byte[] reply)
    {
        // Header 12 bytes, question name 34 + type/class 4, then answer: name(2 ptr or 34) type class ttl rdlength, then count + 18-byte entries.
        if (reply.Length < 57) return "";
        int i = 12 + 34 + 4;           // our query is echoed
        if (reply[i] == 0xC0) i += 2; else i += 34;
        i += 2 + 2 + 4 + 2;            // type, class, ttl, rdlength
        if (i >= reply.Length) return "";
        int count = reply[i++];
        for (int n = 0; n < count && i + 18 <= reply.Length; n++, i += 18)
        {
            var name = System.Text.Encoding.ASCII.GetString(reply, i, 15).TrimEnd(' ', '\0');
            byte suffix = reply[i + 15];
            bool group = (reply[i + 16] & 0x80) != 0;
            if (suffix == 0x00 && !group && name.Length > 0 && name.All(c => c >= 0x20 && c < 0x7F)) return name;
        }
        return "";
    }

    /// <summary>The query that asks a Windows PC (or Samba box) for its NetBIOS names.</summary>
    public static byte[] NetBiosQuery(ushort id)
    {
        var q = new byte[50];
        q[0] = (byte)(id >> 8); q[1] = (byte)id;
        q[5] = 1;                       // one question
        q[12] = 0x20;                   // name length 32: "*" encoded
        q[13] = (byte)('A' + ('*' >> 4)); q[14] = (byte)('A' + ('*' & 0xF));
        for (int i = 15; i < 45; i++) q[i] = (byte)'A';
        q[46] = 0; q[47] = 0x21;        // NBSTAT
        q[48] = 0; q[49] = 1;           // IN
        return q;
    }

    /// <summary>SSDP replies: the LOCATION and SERVER headers.</summary>
    public static (string Location, string Server) Ssdp(string reply)
    {
        string H(string n) { var m = Regex.Match(reply ?? "", @"^" + n + @":\s*(.+?)\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase); return m.Success ? m.Groups[1].Value : ""; }
        return (H("LOCATION"), H("SERVER"));
    }

    /// <summary>friendlyName, manufacturer and modelName from a UPnP device description.</summary>
    public static (string Friendly, string Maker, string Model, string Type) Upnp(string xml)
    {
        string T(string tag) { var m = Regex.Match(xml ?? "", "<" + tag + @">\s*([^<]{1,100})\s*</" + tag + ">", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(200)); return m.Success ? WebUtility.HtmlDecode(m.Groups[1].Value.Trim()) : ""; }
        return (T("friendlyName"), T("manufacturer"), (T("modelName") + " " + T("modelNumber")).Trim(), T("deviceType"));
    }
}
