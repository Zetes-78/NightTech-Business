using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace NightTech.Business.Core.Network;

/// <summary>
/// Finds the devices on a local network and what they offer. Everything is look-only: a ping, a knock on common ports
/// (connect, then hang up), a name lookup, and reading the public front page of web interfaces. It never logs in,
/// sends data to a device, or changes anything. It only scans private (local) address ranges.
/// </summary>
public sealed class Scanner
{
    public static readonly (int Port, string Name)[] Ports =
    {
        (21, "FTP file transfer"), (22, "SSH remote login"), (23, "Telnet (unencrypted remote login)"), (53, "DNS"),
        (80, "Web page"), (135, "Windows RPC"), (139, "Windows file sharing (old)"), (443, "Secure web page"),
        (445, "Windows file sharing"), (515, "Printer (LPD)"), (548, "Mac file sharing"), (554, "Video stream (RTSP)"),
        (631, "Printer (IPP)"), (1433, "SQL Server database"), (3306, "MySQL database"), (3389, "Remote Desktop"),
        (5000, "Web admin / NAS"), (5001, "Secure web admin / NAS"), (5060, "VoIP phone (SIP)"), (5357, "Windows device discovery"),
        (5900, "VNC remote control"), (5938, "TeamViewer"), (7000, "AirPlay"), (7070, "AnyDesk"), (8000, "Web admin / camera"),
        (8008, "Chromecast / Google device"), (8060, "Roku"), (8080, "Web admin"), (8443, "Secure web admin"),
        (9100, "Printer (direct print)"), (37777, "Camera recorder (Dahua)"), (62078, "iPhone/iPad sync"),
    };

    public static string PortName(int port) => Ports.FirstOrDefault(p => p.Port == port).Name ?? $"Port {port}";

    public int Parallel { get; init; } = 64;
    public TimeSpan PingTimeout { get; init; } = TimeSpan.FromMilliseconds(800);
    public TimeSpan PortTimeout { get; init; } = TimeSpan.FromMilliseconds(500);

    /// <summary>Reads the system's ARP table (IP to MAC). Supplied by the app, because it's different on each system.</summary>
    public Func<Dictionary<string, string>> ReadArp { get; init; } = () => new();

    public async Task<List<Device>> ScanAsync(IReadOnlyList<IPAddress> hosts, IPAddress? self, IPAddress? gateway,
        IProgress<(string Stage, double Fraction)>? progress, CancellationToken ct)
    {
        foreach (var h in hosts) if (!Subnet.IsPrivate(h)) throw new InvalidOperationException($"{h} isn't a private (local) address: the scanner only checks local networks.");
        var found = new ConcurrentDictionary<string, Device>();
        using var gate = new SemaphoreSlim(Parallel);

        // 1. Who's there: ping, plus a quick knock on ports most devices answer even when ping is blocked.
        var quick = new[] { 80, 443, 445, 62078, 7000, 8008, 9100 };
        int done = 0;
        await Task.WhenAll(hosts.Select(async ip =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var d = new Device { Ip = ip.ToString() };
                try
                {
                    using var ping = new Ping();
                    var reply = await ping.SendPingAsync(ip, (int)PingTimeout.TotalMilliseconds);
                    if (reply.Status == IPStatus.Success) { d.AnswersPing = true; d.PingMs = (int)reply.RoundtripTime; }
                }
                catch (PingException) { }
                catch (PlatformNotSupportedException) { }
                foreach (var p in quick)
                {
                    ct.ThrowIfCancellationRequested();
                    if (await Open(ip, p, ct)) d.Services.Add(new Service { Port = p, Name = PortName(p) });
                }
                if (d.AnswersPing || d.Services.Count > 0) found[d.Ip] = d;
            }
            finally
            {
                gate.Release();
                progress?.Report(("Looking for devices", Interlocked.Increment(ref done) / (double)hosts.Count * 0.5));
            }
        }));

        // 2. Devices that block ping and every port still show up in the ARP table once we've tried to reach them.
        foreach (var (ip, mac) in ReadArp())
        {
            if (!hosts.Any(h => h.ToString() == ip)) continue;
            var d = found.GetOrAdd(ip, _ => new Device { Ip = ip });
            d.Mac = mac;
        }
        if (self is not null && hosts.Any(h => h.Equals(self))) found.GetOrAdd(self.ToString(), _ => new Device { Ip = self.ToString() }).IsThisPc = true;
        if (gateway is not null && found.TryGetValue(gateway.ToString(), out var gw)) gw.IsGateway = true;

        // 3. What each device offers: the full port list, names, and web page titles.
        var devices = found.Values.ToList();
        var ssdp = await SsdpAsync(ct);
        done = 0;
        await Task.WhenAll(devices.Select(async d =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var ip = IPAddress.Parse(d.Ip);
                foreach (var (port, name) in Ports)
                {
                    ct.ThrowIfCancellationRequested();
                    if (d.Has(port)) continue;
                    if (await Open(ip, port, ct)) d.Services.Add(new Service { Port = port, Name = name });
                }
                d.Services.Sort((a, b) => a.Port.CompareTo(b.Port));
                d.Name = await NameAsync(ip, ct);
                foreach (var s in d.Services.Where(s => s.Port is 80 or 8080 or 443 or 8443 or 5000 or 5001 or 8000))
                    s.Detail = await TitleAsync(ip, s.Port, ct);
                if (ssdp.TryGetValue(d.Ip, out var ad))
                {
                    d.UpnpTypes.AddRange(ad.Types);
                    // Port forwarding by UPnP is only on when the router announces itself as an internet gateway (not just a media server).
                    d.Upnp = ad.Types.Any(t => t.Contains("InternetGatewayDevice", StringComparison.OrdinalIgnoreCase) || t.Contains("WANIPConnection", StringComparison.OrdinalIgnoreCase) || t.Contains("WANPPPConnection", StringComparison.OrdinalIgnoreCase));
                    foreach (var loc in ad.Locations.Take(3))
                    {
                        var (friendly, maker, model, type) = await UpnpAsync(loc, ip, ct);
                        if (model.Length > 0 && d.Model.Length == 0) d.Model = Clean((maker.Length > 0 && !model.StartsWith(maker, StringComparison.OrdinalIgnoreCase) ? maker + " " : "") + model);
                        if (friendly.Length > 0 && d.Name.Length == 0) d.Name = Clean(friendly);
                        if (type.Length > 0 && !d.UpnpTypes.Contains(type)) d.UpnpTypes.Add(type);
                    }
                    if (d.UpnpTypes.Any(t => t.Contains("InternetGatewayDevice", StringComparison.OrdinalIgnoreCase))) d.Upnp = true;
                }
                if (d.Mac.Length > 0) { d.RandomMac = Oui.IsRandom(d.Mac); d.Maker = Oui.Maker(d.Mac); }
            }
            finally
            {
                gate.Release();
                progress?.Report(("Identifying devices", 0.5 + Interlocked.Increment(ref done) / (double)Math.Max(1, devices.Count) * 0.5));
            }
        }));
        foreach (var d in devices) Classify.Apply(d);
        return devices.OrderBy(d => d.Sort).ToList();
    }

    private async Task<bool> Open(IPAddress ip, int port, CancellationToken ct)
    {
        using var c = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(PortTimeout);
        try { await c.ConnectAsync(ip, port, cts.Token); return true; }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return false; }
        catch (SocketException) { return false; }
    }

    /// <summary>Names from the network can contain anything: keep printable characters only, and a sensible length.</summary>
    internal static string Clean(string s) => new string((s ?? "").Where(c => !char.IsControl(c)).Take(80).ToArray()).Trim();

    private static async Task<string> NameAsync(IPAddress ip, CancellationToken ct)
    {
        // Windows PCs answer NetBIOS (local, quick) first; then reverse DNS, given at most 2 seconds.
        var nb = await NetBiosAsync(ip, ct);
        if (nb.Length > 0) return nb;
        try
        {
            var lookup = Dns.GetHostEntryAsync(ip.ToString());
            if (await Task.WhenAny(lookup, Task.Delay(2000, ct)) == lookup)
            {
                var e = await lookup;
                if (!string.IsNullOrWhiteSpace(e.HostName) && e.HostName != ip.ToString()) return Clean(e.HostName.Split('.')[0]);
            }
            else _ = lookup.ContinueWith(t => _ = t.Exception, TaskScheduler.Default); // abandoned: observe its error later
        }
        catch (Exception x) when (x is SocketException or ArgumentException) { }
        ct.ThrowIfCancellationRequested();
        return "";
    }

    private static async Task<string> NetBiosAsync(IPAddress ip, CancellationToken ct)
    {
        try
        {
            using var u = new UdpClient();
            u.Client.ReceiveTimeout = 800;
            var q = Parse.NetBiosQuery((ushort)Random.Shared.Next(1, 65535));
            await u.SendAsync(q, q.Length, new IPEndPoint(ip, 137));
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMilliseconds(900));
            var r = await u.ReceiveAsync(cts.Token);
            if (r.RemoteEndPoint.Address.Equals(ip)) return Clean(Parse.NetBiosName(r.Buffer));
        }
        catch (Exception x) when (x is SocketException or OperationCanceledException) { if (ct.IsCancellationRequested) throw; }
        return "";
    }

    private static HttpClient Http(bool acceptAnyCertificate) => new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseProxy = false,   // straight to the device: never through the office's proxy or a WPAD-announced one
        ConnectTimeout = TimeSpan.FromSeconds(2),
        // Only to read a device's own login page title on the local network (most use self-signed certificates). Nothing is sent.
        SslOptions = { RemoteCertificateValidationCallback = acceptAnyCertificate ? (_, _, _, _) => true : null },
    }) { Timeout = TimeSpan.FromSeconds(3) };

    private static readonly HttpClient Plain = Http(false), Tls = Http(true);

    private static async Task<string> TitleAsync(IPAddress ip, int port, CancellationToken ct)
    {
        bool tls = port is 443 or 8443 or 5001;
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(4));   // the whole request, body included: a device that stalls can't hold up the scan
        var lt = limit.Token;
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{(tls ? "https" : "http")}://{ip}:{port}/");
            req.Headers.UserAgent.ParseAdd("NightTechNetworkScan/1.0");
            using var resp = await (tls ? Tls : Plain).SendAsync(req, HttpCompletionOption.ResponseHeadersRead, lt);
            var server = resp.Headers.Server.ToString();
            if ((int)resp.StatusCode is >= 300 and < 400) return Clean("redirects to its login page" + (server.Length > 0 ? $" ({server})" : ""));
            await using var s = await resp.Content.ReadAsStreamAsync(lt);
            var buf = new byte[32 * 1024];
            int n = 0, r;
            while (n < buf.Length && (r = await s.ReadAsync(buf.AsMemory(n), lt)) > 0) n += r;
            var title = Parse.Title(Encoding.UTF8.GetString(buf, 0, n));
            return Clean(title.Length > 0 ? title : server);
        }
        catch (Exception x) when (x is HttpRequestException or TaskCanceledException or IOException or OperationCanceledException or System.Security.Authentication.AuthenticationException)
        {
            if (ct.IsCancellationRequested) throw;
            return "";
        }
    }

    /// <summary>UPnP discovery: asks everything on the network to describe itself (one multicast message), for 3 seconds.</summary>
    private sealed record Announce(List<string> Locations, List<string> Types);

    private static async Task<Dictionary<string, Announce>> SsdpAsync(CancellationToken ct)
    {
        var map = new Dictionary<string, Announce>();
        try
        {
            using var u = new UdpClient(AddressFamily.InterNetwork);
            var msg = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n");
            await u.SendAsync(msg, msg.Length, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900));
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(3));
            while (!cts.IsCancellationRequested)
            {
                var r = await u.ReceiveAsync(cts.Token);
                var text = Encoding.ASCII.GetString(r.Buffer);
                var (loc, _) = Parse.Ssdp(text);
                var st = Parse.Header(text, "ST") is { Length: > 0 } x ? x : Parse.Header(text, "NT");
                var ip = r.RemoteEndPoint.Address.ToString();
                if (!map.TryGetValue(ip, out var a)) map[ip] = a = new Announce(new(), new());
                if (loc.Length > 0 && !a.Locations.Contains(loc) && a.Locations.Count < 10) a.Locations.Add(loc);
                if (st.Length > 0 && !a.Types.Contains(st) && a.Types.Count < 30) a.Types.Add(st);
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
        catch (SocketException) { }
        return map;
    }

    private static async Task<(string, string, string, string)> UpnpAsync(string location, IPAddress ip, CancellationToken ct)
    {
        // Only follow the description link if it points back at the same device (never anywhere else).
        if (!Uri.TryCreate(location, UriKind.Absolute, out var u) || u.Scheme != "http" || u.Host != ip.ToString()) return ("", "", "", "");
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(ct);
        limit.CancelAfter(TimeSpan.FromSeconds(4));
        var lt = limit.Token;
        try
        {
            using var resp = await Plain.GetAsync(u, HttpCompletionOption.ResponseHeadersRead, lt);
            await using var s = await resp.Content.ReadAsStreamAsync(lt);
            var buf = new byte[64 * 1024];
            int n = 0, r;
            while (n < buf.Length && (r = await s.ReadAsync(buf.AsMemory(n), lt)) > 0) n += r;
            return Parse.Upnp(Encoding.UTF8.GetString(buf, 0, n));
        }
        catch (Exception x) when (x is HttpRequestException or TaskCanceledException or IOException or OperationCanceledException)
        {
            if (ct.IsCancellationRequested) throw;
            return ("", "", "", "");
        }
    }
}
