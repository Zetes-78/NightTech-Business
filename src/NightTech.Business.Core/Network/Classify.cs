using System.Text.RegularExpressions;

namespace NightTech.Business.Core.Network;

/// <summary>Works out what kind of device each one is (from its maker, name and what it offers), and what's worth a note.</summary>
public static class Classify
{
    private static bool Word(string text, string word) =>
        text.Length > 0 && Regex.IsMatch(text, @"(?<![A-Za-z0-9])" + Regex.Escape(word) + @"(?![A-Za-z0-9])", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50));

    /// <summary>The maker (or the model it announces) contains one of these as a whole word: "Nest" isn't "Finest", "Ring" isn't "Engineering".</summary>
    private static bool Maker(Device d, params string[] names) => names.Any(n => Word(d.Maker, n) || Word(d.Model, n));

    /// <summary>The maker is exactly one of these (for names that are also common words, like Square or Ring).</summary>
    private static bool MakerIs(Device d, params string[] names) => names.Any(n => d.Maker.Equals(n, StringComparison.OrdinalIgnoreCase));

    private static bool Named(Device d, params string[] parts) =>
        parts.Any(p => Word(d.Name, p) || Word(d.Model, p) || d.Services.Any(s => Word(s.Detail, p)) || d.UpnpTypes.Any(t => t.Contains(p, StringComparison.OrdinalIgnoreCase)));

    public static string Label(DeviceKind k) => k switch
    {
        DeviceKind.Router => "Router / gateway",
        DeviceKind.NetworkGear => "Network equipment (switch, Wi-Fi access point)",
        DeviceKind.WindowsPc => "Windows computer",
        DeviceKind.Computer => "Computer (firewall on, details hidden)",
        DeviceKind.Mac => "Mac",
        DeviceKind.AppleDevice => "Apple device (Mac, Apple TV or HomePod)",
        DeviceKind.LinuxDevice => "Linux device",
        DeviceKind.Server => "Server",
        DeviceKind.Printer => "Printer",
        DeviceKind.Nas => "Network storage (NAS)",
        DeviceKind.Camera => "Camera or video recorder",
        DeviceKind.Phone => "Phone or tablet",
        DeviceKind.Tablet => "Tablet",
        DeviceKind.PrivateAddress => "Phone, tablet or laptop (private address)",
        DeviceKind.TvOrStreamer => "TV or streaming device",
        DeviceKind.SmartHome => "Smart device (speaker, plug, thermostat, doorbell)",
        DeviceKind.VoipPhone => "Desk phone (VoIP)",
        DeviceKind.PosTerminal => "Card reader / point of sale",
        DeviceKind.GameConsole => "Game console",
        DeviceKind.ThisPc => "This computer (running the scan)",
        _ => "Unknown device",
    };

    /// <summary>Kinds that count as the business's own computers.</summary>
    public static bool IsComputer(DeviceKind k) => k is DeviceKind.WindowsPc or DeviceKind.Computer or DeviceKind.Mac or DeviceKind.Server or DeviceKind.ThisPc;

    public static void Apply(Device d)
    {
        (DeviceKind k, string why) = Decide(d);
        d.Kind = k;
        d.KindReason = why;
    }

    private static readonly string[] PcMakers = { "Dell", "Lenovo", "HP", "Hewlett Packard", "Hewlett-Packard", "Intel Corporate", "Microsoft", "ASUSTek Computer", "Acer", "Micro-Star", "Gigabyte", "ASRock", "Liteon", "AzureWave", "Framework", "Panasonic Mobile", "Toshiba", "Fujitsu" };

    private static (DeviceKind, string) Decide(Device d)
    {
        if (d.IsThisPc) return (DeviceKind.ThisPc, "the computer running the scan");
        if (d.IsGateway) return (DeviceKind.Router, "the network's gateway");
        if (Maker(d, "Verifone", "Ingenico", "PAX Technology", "Clover Network", "Elo Touch", "Posiflex") || MakerIs(d, "Square", "Toast"))
            return (DeviceKind.PosTerminal, "made by a card-terminal maker");
        if (Maker(d, "Synology", "QNAP", "Asustor", "Buffalo", "TerraMaster", "Drobo") || Named(d, "DiskStation", "NAS"))
            return (DeviceKind.Nas, "network storage maker or name");
        if (d.Has(554) || d.Has(37777) || Maker(d, "Hikvision", "Dahua", "Amcrest", "Reolink", "Axis Communications", "Hanwha", "Uniview", "Lorex", "Swann", "Wyze") || Named(d, "NVR", "DVR", "IPCam"))
            return (DeviceKind.Camera, d.Has(554) ? "streams video (RTSP)" : "made by a camera maker");
        if (Maker(d, "Apple"))
        {
            if (d.Has(62078)) return (DeviceKind.Phone, "iPhone/iPad sync service");
            if (d.Has(548) || d.Has(22) || d.Has(445) || d.Has(5900) || Named(d, "MacBook", "iMac", "Mac-mini", "Macmini", "MacBook-Pro", "MacBook-Air"))
                return (DeviceKind.Mac, "Apple computer with file sharing, remote login or a Mac name");
            if (d.Has(7000) || d.Has(5000) || d.Has(8009)) return (DeviceKind.AppleDevice, "AirPlay: a Mac, Apple TV or HomePod");
            return (DeviceKind.Phone, "Apple device with no services (usually an iPhone, iPad or Watch)");
        }
        if (d.Has(548) || Named(d, "MacBook", "iMac")) return (DeviceKind.Mac, "Mac file sharing or a Mac name");
        if (d.Has(9100) || d.Has(631) || d.Has(515) || Maker(d, "Brother", "Seiko Epson", "Epson", "Lexmark", "Xerox", "Ricoh", "Kyocera", "Konica Minolta", "Canon"))
            return (DeviceKind.Printer, d.Has(9100) || d.Has(631) ? "accepts print jobs" : "made by a printer maker");
        if (d.Has(5060) || Maker(d, "Yealink", "Polycom", "Poly", "Grandstream", "Mitel", "Avaya", "Snom", "Fanvil"))
            return (DeviceKind.VoipPhone, "desk-phone maker or SIP");
        if (Maker(d, "Nintendo", "Sony Interactive Entertainment") || Named(d, "Xbox", "PlayStation", "PS5", "PS4"))
            return (DeviceKind.GameConsole, "game console maker or name");
        if (d.Has(8060) || Maker(d, "Roku", "Vizio") || Named(d, "Roku", "FireTV", "Fire TV", "AppleTV", "Apple TV", "Chromecast", "BRAVIA", "SmartTV", "MediaRenderer"))
            return (DeviceKind.TvOrStreamer, "TV or streamer name, maker or port");
        if (d.Has(8008) && Maker(d, "Google")) return (DeviceKind.TvOrStreamer, "Google Cast device");
        if (d.Has(135) || d.Has(3389) || d.Has(5357) || (d.Has(445) && !d.Has(22)))
            return (Named(d, "SRV", "SERVER", "DC", "DC01", "DC1") || d.Has(53) && d.Has(445) ? DeviceKind.Server : DeviceKind.WindowsPc, "Windows services (file sharing, Remote Desktop or RPC)");
        if (d.Has(22) && d.Has(445)) return (DeviceKind.LinuxDevice, "Linux with file sharing (Samba)");
        if (Maker(d, "Ubiquiti", "Netgear", "Cisco", "Aruba", "Meraki", "eero", "Linksys", "Ruckus", "MikroTik", "Juniper", "Fortinet", "SonicWall", "Zyxel", "D-Link", "Cambium", "EnGenius", "Arris", "Sagemcom", "Technicolor", "TP-Link")
            && (d.Has(80) || d.Has(443) || d.Has(22) || d.Has(8443)))
            return (DeviceKind.NetworkGear, "network-equipment maker with a web admin page");
        if (Maker(d, "Espressif", "Tuya", "Shelly", "Nest", "Nest Labs", "ecobee", "Sonos", "Signify", "Philips Lighting", "Amazon", "iRobot", "Lutron", "Chamberlain", "Belkin", "TP-Link", "LIFX", "Ezviz") || MakerIs(d, "Ring"))
            return (DeviceKind.SmartHome, "smart-device maker");
        if (PcMakers.Any(m => Word(d.Maker, m))) return (DeviceKind.Computer, $"made by a computer maker ({d.Maker}); its firewall hides the rest");
        if (Maker(d, "Samsung", "Motorola", "OnePlus", "Xiaomi", "Huawei", "OPPO", "vivo", "Google") && d.Services.Count == 0)
            return (DeviceKind.Phone, "phone maker, no services");
        if (d.RandomMac && d.Services.Count == 0) return (DeviceKind.PrivateAddress, "uses a private (random) address, as phones and newer laptops do");
        if (d.Has(22) && d.Services.Count <= 3) return (DeviceKind.LinuxDevice, "SSH only");
        return (DeviceKind.Unknown, d.Maker.Length > 0 ? "made by " + d.Maker : "no identifying details");
    }

    /// <summary>Things worth telling the owner about, across the whole network.</summary>
    public static List<NetFinding> Findings(IReadOnlyList<Device> devices, NetworkInfo net)
    {
        var f = new List<NetFinding>();
        string Who(Device d) => (d.Label.Length > 0 ? d.Label : d.Name.Length > 0 ? d.Name : d.Model.Length > 0 ? d.Model : d.Ip) + $" ({d.Ip})";
        string List(IEnumerable<Device> ds) { var l = ds.Select(Who).ToList(); return string.Join(", ", l.Take(8)) + (l.Count > 8 ? $" and {l.Count - 8} more" : ""); }

        var telnet = devices.Where(d => d.Has(23)).ToList();
        if (telnet.Count > 0) f.Add(new(NoteLevel.Risk, $"Telnet is on ({telnet.Count} device(s))", $"Telnet sends passwords unencrypted. Turn it off or replace it with SSH: {List(telnet)}."));
        var ftp = devices.Where(d => d.Has(21)).ToList();
        if (ftp.Count > 0) f.Add(new(NoteLevel.Warning, $"FTP is on ({ftp.Count} device(s))", $"Plain FTP sends passwords unencrypted. Use SFTP or turn it off if nobody uses it: {List(ftp)}."));
        var vnc = devices.Where(d => d.Has(5900)).ToList();
        if (vnc.Count > 0) f.Add(new(NoteLevel.Warning, $"VNC remote control is on ({vnc.Count} device(s))", $"Make sure it has a strong password and that the owner knows it's there: {List(vnc)}."));
        var remote = devices.Where(d => d.Has(7070) || d.Has(5938)).ToList();
        if (remote.Count > 0) f.Add(new(NoteLevel.Warning, "Remote-control software is listening", $"AnyDesk or TeamViewer on {List(remote)}. Confirm the owner knows who uses it; scammers use the same tools."));
        var rdp = devices.Where(d => d.Has(3389) && d.Kind != DeviceKind.ThisPc).ToList();
        if (rdp.Count > 0) f.Add(new(NoteLevel.Info, $"Remote Desktop is on for {rdp.Count} computer(s)", $"Fine inside the office if accounts have strong passwords. Make sure it isn't reachable from the internet: {List(rdp)}."));
        var db = devices.Where(d => d.Has(1433) || d.Has(3306)).ToList();
        if (db.Count > 0) f.Add(new(NoteLevel.Warning, "Database servers are open on the network", $"Check only the programs that need them can reach them, and that they're backed up: {List(db)}."));
        var gw = devices.FirstOrDefault(d => d.IsGateway);
        if (gw is { Upnp: true }) f.Add(new(NoteLevel.Warning, "UPnP is on at the router", "It lets any device on the network open doors to the internet without asking. Turn it off unless a game console or camera system truly needs it."));
        if (gw is not null && gw.Has(80) && !gw.Has(443)) f.Add(new(NoteLevel.Info, "The router's settings page isn't encrypted", "It only offers plain http. Make sure its admin password isn't the default."));
        var plainAdmin = devices.Where(d => d.Kind is DeviceKind.Camera or DeviceKind.Nas or DeviceKind.Printer && d.Has(80) && !d.Has(443)).ToList();
        if (plainAdmin.Count > 0) f.Add(new(NoteLevel.Info, "Some devices' settings pages aren't encrypted", $"Check none still use the factory password: {List(plainAdmin)}."));

        var iot = devices.Count(d => d.Kind is DeviceKind.Camera or DeviceKind.SmartHome or DeviceKind.TvOrStreamer or DeviceKind.GameConsole);
        var work = devices.Count(d => IsComputer(d.Kind) || d.Kind is DeviceKind.Nas or DeviceKind.PosTerminal);
        if (iot >= 2 && work >= 1)
            f.Add(new(NoteLevel.Warning, $"{iot} cameras, TVs or smart devices share the network with the business computers",
                "These devices rarely get security updates. Put them (and guests) on a separate network or VLAN so a weak one can't reach the computers or card readers."));
        var pos = devices.Where(d => d.Kind == DeviceKind.PosTerminal).ToList();
        if (pos.Count > 0 && iot > 0) f.Add(new(NoteLevel.Warning, "Card readers are on the same network as other devices", "Card-industry rules (PCI) expect payment devices to be kept apart from everything else."));
        var unknown = devices.Where(d => d.Kind == DeviceKind.Unknown).ToList();
        if (unknown.Count > 0) f.Add(new(NoteLevel.Info, $"{unknown.Count} device(s) couldn't be identified", $"Ask the owner what these are, and label them: {List(unknown)}."));

        if (net.ConnectedWifi is { } w)
        {
            var sec = w.Security.ToUpperInvariant();
            if (sec.Contains("OPEN") || sec.Length == 0) f.Add(new(NoteLevel.Risk, $"Wi-Fi \"{w.Ssid}\" has no password", "Anyone nearby can join it and reach every device. Turn on WPA2 or WPA3."));
            else if (sec.Contains("WEP") || (sec.Contains("WPA") && !sec.Contains("WPA2") && !sec.Contains("WPA3")))
                f.Add(new(NoteLevel.Risk, $"Wi-Fi \"{w.Ssid}\" uses outdated security ({w.Security})", "It can be broken in minutes. Switch the router to WPA2 or WPA3."));
            else if (sec.Contains("WPA3")) f.Add(new(NoteLevel.Info, $"Wi-Fi \"{w.Ssid}\" uses WPA3", "The current standard."));
            if (w.SignalPercent is > 0 and < 50) f.Add(new(NoteLevel.Info, $"Wi-Fi signal here is weak ({w.SignalPercent}%)", "Where the scan ran, the signal is poor. An extra access point may help."));
            if (w.Band == "2.4 GHz")
            {
                var same = net.NearbyWifi.Count(n => n.Band == "2.4 GHz" && Math.Abs(n.Channel - w.Channel) < 5 && n.Bssid != w.Bssid);
                if (same >= 4) f.Add(new(NoteLevel.Info, $"Wi-Fi channel {w.Channel} is crowded", $"{same} other networks nearby overlap it. Use 5 GHz where possible, or channel 1, 6 or 11, whichever is quietest."));
                else if (w.Channel is not (1 or 6 or 11)) f.Add(new(NoteLevel.Info, $"Wi-Fi is on channel {w.Channel}", "On 2.4 GHz, channels 1, 6 and 11 don't overlap; the others interfere with neighbors."));
            }
        }
        var openNearby = net.NearbyWifi.Where(n => n.Security.Contains("Open", StringComparison.OrdinalIgnoreCase) && n.Ssid != "(hidden)").Select(n => n.Ssid).Distinct().ToList();
        if (openNearby.Count > 0 && net.ConnectedWifi is { } cw && openNearby.Contains(cw.Ssid) is false)
            f.Add(new(NoteLevel.Info, "Open (no password) Wi-Fi networks nearby", $"{string.Join(", ", openNearby.Take(5))}. If one is the business's guest network, make sure it's kept apart from the business network."));

        return f.OrderByDescending(x => x.Level).ToList();
    }
}
