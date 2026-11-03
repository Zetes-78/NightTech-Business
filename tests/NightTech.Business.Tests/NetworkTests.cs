using System.Net;
using System.Net.Sockets;
using NightTech.Business.Core.Network;

namespace NightTech.Business.Tests;

public class NetworkTests
{
    [Fact]
    public void Subnet_lists_hosts_and_caps_big_networks()
    {
        var (hosts, range) = Subnet.Hosts(IPAddress.Parse("192.168.1.57"), 24);
        Assert.Equal(254, hosts.Count);
        Assert.Equal("192.168.1.0/24", range);
        Assert.Equal("192.168.1.1", hosts[0].ToString());
        Assert.Equal("192.168.1.254", hosts[^1].ToString());

        var (big, r16) = Subnet.Hosts(IPAddress.Parse("10.4.9.20"), 16);
        Assert.Equal(254, big.Count);                     // a /16 scans only our /24
        Assert.Equal("10.4.9.0/24", r16);
        var (h22, _) = Subnet.Hosts(IPAddress.Parse("10.0.5.1"), 22);
        Assert.Equal(1022, h22.Count);

        Assert.True(Subnet.IsPrivate(IPAddress.Parse("172.20.1.1")));
        Assert.False(Subnet.IsPrivate(IPAddress.Parse("8.8.8.8")));
        Assert.False(Subnet.IsPrivate(IPAddress.Parse("172.32.0.1")));
    }

    [Fact]
    public void Scanner_refuses_public_addresses()
    {
        var s = new Scanner();
        Assert.ThrowsAsync<InvalidOperationException>(() => s.ScanAsync(new[] { IPAddress.Parse("8.8.8.8") }, null, null, null, CancellationToken.None)).Wait();
    }

    [Fact]
    public void Makers_come_from_the_mac_address()
    {
        Assert.Equal("AA:BB:CC:00:11:22", Oui.Normalize("aa-bb-cc-00-11-22"));
        Assert.Equal("00:1B:63:84:45:E6", Oui.Normalize("001b.6384.45e6"));
        Assert.Equal("", Oui.Normalize("ff-ff-ff-ff-ff-ff"));
        Assert.Contains("Apple", Oui.Maker("00:1B:63:84:45:E6"));         // 00:1B:63 is Apple
        Assert.True(Oui.IsRandom("DA:A1:19:00:00:01"));                    // locally administered = private address
        Assert.Equal("", Oui.Maker("DA:A1:19:00:00:01"));
        Assert.Equal("Hon Hai Precision Ind", Oui.Tidy("HON HAI PRECISION IND. CO.,LTD."));
        Assert.Equal("TP-Link Systems", Oui.Tidy("TP-LINK SYSTEMS INC."));
    }

    [Fact]
    public void Windows_command_output_is_read()
    {
        var arp = Parse.Arp("""
            Interface: 192.168.1.57 --- 0xb
              Internet Address      Physical Address      Type
              192.168.1.1           a0-b5-49-12-34-56     dynamic
              192.168.1.20          3c-2a-f4-aa-bb-cc     dynamic
              192.168.1.255         ff-ff-ff-ff-ff-ff     static
              224.0.0.22            01-00-5e-00-00-16     static
            """);
        Assert.Equal(2, arp.Count);
        Assert.Equal("A0:B5:49:12:34:56", arp["192.168.1.1"]);

        var wifi = Parse.WlanInterface("""
                Name                   : Wi-Fi
                State                  : connected
                SSID                   : Shop WiFi
                BSSID                  : 70:3a:cb:11:22:33
                Network type           : Infrastructure
                Radio type             : 802.11ax
                Authentication         : WPA2-Personal
                Channel                : 6
                Signal                 : 82%
            """)!;
        Assert.Equal("Shop WiFi", wifi.Ssid);
        Assert.Equal(6, wifi.Channel);
        Assert.Equal("2.4 GHz", wifi.Band);
        Assert.Equal(82, wifi.SignalPercent);

        var near = Parse.WlanNetworks("""
            SSID 1 : Shop WiFi
                Network type            : Infrastructure
                Authentication          : WPA2-Personal
                Encryption              : CCMP
                BSSID 1                 : 70:3a:cb:11:22:33
                     Signal             : 82%
                     Channel            : 6
                BSSID 2                 : 70:3a:cb:11:22:34
                     Signal             : 60%
                     Channel            : 149
            SSID 2 : Neighbor
                Authentication          : Open
                BSSID 1                 : 10:20:30:40:50:60
                     Signal             : 30%
                     Channel            : 6
            """);
        Assert.Equal(3, near.Count);
        Assert.Equal("5 GHz", near[1].Band);
        Assert.Equal("Open", near[2].Security);

        Assert.Equal("HP LaserJet Pro", Parse.Title("<html><head><title>\n HP  LaserJet Pro </title>"));
        var up = Parse.Upnp("<root><device><deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName>Lobby TV</friendlyName><manufacturer>Samsung</manufacturer><modelName>QN55</modelName></device></root>");
        Assert.Equal(("Lobby TV", "Samsung", "QN55"), (up.Friendly, up.Maker, up.Model));
        Assert.Equal("http://192.168.1.30:49152/desc.xml", Parse.Ssdp("HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.30:49152/desc.xml\r\nSERVER: Linux UPnP/1.0\r\n").Location);
    }

    [Fact]
    public void NetBios_query_and_reply_are_read_as_RFC_1002_says()
    {
        var q = Parse.NetBiosQuery(0x1234);
        Assert.Equal(50, q.Length);
        // A real node status reply: header (QDCOUNT 0, ANCOUNT 1), the answer's name in full, type/class/TTL/length, names.
        var reply = new List<byte> { 0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0 };
        reply.AddRange(q.Skip(12).Take(34));                    // RR name (same encoded "*" as the query)
        reply.AddRange(new byte[] { 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 37 });
        reply.Add(2);
        void Name(string n, byte suffix, byte flags) { reply.AddRange(System.Text.Encoding.ASCII.GetBytes(n.PadRight(15))); reply.Add(suffix); reply.Add(flags); reply.Add(0); }
        Name("WORKGROUP", 0x00, 0x80);      // group name: skipped
        Name("FRONT-DESK", 0x00, 0x04);
        Assert.Equal("FRONT-DESK", Parse.NetBiosName(reply.ToArray()));
        Assert.Equal("", Parse.NetBiosName(new byte[10]));

        // Some stacks send a compressed name pointer instead.
        var ptr = new List<byte> { 0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 0x0C, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 19, 1 };
        ptr.AddRange(System.Text.Encoding.ASCII.GetBytes("OFFICE-PC".PadRight(15))); ptr.AddRange(new byte[] { 0, 0x04, 0 });
        Assert.Equal("OFFICE-PC", Parse.NetBiosName(ptr.ToArray()));
    }

    private static Device D(string ip, string maker = "", params int[] ports)
    {
        var d = new Device { Ip = ip, Maker = maker };
        foreach (var p in ports) d.Services.Add(new Service { Port = p, Name = Scanner.PortName(p) });
        Classify.Apply(d);
        return d;
    }

    [Fact]
    public void Devices_are_identified()
    {
        Assert.Equal(DeviceKind.Printer, D("1", "Brother Industries").Kind);
        Assert.Equal(DeviceKind.Printer, D("2", "HP Inc", 80, 9100).Kind);
        Assert.Equal(DeviceKind.Camera, D("3", "Hangzhou Hikvision Digital", 80, 554).Kind);
        Assert.Equal(DeviceKind.Nas, D("4", "Synology", 5000, 445).Kind);
        Assert.Equal(DeviceKind.WindowsPc, D("5", "Dell", 135, 139, 445).Kind);
        Assert.Equal(DeviceKind.Phone, D("6", "Apple", 62078).Kind);
        Assert.Equal(DeviceKind.PosTerminal, D("7", "Verifone").Kind);
        Assert.Equal(DeviceKind.NetworkGear, D("8", "Ubiquiti", 22, 443).Kind);
        Assert.Equal(DeviceKind.TvOrStreamer, D("9", "Roku", 8060).Kind);
        Assert.Equal(DeviceKind.SmartHome, D("10", "Espressif").Kind);
        Assert.Equal(DeviceKind.Unknown, D("11").Kind);
        var phone = new Device { Ip = "12", RandomMac = true }; Classify.Apply(phone);
        Assert.Equal(DeviceKind.PrivateAddress, phone.Kind);
        var gw = new Device { Ip = "1.1", IsGateway = true, Maker = "Netgear" }; Classify.Apply(gw);
        Assert.Equal(DeviceKind.Router, gw.Kind);
    }

    [Fact]
    public void Findings_point_out_the_real_problems()
    {
        var devices = new List<Device>
        {
            new() { Ip = "192.168.1.1", IsGateway = true, Upnp = true, Services = { new Service { Port = 80 } } },
            D("192.168.1.10", "Dell", 135, 445, 3389),
            D("192.168.1.20", "Hangzhou Hikvision Digital", 80, 554, 23),
            D("192.168.1.21", "Espressif"),
            D("192.168.1.30", "Verifone"),
        };
        Classify.Apply(devices[0]);
        var net = new NetworkInfo { ConnectedWifi = new WifiNetwork { Ssid = "Shop", Security = "WPA-Personal", Channel = 3, Band = "2.4 GHz", SignalPercent = 90 } };
        var f = Classify.Findings(devices, net);
        Assert.Equal(NoteLevel.Risk, f[0].Level);
        Assert.Contains(f, x => x.Title.StartsWith("Telnet") && x.Level == NoteLevel.Risk);
        Assert.Contains(f, x => x.Title.Contains("outdated security") && x.Level == NoteLevel.Risk);
        Assert.Contains(f, x => x.Title.Contains("UPnP"));
        Assert.Contains(f, x => x.Title.Contains("share the network"));
        Assert.Contains(f, x => x.Title.Contains("Card readers"));
        Assert.Contains(f, x => x.Title.Contains("channel 3"));
    }

    [Fact]
    public void Programs_are_summarized_across_pcs()
    {
        var pcs = new List<PcInventory>
        {
            new() { Computer = "FRONT", Windows = "Windows 10 Pro", Programs = { new() { Name = "Google Chrome", Version = "130" }, new() { Name = "AnyDesk", Version = "8" }, new() { Name = "Microsoft Office Professional Plus 2016" }, new() { Name = "Norton 360" }, new() { Name = "McAfee LiveSafe" }, new() { Name = "Microsoft Visual C++ 2015-2022 Redistributable (x64)" } } },
            new() { Computer = "BACK", Windows = "Windows 11 Pro", Programs = { new() { Name = "Google Chrome", Version = "131" }, new() { Name = "QuickBooks Desktop Pro 2024" } } },
        };
        var all = Software.Summarize(pcs);
        Assert.DoesNotContain(all, s => s.Name.StartsWith("Microsoft Visual C++"));
        var chrome = all.Single(s => s.Name == "Google Chrome");
        Assert.Equal(2, chrome.Computers.Count);
        Assert.Equal(2, chrome.Versions.Count);
        Assert.Equal(NoteLevel.Risk, all[0].Level);              // Office 2016 first
        var f = Software.Findings(pcs, all);
        Assert.Contains(f, x => x.Title.Contains("AnyDesk"));
        Assert.Contains(f, x => x.Title.Contains("2 antivirus"));
        Assert.Contains(f, x => x.Title.Contains("Windows 10"));
    }

    [Fact]
    public void Report_round_trips_and_spreadsheets_are_safe()
    {
        var r = new NetworkReport
        {
            Business = "Acme <b>", Ticket = "77", Technician = "Jason", PermissionFrom = "Owner", Started = new DateTime(2026, 11, 3, 18, 0, 0), Finished = new DateTime(2026, 11, 3, 18, 10, 0),
            Devices = { D("192.168.1.5", "Dell", 445, 139, 135) },
            Computers = { new PcInventory { Computer = "PC1", Programs = { new() { Name = "=cmd|' /C calc'!A0", Version = "1" } } } },
        };
        r.Devices[0].Name = "=HYPERLINK(\"x\")";
        r.Evaluate();
        var back = NetworkReport.FromJson(r.ToJson())!;
        Assert.Equal(DeviceKind.WindowsPc, back.Devices[0].Kind);
        Assert.DoesNotContain("<b>", r.ToHtml().Replace("<b>1</b>", "").Replace("<b style", ""));
        Assert.Contains("'=HYPERLINK", r.DevicesCsv());
        Assert.Contains("'=cmd", r.SoftwareCsv());
        var inv = NetworkReport.InventoryFromJson(NetworkReport.InventoryJson(r.Computers[0]))!;
        Assert.Equal("PC1", inv.Computer);
        var fk = NetworkReport.InventoryFromJson("""{"tool":"Night Tech Field Kit","computer":{"name":"DESK2","osName":"Windows 11 Home"},"programs":[{"name":"Zoom","version":"6.1","publisher":"Zoom"}]}""")!;
        Assert.Equal("DESK2", fk.Computer);
        Assert.Equal("Zoom", fk.Programs[0].Name);
    }

    [Fact]
    public async Task Scanner_finds_a_listening_device_on_this_machine()
    {
        // A real scan of 127.0.0.1 can't be done (not private by our rule), so listen on this machine's private address if it has one.
        var local = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .SelectMany(n => n.GetIPProperties().UnicastAddresses).Select(a => a.Address)
            .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && Subnet.IsPrivate(a));
        if (local is null) return;
        var l = new TcpListener(local, 9100);
        try { l.Start(); } catch (SocketException) { return; }
        try
        {
            var s = new Scanner { PortTimeout = TimeSpan.FromMilliseconds(300), PingTimeout = TimeSpan.FromMilliseconds(300) };
            var found = await s.ScanAsync(new[] { local }, local, null, null, CancellationToken.None);
            var d = Assert.Single(found);
            Assert.True(d.IsThisPc);
            Assert.True(d.Has(9100));
        }
        finally { l.Stop(); }
    }

    [Fact]
    public void Classification_avoids_the_embarrassing_mistakes()
    {
        var jonas = D("1", "Dell", 135, 445); jonas.Name = "JONAS-PC"; Classify.Apply(jonas);
        Assert.Equal(DeviceKind.WindowsPc, jonas.Kind);                           // "NAS" inside a name isn't a NAS
        Assert.NotEqual(DeviceKind.SmartHome, D("2", "Precision Engineering").Kind);  // "Ring" inside a word
        Assert.NotEqual(DeviceKind.PosTerminal, D("3", "Square D").Kind);
        Assert.Equal(DeviceKind.PosTerminal, D("3b", "Square").Kind);
        Assert.NotEqual(DeviceKind.NetworkGear, D("4", "Harris", 80).Kind);
        Assert.Equal(DeviceKind.AppleDevice, D("5", "Apple", 5000, 7000).Kind);     // AirPlay Mac / Apple TV, not a phone
        Assert.Equal(DeviceKind.Nas, D("6", "Synology", 5000, 445, 631).Kind);     // NAS with print server stays a NAS
        Assert.Equal(DeviceKind.LinuxDevice, D("7", "Raspberry Pi Trading", 22, 139, 445).Kind);
        Assert.Equal(DeviceKind.Computer, D("8", "Dell").Kind);                     // firewall on
        var lap = new Device { Ip = "9", RandomMac = true }; Classify.Apply(lap);
        Assert.Equal(DeviceKind.PrivateAddress, lap.Kind);
        Assert.Equal(new[] { "192.168.1.254" }.Length, Subnet.Hosts(IPAddress.Parse("192.168.1.5"), 24, IPAddress.Parse("8.8.8.8")).Hosts.Count(h => h.ToString() == "8.8.8.8") + 1);
    }

    [Fact]
    public void Software_flags_only_the_pcs_that_need_it()
    {
        var pcs = new List<PcInventory>
        {
            new() { Computer = "A", Windows = "Windows 10 IoT Enterprise LTSC", Programs = { new() { Name = "Python 3.12.1" }, new() { Name = "WinRAR 7.13 (64-bit)", Version = "7.13.0" }, new() { Name = "Bitdefender Total Security" }, new() { Name = "Bitdefender Agent" }, new() { Name = "Microsoft 365 - en-us" } } },
            new() { Computer = "B", Windows = "Windows 11 Pro", Programs = { new() { Name = "Python 2.7.18" }, new() { Name = "WinRAR 6.02 (64-bit)", Version = "6.02.0" }, new() { Name = "Microsoft Office Shared 64-bit MUI (English) 2016" }, new() { Name = "Microsoft Office Professional Plus 2021" }, new() { Name = "Microsoft 365 - es-es" } } },
        };
        var all = Software.Summarize(pcs);
        var f = Software.Findings(pcs, all);
        var py = f.Single(x => x.Title.StartsWith("Python"));
        Assert.False(py.Detail.Split(", ").Select(x => x.Trim('.')).Contains("A"));
        Assert.Contains(f, x => x.Title.StartsWith("WinRAR") && x.Detail.Contains("B") && !x.Detail.Contains("A,"));
        Assert.Contains(f, x => x.Title.Contains("Office Professional Plus 2021"));
        Assert.DoesNotContain(f, x => x.Title.Contains("Shared"));
        Assert.DoesNotContain(f, x => x.Title.Contains("antivirus"));        // one maker
        Assert.DoesNotContain(f, x => x.Title.Contains("Windows 10"));       // LTSC is still supported
        Assert.Equal(1, all.Count(s => s.Name == "Microsoft 365"));
    }

    [Fact]
    public void Hostile_import_files_are_refused_or_cleaned()
    {
        Assert.Throws<InvalidDataException>(() => NetworkReport.InventoryFromJson("[]"));
        var pc = NetworkReport.InventoryFromJson("""{"computer":"x","programs":null}""")!;
        Assert.Empty(pc.Programs);
        var pc2 = NetworkReport.InventoryFromJson("""{"computer":"y","programs":[null,{"name":"Zoom","version":null}]}""")!;
        Assert.Equal(1, pc2.Programs.Count);
        Assert.Equal("", pc2.Programs[0].Version);
        var r = new NetworkReport { Computers = { pc, pc2 } };
        r.Evaluate();                                                        // doesn't throw
        Assert.Contains("\"a\rb\"", new NetworkReport { Devices = { new Device { Ip = "1", Name = "a\rb" } } }.DevicesCsv());
    }

    [Fact]
    public void Typed_ranges_are_read_and_limited_to_local_networks()
    {
        var (h1, _, e1) = Subnet.ParseRanges("192.168.1.0/24");
        Assert.Equal("", e1);
        Assert.Equal(254, h1.Count);
        var (h2, _, _) = Subnet.ParseRanges("192.168.1.10-192.168.1.20");
        Assert.Equal(11, h2.Count);
        var (h3, _, _) = Subnet.ParseRanges("192.168.1.50-40, 192.168.1.45 10.0.0.5");
        Assert.Equal(12, h3.Count);                                      // reversed range, a duplicate, and a second network
        Assert.Equal("10.0.0.5", h3[^1].ToString());
        var (h4, _, _) = Subnet.ParseRanges("192.168.10.0/24; 192.168.20.0/24");
        Assert.Equal(508, h4.Count);
        Assert.Contains("local", Subnet.ParseRanges("8.8.8.0/24").Error);
        Assert.Contains("local", Subnet.ParseRanges("172.31.255.250-172.32.0.5").Error);
        Assert.Contains("local", Subnet.ParseRanges("10.255.255.250-11.0.0.5").Error);
        Assert.Contains("more than", Subnet.ParseRanges("10.0.0.0/16").Error);
        Assert.Contains("isn't", Subnet.ParseRanges("192.168.1.0/40").Error);
        Assert.Contains("isn't", Subnet.ParseRanges("printer").Error);
        Assert.NotEqual("", Subnet.ParseRanges("  ").Error);
    }
}
