using System.Net;
using System.Text.Json.Serialization;

namespace NightTech.Business.Core.Network;

public enum DeviceKind
{
    Unknown, Router, NetworkGear, WindowsPc, Mac, LinuxDevice, Server, Printer, Nas, Camera, Phone, Tablet, TvOrStreamer,
    SmartHome, VoipPhone, PosTerminal, GameConsole, ThisPc,
}

/// <summary>Something listening on a device: a port and what it usually is.</summary>
public sealed class Service
{
    public int Port { get; set; }
    public string Name { get; set; } = "";
    /// <summary>Extra detail: a web page title, a printer model, a UPnP description.</summary>
    public string Detail { get; set; } = "";
}

public sealed class Device
{
    public string Ip { get; set; } = "";
    public string Mac { get; set; } = "";
    public string Maker { get; set; } = "";
    /// <summary>The address is "private" (randomized), as phones and newer laptops use on Wi-Fi: the maker can't be told from it.</summary>
    public bool RandomMac { get; set; }
    public string Name { get; set; } = "";       // DNS or NetBIOS name
    public string Model { get; set; } = "";      // from UPnP/mDNS when offered
    public DeviceKind Kind { get; set; }
    public string KindReason { get; set; } = "";
    public bool AnswersPing { get; set; }
    public int? PingMs { get; set; }
    public List<Service> Services { get; set; } = new();
    public List<string> Notes { get; set; } = new();
    public bool IsGateway { get; set; }
    /// <summary>Answered UPnP discovery (on a router, UPnP lets devices open ports to the internet).</summary>
    public bool Upnp { get; set; }
    public bool IsThisPc { get; set; }
    /// <summary>The owner's own label, typed by the technician ("Front desk PC").</summary>
    public string Label { get; set; } = "";

    [JsonIgnore] public uint Sort => IPAddress.TryParse(Ip, out var a) && a.GetAddressBytes() is { Length: 4 } b ? (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]) : uint.MaxValue;
    public bool Has(int port) => Services.Any(s => s.Port == port);
}

public sealed class WifiNetwork
{
    public string Ssid { get; set; } = "";
    public string Bssid { get; set; } = "";
    public int SignalPercent { get; set; }
    public int Channel { get; set; }
    public string Band { get; set; } = "";
    public string Security { get; set; } = "";
    public bool Connected { get; set; }
}

public sealed class NetworkInfo
{
    public string Adapter { get; set; } = "";
    public string LocalIp { get; set; } = "";
    public int PrefixLength { get; set; }
    public string Gateway { get; set; } = "";
    public List<string> DnsServers { get; set; } = new();
    public string DhcpServer { get; set; } = "";
    public string DnsSuffix { get; set; } = "";
    public string ScannedRange { get; set; } = "";
    public int AddressesScanned { get; set; }
    public WifiNetwork? ConnectedWifi { get; set; }
    public List<WifiNetwork> NearbyWifi { get; set; } = new();
}

public sealed class SoftwareItem
{
    public string Name { get; set; } = "";
    public string Version { get; set; } = "";
    public string Publisher { get; set; } = "";
    public DateTime? Installed { get; set; }
}

/// <summary>Programs installed on one Windows PC: read from this PC, read over the network, or imported from a file made on that PC.</summary>
public sealed class PcInventory
{
    public string Computer { get; set; } = "";
    public string Ip { get; set; } = "";
    public string Windows { get; set; } = "";
    public string Source { get; set; } = "";   // "This PC", "Read over the network", "Imported file"
    public DateTime Taken { get; set; }
    public List<SoftwareItem> Programs { get; set; } = new();
}

public enum NoteLevel { Info, Warning, Risk }

public sealed class NetFinding
{
    public NoteLevel Level { get; set; }
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public NetFinding() { }
    public NetFinding(NoteLevel level, string title, string detail = "") { Level = level; Title = title; Detail = detail; }
}
