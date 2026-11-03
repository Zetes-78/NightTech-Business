using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Microsoft.Win32;
using NightTech.Business.Core.Network;

namespace NightTech.NetworkScan.Windows;

/// <summary>Windows-side reading: this PC's network settings, the ARP table, Wi-Fi, and installed programs. All read only.</summary>
public static class LocalNet
{
    public sealed record Adapter(string Name, IPAddress Ip, int Prefix, IPAddress? Gateway, List<string> Dns, string Dhcp, string Suffix, bool Wireless);

    /// <summary>Adapters that are up and have a private IPv4 address; the one with a gateway comes first.</summary>
    public static List<Adapter> Adapters()
    {
        var list = new List<Adapter>();
        foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (n.OperationalStatus != OperationalStatus.Up || n.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            if (n.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase) || n.Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase) || n.Description.Contains("VPN", StringComparison.OrdinalIgnoreCase)) continue;
            var p = n.GetIPProperties();
            var ua = p.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork && Subnet.IsPrivate(a.Address) && !a.Address.ToString().StartsWith("169.254", StringComparison.Ordinal));
            if (ua is null) continue;
            var gw = p.GatewayAddresses.Select(g => g.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any));
            string dhcp = "";
            try { dhcp = p.DhcpServerAddresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString() ?? ""; } catch (PlatformNotSupportedException) { }
            list.Add(new Adapter(n.Name + " (" + n.Description + ")", ua.Address, ua.PrefixLength, gw,
                p.DnsAddresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork).Select(a => a.ToString()).ToList(), dhcp, p.DnsSuffix,
                n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211));
        }
        return list.OrderBy(a => a.Gateway is null).ThenBy(a => a.Wireless).ToList();
    }

    private static string Run(string exe, string args, int seconds = 20)
    {
        try
        {
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, exe), args)
            { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
            using var p = Process.Start(psi)!;
            var outTask = p.StandardOutput.ReadToEndAsync();
            if (!p.WaitForExit(seconds * 1000)) { try { p.Kill(); } catch (InvalidOperationException) { } return ""; }
            return outTask.Result;
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException) { return ""; }
    }

    public static Dictionary<string, string> Arp() => Parse.Arp(Run("arp.exe", "-a"));

    public static (WifiNetwork? Connected, List<WifiNetwork> Nearby, string Note) Wifi()
    {
        var iface = Run("netsh.exe", "wlan show interfaces");
        var nets = Run("netsh.exe", "wlan show networks mode=bssid");
        var note = "";
        if (nets.Contains("location", StringComparison.OrdinalIgnoreCase) && !nets.Contains("BSSID", StringComparison.Ordinal))
            note = "Windows hides nearby Wi-Fi networks until location access is on (Settings > Privacy & security > Location). The connected network was still read.";
        if (iface.Length > 0 && !iface.Contains("SSID", StringComparison.Ordinal) && !iface.Contains("State", StringComparison.Ordinal))
            note = "Wi-Fi details are only read on English Windows.";
        return (Parse.WlanInterface(iface), Parse.WlanNetworks(nets), note);
    }

    private static readonly string[] UninstallKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    };

    private static DateTime? InstallDate(string s) =>
        DateTime.TryParseExact(s, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;

    /// <summary>Programs installed on this PC (all users, plus this user's own installs).</summary>
    public static PcInventory ThisPc()
    {
        var pc = new PcInventory { Computer = Environment.MachineName, Source = "This PC", Taken = DateTime.Now, Windows = WindowsName() };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        void From(RegistryKey root, string path)
        {
            using var k = root.OpenSubKey(path);
            if (k is null) return;
            foreach (var sub in k.GetSubKeyNames())
            {
                using var e = k.OpenSubKey(sub);
                if (e is null) continue;
                var name = (e.GetValue("DisplayName") as string ?? "").Trim();
                if (name.Length == 0 || e.GetValue("SystemComponent") is int sc && sc == 1 || e.GetValue("ParentKeyName") is not null) continue;
                var ver = (e.GetValue("DisplayVersion") as string ?? "").Trim();
                if (!seen.Add(name + "|" + ver)) continue;
                pc.Programs.Add(new SoftwareItem { Name = name, Version = ver, Publisher = (e.GetValue("Publisher") as string ?? "").Trim(), Installed = InstallDate(e.GetValue("InstallDate") as string ?? "") });
            }
        }
        foreach (var path in UninstallKeys) { try { From(Registry.LocalMachine, path); } catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { } }
        try { From(Registry.CurrentUser, UninstallKeys[0]); } catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException) { }
        pc.Programs.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return pc;
    }

    private static string WindowsName()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var product = k?.GetValue("ProductName") as string ?? "Windows";
            var build = k?.GetValue("CurrentBuildNumber") as string ?? "";
            // Windows 11 still says "Windows 10" in ProductName; the build number tells them apart.
            if (int.TryParse(build, out var b) && b >= 22000) product = product.Replace("Windows 10", "Windows 11");
            var display = k?.GetValue("DisplayVersion") as string ?? "";
            return $"{product} {display}".Trim();
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException) { return "Windows"; }
    }

    /// <summary>
    /// Programs on another Windows PC, read over the network with the signed-in account's own rights (WMI). Works on
    /// office networks where that account is an administrator on the PC. Nothing is installed or changed on it.
    /// </summary>
    public static PcInventory Remote(string host, CancellationToken ct)
    {
        var opts = new ConnectionOptions { Impersonation = ImpersonationLevel.Impersonate, Authentication = AuthenticationLevel.PacketPrivacy, Timeout = TimeSpan.FromSeconds(15) };
        var reg = new ManagementScope($@"\\{host}\root\default", opts);
        reg.Connect();
        var pc = new PcInventory { Computer = host, Ip = host, Source = "Read over the network", Taken = DateTime.Now };
        try
        {
            var cim = new ManagementScope($@"\\{host}\root\cimv2", opts);
            cim.Connect();
            using var s = new ManagementObjectSearcher(cim, new ObjectQuery("SELECT Caption, CSName FROM Win32_OperatingSystem"));
            foreach (ManagementObject o in s.Get())
            {
                pc.Windows = (o["Caption"] as string ?? "").Replace("Microsoft ", "");
                if (o["CSName"] is string n && n.Length > 0) pc.Computer = n;
            }
        }
        catch (ManagementException) { }
        using var prov = new ManagementClass(reg, new ManagementPath("StdRegProv"), null);
        const uint HKLM = 0x80000002;
        object? Call(string method, params (string Name, object Value)[] args)
        {
            ct.ThrowIfCancellationRequested();
            using var inp = prov.GetMethodParameters(method);
            foreach (var (n, v) in args) inp[n] = v;
            using var outp = prov.InvokeMethod(method, inp, null);
            return outp?["ReturnValue"] is uint rv && rv == 0 ? outp : null;
        }
        string Str(string key, string value) => Call("GetStringValue", ("hDefKey", HKLM), ("sSubKeyName", key), ("sValueName", value)) is ManagementBaseObject o ? (o["sValue"] as string ?? "").Trim() : "";
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in UninstallKeys)
        {
            if (Call("EnumKey", ("hDefKey", HKLM), ("sSubKeyName", path)) is not ManagementBaseObject keys || keys["sNames"] is not string[] names) continue;
            foreach (var sub in names)
            {
                var k = path + "\\" + sub;
                var name = Str(k, "DisplayName");
                if (name.Length == 0 || Str(k, "ParentKeyName").Length > 0) continue;
                var ver = Str(k, "DisplayVersion");
                if (!seen.Add(name + "|" + ver)) continue;
                pc.Programs.Add(new SoftwareItem { Name = name, Version = ver, Publisher = Str(k, "Publisher"), Installed = InstallDate(Str(k, "InstallDate")) });
            }
        }
        pc.Programs.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return pc;
    }
}
