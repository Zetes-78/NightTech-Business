using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using NightTech.Business.Core.Network;
using NightTech.NetworkScan.Windows;

namespace NightTech.NetworkScan;

public sealed class DeviceRow
{
    public required Device D { get; init; }
    public string Ip => D.Ip;
    public string Type => Classify.Label(D.Kind) + (D.IsGateway && D.Kind != DeviceKind.Router ? " (gateway)" : "");
    public string Label { get => D.Label; set => D.Label = value?.Trim() ?? ""; }
    public string Name => D.Name;
    public string Maker => D.RandomMac ? "private (random) address" : string.Join(" ", new[] { D.Maker, D.Model }.Where(x => x.Length > 0));
    public string Mac => D.Mac;
    public string Services => string.Join(", ", D.Services.Select(s => s.Name + (s.Detail.Length > 0 ? $" \"{s.Detail}\"" : "")));
}

public sealed class SoftwareRow
{
    public required SoftwareSummary S { get; init; }
    public string Name => S.Name;
    public int Count => S.Computers.Count;
    public string Versions => string.Join(", ", S.Versions.Take(4));
    public string Flag => S.Flag;
    public string Computers => string.Join(", ", S.Computers);
}

public sealed class FindingRow
{
    public required NetFinding F { get; init; }
    public string Mark => F.Level switch { NoteLevel.Risk => "FIX", NoteLevel.Warning => "CHECK", _ => "NOTE" };
    public Brush Color => F.Level switch { NoteLevel.Risk => Brushes.Firebrick, NoteLevel.Warning => Brushes.DarkOrange, _ => Brushes.SteelBlue };
    public string Title => F.Title;
    public string Detail => F.Detail;
}

public partial class MainWindow : Window
{
    private readonly NetworkReport _report = new();
    private CancellationTokenSource? _cts;
    private string? _lastReport;

    public MainWindow()
    {
        InitializeComponent();
        VersionText.Text = "v" + App.ToolVersion;
        TechBox.Text = Environment.UserName;
        App.Log.LineWritten += line => Dispatcher.InvokeAsync(() =>
        {
            LogList.Items.Add(line);
            if (LogList.Items.Count > 300) LogList.Items.RemoveAt(0);
            LogList.ScrollIntoView(line);
        });
        Loaded += async (_, _) =>
        {
            var adapters = LocalNet.Adapters();
            AdapterBox.ItemsSource = adapters;
            if (adapters.Count > 0) AdapterBox.SelectedIndex = 0;
            else App.Log.Warn("No network connection with a local address was found.");
            ShowNet(adapters.FirstOrDefault());
            await Job("Reading this PC's programs", async ct =>
            {
                var pc = await Task.Run(LocalNet.ThisPc, ct);
                AddPc(pc);
            });
        };
        AdapterBox.SelectionChanged += (_, _) => ShowNet(AdapterBox.SelectedItem as LocalNet.Adapter);
    }

    private void ShowNet(LocalNet.Adapter? a)
    {
        if (a is null) { NetText.Text = "Not connected to a local network."; return; }
        var (_, range) = Subnet.Hosts(a.Ip, a.Prefix, a.Gateway);
        NetText.Text = $"Connection: {a.Name}\nThis PC: {a.Ip}/{a.Prefix}\nRange to scan: {range}\nGateway (router): {a.Gateway?.ToString() ?? "none"}\n" +
                       $"DNS: {string.Join(", ", a.Dns)}{(a.Dhcp.Length > 0 ? $"\nDHCP server: {a.Dhcp}" : "")}{(a.Suffix.Length > 0 ? $"\nDomain: {a.Suffix}" : "")}";
    }

    // ---------------- Busy handling ----------------

    private bool _closeAfter;

    private async Task Job(string title, Func<CancellationToken, Task> work)
    {
        if (_cts is not null) { Warn("Wait for the current job to finish (or press Stop)."); return; }
        _cts = new CancellationTokenSource();
        BusyText.Text = title + "...";
        Busy.IsIndeterminate = true;
        StopButton.IsEnabled = true;
        ScanButton.IsEnabled = false;
        App.Log.Info(title + ".");
        try { await work(_cts.Token); }
        catch (OperationCanceledException) { App.Log.Warn(title + ": stopped."); }
        catch (Exception ex) { App.Log.Error(title + " failed.", ex); Warn(title + " didn't finish: " + ex.Message); }
        finally
        {
            _cts.Dispose(); _cts = null;
            Busy.IsIndeterminate = false; Busy.Value = 0;
            StopButton.IsEnabled = false;
            ScanButton.IsEnabled = true;
            BusyText.Text = "Ready";
            if (_closeAfter) { _closeAfter = false; _ = Dispatcher.InvokeAsync(Close); }
        }
    }

    private void Stop_Click(object sender, RoutedEventArgs e) { _cts?.Cancel(); BusyText.Text = "Stopping..."; }

    // ---------------- Scan ----------------

    private async void Scan_Click(object sender, RoutedEventArgs e)
    {
        if (PermissionCheck.IsChecked != true || PermissionBox.Text.Trim().Length == 0)
        { Warn("Only scan with the owner's permission: tick the box and type who gave it."); return; }
        if (AdapterBox.SelectedItem is not LocalNet.Adapter a) { Warn("Pick the network to scan."); return; }
        if (BusinessBox.Text.Trim().Length == 0) { Warn("Type the business name first."); return; }

        await Job("Scanning the network", async ct =>
        {
            _report.Started = DateTime.Now;
            var (hosts, range) = Subnet.Hosts(a.Ip, a.Prefix, a.Gateway);
            _report.Network = new NetworkInfo
            {
                Adapter = a.Name, LocalIp = a.Ip.ToString(), PrefixLength = a.Prefix, Gateway = a.Gateway?.ToString() ?? "", DnsServers = a.Dns,
                DhcpServer = a.Dhcp, DnsSuffix = a.Suffix, ScannedRange = range, AddressesScanned = hosts.Count,
            };
            App.Log.Info($"Scanning {range} ({hosts.Count} addresses) with permission from {PermissionBox.Text.Trim()}.");
            Busy.IsIndeterminate = false;
            var scanner = new Scanner { ReadArp = LocalNet.Arp };
            var progress = new Progress<(string Stage, double Fraction)>(p => { BusyText.Text = $"{p.Stage}... {p.Fraction:P0}"; Busy.Value = p.Fraction; });
            var devices = await Task.Run(() => scanner.ScanAsync(hosts, a.Ip, a.Gateway, progress, ct), ct);

            // Keep labels typed in an earlier scan.
            foreach (var d in devices)
                if (_report.Devices.FirstOrDefault(o => o.Ip == d.Ip && o.Mac == d.Mac) is { Label.Length: > 0 } old) d.Label = old.Label;
            if (devices.FirstOrDefault(d => d.IsThisPc) is { } me) { me.Name = Environment.MachineName; }
            _report.Devices = devices;

            BusyText.Text = "Reading the Wi-Fi...";
            var (wifi, nearby, note) = await Task.Run(LocalNet.Wifi, ct);
            _report.Network.ConnectedWifi = wifi;
            _report.Network.NearbyWifi = nearby;
            if (note.Length > 0) App.Log.Warn(note);
            WifiText.Text = wifi is null ? "This PC isn't connected by Wi-Fi." + (note.Length > 0 ? " " + note : "")
                : $"Connected to \"{wifi.Ssid}\": {wifi.Security}, channel {wifi.Channel} ({wifi.Band}), signal {wifi.SignalPercent}%. {nearby.Select(n => n.Ssid).Distinct().Count()} networks nearby. {note}";
            WifiGrid.ItemsSource = nearby.OrderByDescending(n => n.SignalPercent).ToList();
            _report.Finished = DateTime.Now;
            App.Log.Info($"Scan finished: {devices.Count} devices.");
            Refresh();
            Tabs.SelectedIndex = 1;
        });
    }

    private void Refresh()
    {
        DeviceGrid.ItemsSource = _report.Devices.Select(d => new DeviceRow { D = d }).ToList();
        var by = _report.Devices.GroupBy(d => d.Kind).OrderByDescending(g => g.Count()).Select(g => $"{g.Count()} × {Classify.Label(g.Key)}");
        SummaryText.Text = _report.Devices.Count == 0 ? "Nothing scanned yet." : $"{_report.Devices.Count} devices:\n" + string.Join("\n", by);
        SoftwareGrid.ItemsSource = _report.Software.Select(s => new SoftwareRow { S = s }).ToList();
        PcText.Text = _report.Computers.Count == 0 ? "" : "Computers read: " + string.Join(", ", _report.Computers.Select(c => $"{c.Computer} ({c.Programs.Count(p => !Software.IsNoise(p.Name))} programs, {c.Source.ToLowerInvariant()})"));
        _report.Evaluate();
        FindingList.ItemsSource = _report.Findings.Select(f => new FindingRow { F = f }).ToList();
    }

    // ---------------- Programs ----------------

    private void AddPc(PcInventory pc)
    {
        _report.Computers.RemoveAll(c => c.Computer.Equals(pc.Computer, StringComparison.OrdinalIgnoreCase));
        _report.Computers.Add(pc);
        App.Log.Info($"Programs: {pc.Computer}, {pc.Programs.Count} entries ({pc.Source}).");
        Refresh();
    }

    private async void ReadRemote_Click(object sender, RoutedEventArgs e)
    {
        var pcs = _report.Devices.Where(d => d.Kind is DeviceKind.WindowsPc or DeviceKind.Server or DeviceKind.Computer && !d.IsThisPc
                                             && IPAddress.TryParse(d.Ip, out var a) && Subnet.IsPrivate(a)).ToList();
        if (pcs.Count == 0) { Warn("Scan the network first. No other Windows PCs were found."); return; }
        var list = string.Join("\n", pcs.Take(12).Select(d => $"  {d.Ip}  {(d.Label.Length > 0 ? d.Label : d.Name)}")) + (pcs.Count > 12 ? $"\n  ...and {pcs.Count - 12} more" : "");
        if (MessageBox.Show(this, $"Read the installed programs from these {pcs.Count} PC(s) using your signed-in account ({Environment.UserDomainName}\\{Environment.UserName})?\n\n{list}\n\n" +
                "Nothing is installed or changed on them. PCs where this account isn't an administrator will be skipped: use 'Save this PC's programs' on those instead.",
                "Night Tech Network Scan", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        await Job("Reading programs over the network", async ct =>
        {
            int ok = 0;
            foreach (var d in pcs)
            {
                ct.ThrowIfCancellationRequested();
                var host = d.Ip;   // always the address the scan found, never a name a device announced
                BusyText.Text = $"Reading {host}...";
                try
                {
                    var pc = await Task.Run(() => LocalNet.Remote(host, ct), ct);
                    pc.Ip = d.Ip;
                    if (pc.Computer == d.Ip && d.Name.Length > 0) pc.Computer = d.Name;
                    AddPc(pc);
                    ok++;
                }
                catch (Exception ex) when (ex is UnauthorizedAccessException or System.Management.ManagementException or System.Runtime.InteropServices.COMException or TimeoutException)
                {
                    App.Log.Warn($"Couldn't read {host}: {ex.Message.Trim()} (needs an administrator account on that PC, with remote management allowed).");
                }
            }
            App.Log.Info($"Read {ok} of {pcs.Count} PCs.");
        });
    }

    private void Import_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Import program lists", Filter = "Program lists and Field Kit reports (*.json)|*.json", Multiselect = true };
        if (dlg.ShowDialog(this) != true) return;
        foreach (var f in dlg.FileNames)
        {
            try
            {
                if (new FileInfo(f).Length > 20 * 1024 * 1024) throw new InvalidDataException("file is too big");
                var pc = NetworkReport.InventoryFromJson(File.ReadAllText(f)) ?? throw new InvalidDataException("not a program list");
                if (pc.Computer.Length == 0) pc.Computer = Path.GetFileNameWithoutExtension(f);
                pc.Source = pc.Source.Length > 0 ? pc.Source : "Imported file";
                AddPc(pc);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException or InvalidDataException or InvalidOperationException or NotSupportedException)
            { Warn($"Couldn't import {Path.GetFileName(f)}: {ex.Message}"); }
        }
    }

    private void SaveInventory_Click(object sender, RoutedEventArgs e)
    {
        var pc = _report.Computers.FirstOrDefault(c => c.Source == "This PC") ?? LocalNet.ThisPc();
        var dlg = new SaveFileDialog { Title = "Save this PC's programs", Filter = "Program list (*.json)|*.json", FileName = $"programs-{Environment.MachineName}.json", InitialDirectory = App.ReportsFolder };
        Directory.CreateDirectory(App.ReportsFolder);
        if (dlg.ShowDialog(this) != true) return;
        File.WriteAllText(dlg.FileName, NetworkReport.InventoryJson(pc));
        App.Log.Info("Saved this PC's programs: " + dlg.FileName);
        MessageBox.Show(this, "Saved. Import this file on the PC that's making the network report.", "Night Tech Network Scan");
    }

    // ---------------- Report ----------------

    private void Save_Click(object sender, RoutedEventArgs e)
    {
        _report.ToolVersion = App.ToolVersion;
        _report.Business = BusinessBox.Text.Trim();
        _report.Site = SiteBox.Text.Trim();
        _report.Ticket = TicketBox.Text.Trim();
        _report.Technician = TechBox.Text.Trim();
        _report.PermissionFrom = PermissionBox.Text.Trim();
        _report.Notes = NotesBox.Text.Trim();
        if (_report.Started == default) { _report.Started = DateTime.Now; }
        if (_report.Finished == default) _report.Finished = DateTime.Now;
        _report.Evaluate();
        try
        {
            var s = _report.Save(App.ReportsFolder);
            _lastReport = s.Html;
            SavedText.Text = $"Saved in {App.ReportsFolder}: the report (.html) for the owner, spreadsheets of devices and programs (.csv), and {Path.GetFileName(s.Json)} for the Hub ticket.";
            App.Log.Info("Report saved: " + s.Html);
            Process.Start(new ProcessStartInfo(s.Html) { UseShellExecute = true });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { Warn("Couldn't save the report: " + ex.Message); }
    }

    private void OpenReports_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(App.ReportsFolder);
        Process.Start(new ProcessStartInfo("explorer.exe", _lastReport is null ? $"\"{App.ReportsFolder}\"" : $"/select,\"{_lastReport}\"") { UseShellExecute = true });
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_cts is null) return;
        e.Cancel = true;
        if (_closeAfter) return;
        _closeAfter = true;
        _cts.Cancel();
        BusyText.Text = "Stopping, then closing...";
    }

    private void Warn(string m) => MessageBox.Show(this, m, "Night Tech Network Scan", MessageBoxButton.OK, MessageBoxImage.Warning);
}
