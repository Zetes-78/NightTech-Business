using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using NightTech.AiSetup.Windows;
using NightTech.Business.Core.PrivateAi;

namespace NightTech.AiSetup;

public sealed class ModelChoice
{
    public required AiModel Model { get; init; }
    public required string Label { get; init; }
}

public sealed class StepRow : INotifyPropertyChanged
{
    private string _mark = "  ", _detail = "";
    private Brush _color = Brushes.Gray;
    public string Name { get; init; } = "";
    public string Mark { get => _mark; set { _mark = value; On(); } }
    public Brush MarkColor { get => _color; set { _color = value; On(); } }
    public string Detail { get => _detail; set { _detail = value; On(); } }
    public event PropertyChangedEventHandler? PropertyChanged;
    private void On([CallerMemberName] string? p = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));
}

public partial class MainWindow : Window
{
    private HardwareProfile? _hw;
    private Recommendation? _rec;
    private CancellationTokenSource? _cts;
    private string? _reportText;
    private int _port = 8080;
    private readonly ObservableCollection<StepRow> _rows = new();

    public MainWindow()
    {
        InitializeComponent();
        VersionText.Text = "v" + App.ToolVersion;
        App.Log.LineWritten += line => Dispatcher.InvokeAsync(() =>
        {
            LogList.Items.Add(line);
            if (LogList.Items.Count > 300) LogList.Items.RemoveAt(0);
            LogList.ScrollIntoView(LogList.Items[^1]);
        });
        foreach (var n in Installer.StepNames) _rows.Add(new StepRow { Name = n });
        StepList.ItemsSource = _rows;
        TechBox.Text = Environment.UserName;
        Loaded += async (_, _) => await CheckAsync();
    }

    // ---------------- 1. Hardware ----------------

    private async void Check_Click(object sender, RoutedEventArgs e) => await CheckAsync();

    private async Task CheckAsync()
    {
        CheckButton.IsEnabled = false;
        RecommendText.Text = "Checking this computer...";
        try
        {
            var drive = Path.GetPathRoot(Paths.ModelsDir) ?? "C:\\";
            _hw = await Task.Run(() => Hardware.Read(drive));
            CpuText.Text = $"{_hw.Cpu} ({_hw.CpuCores} cores)";
            RamText.Text = $"{_hw.RamGb:0.#} GB";
            GpuText.Text = _hw.Gpus.Count == 0 ? "None found" : string.Join("\n", _hw.Gpus.Select(g => $"{g.Name}{(g.MemoryGb > 0 ? $" ({g.MemoryGb:0.#} GB)" : "")}{(g.Usable ? "" : " (not used for AI)")}"));
            DiskText.Text = $"{_hw.FreeDiskGb:0} GB on {drive}";
            WinText.Text = _hw.Windows;
            App.Log.Info($"Hardware: {_hw.Cpu}, {_hw.RamGb} GB, GPUs: {string.Join("; ", _hw.Gpus.Select(g => g.Name + " " + g.MemoryGb + " GB"))}, {_hw.FreeDiskGb} GB free.");
            Recommend();
        }
        catch (Exception ex)
        {
            App.Log.Error("Hardware check failed.", ex);
            RecommendText.Text = "Couldn't check this computer: " + ex.Message;
        }
        finally { CheckButton.IsEnabled = true; }
    }

    private void Recommend()
    {
        if (_hw is null) return;
        _rec = Recommender.For(_hw, UsOnlyBox.IsChecked == true);
        RecommendText.Text = _rec.Summary;
        NotesText.Text = string.Join("\n", _rec.Notes);
        var budget = _rec.Mode == RunMode.GraphicsCard ? _hw.BestGpu!.MemoryGb : Math.Min(_hw.RamGb - 6, 12);
        var choices = ModelCatalog.ChatModels
            .Where(m => UsOnlyBox.IsChecked != true || m.UsCompany)
            .Select(m => new ModelChoice
            {
                Model = m,
                Label = $"{m.Name} · {m.MadeBy} · {m.DownloadGb:0.#} GB download" +
                        (m == _rec.Pick ? "  (recommended)" : ModelCatalog.RunGb(m) > budget ? "  (too big for this computer)" : ""),
            }).ToList();
        ModelBox.ItemsSource = choices;
        ModelBox.SelectedItem = choices.FirstOrDefault(c => c.Model == _rec.Pick) ?? choices.FirstOrDefault();
    }

    private void UsOnly_Click(object sender, RoutedEventArgs e) => Recommend();

    private void ModelBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ModelBox.SelectedItem is ModelChoice c) ModelInfo.Text = $"{c.Model.BestFor}. Needs about {ModelCatalog.RunGb(c.Model):0} GB of {(_rec?.Mode == RunMode.GraphicsCard ? "graphics memory" : "memory")}.";
    }

    // ---------------- 4. Install ----------------

    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        if (ModelBox.SelectedItem is not ModelChoice choice) { Warn("Pick an AI model first."); return; }
        var admin = AdminBox.Text.Trim();
        if (UserStore.CheckName(admin) is { } nameProblem) { Warn("Admin user name: " + nameProblem); return; }
        var existing = new UserStore(Path.Combine(Paths.DataDir, "users.json")).Find(admin) is not null;
        if (!existing)
        {
            if (UserStore.CheckPassword(PasswordBox1.Password) is { } pwProblem) { Warn(pwProblem); return; }
            if (PasswordBox1.Password != PasswordBox2.Password) { Warn("The two passwords don't match."); return; }
        }
        if (!int.TryParse(PortBox.Text.Trim(), out var port) || port is < 1024 or > 65535) { Warn("Use a port between 1024 and 65535 (8080 is normal)."); return; }
        if (_rec?.Mode == RunMode.NotSuitable &&
            MessageBox.Show(this, "This computer is below the minimum for a private AI. It will be very slow.\n\nInstall anyway (for a demo)?", "Night Tech AI Setup",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        if (_hw is not null && choice.Model.DownloadGb + 5 > _hw.FreeDiskGb) { Warn($"Not enough disk space: {choice.Model.Name} needs about {choice.Model.DownloadGb + 5:0} GB free."); return; }

        var report = new AiSetupReport
        {
            ToolVersion = App.ToolVersion,
            Ticket = TicketBox.Text.Trim(),
            Technician = TechBox.Text.Trim(),
            Customer = CustomerBox.Text.Trim(),
            Started = DateTime.Now,
            Hardware = _hw,
            RunsOn = _rec?.Mode switch { RunMode.GraphicsCard => $"Graphics card ({_hw?.BestGpu?.Name})", RunMode.Processor => "Processor (no suitable graphics card)", _ => "Below minimum" },
            Model = choice.Model.Tag,
            ModelName = $"{choice.Model.Name} by {choice.Model.MadeBy}",
            SearchModel = ModelCatalog.DocumentSearch.Name,
        };
        var options = new SetupOptions(CustomerBox.Text.Trim(), TicketBox.Text.Trim(), TechBox.Text.Trim(), admin,
            string.IsNullOrWhiteSpace(AdminNameBox.Text) ? admin : AdminNameBox.Text.Trim(), PasswordBox1.Password, choice.Model.Tag, port);

        SetRunning(true);
        DoneCard.Visibility = Visibility.Collapsed;
        _cts = new CancellationTokenSource();
        var installer = new Installer(options, report,
            new Progress<StepUpdate>(ShowStep),
            new Progress<Transfer>(t =>
            {
                TransferText.Text = t.What;
                Bar.IsIndeterminate = t.Percent < 0;
                if (t.Percent >= 0) Bar.Value = t.Percent;
                TransferDetail.Text = t.Detail;
            }));
        App.Log.Info($"Installing Private AI: model {choice.Model.Tag}, port {port}, admin {admin}.");
        bool ok = false;
        try
        {
            ok = await Task.Run(() => installer.RunAsync(_cts.Token));
        }
        catch (OperationCanceledException) { App.Log.Warn("Setup stopped by the technician."); }
        finally
        {
            PasswordBox1.Clear();
            PasswordBox2.Clear();
            Bar.IsIndeterminate = false;
            report.Finished = DateTime.Now;
            SetRunning(false);
            _cts.Dispose();
            _cts = null;
        }

        try
        {
            var (_, text) = report.Save(App.ReportsFolder);
            _reportText = text;
            App.Log.Info("Setup report saved: " + text);
        }
        catch (Exception ex) { App.Log.Error("Couldn't save the setup report.", ex); }

        _port = installer.Port;
        if (ok)
        {
            TransferText.Text = "Done.";
            TransferDetail.Text = "";
            Bar.Value = 100;
            AddressesText.Text = string.Join("\n", new[] { $"http://localhost:{_port}" }.Concat(report.Addresses));
            DoneCard.Visibility = Visibility.Visible;
            var warn = report.Steps.Where(s => s.Result == StepResult.Warning).Select(s => "\n\nNote: " + s.Detail);
            MessageBox.Show(this, "Private AI is installed and running." + string.Concat(warn) + "\n\nSign in with the administrator account, then add the other people under Settings and users.",
                "Night Tech AI Setup", MessageBoxButton.OK, warn.Any() ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }
        else
        {
            TransferText.Text = "Setup didn't finish.";
            var failed = report.Steps.FirstOrDefault(s => s.Result == StepResult.Failed);
            if (failed is not null) Warn($"{failed.Name} didn't finish:\n\n{failed.Detail}\n\nFix that and press Install again. Steps already done are skipped.");
        }
    }

    private void ShowStep(StepUpdate u)
    {
        var row = _rows[u.Index];
        row.Detail = u.Detail;
        (row.Mark, row.MarkColor) = u.Result switch
        {
            StepResult.Running => ("..", (Brush)FindResource("Navy")),
            StepResult.Done => ("OK", Brushes.ForestGreen),
            StepResult.Warning => ("!!", (Brush)FindResource("Orange")),
            StepResult.Failed => ("XX", (Brush)FindResource("Danger")),
            StepResult.Skipped => ("--", Brushes.Gray),
            _ => ("  ", Brushes.Gray),
        };
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        StopButton.IsEnabled = false;
        TransferText.Text = "Stopping...";
        _cts?.Cancel();
    }

    private void SetRunning(bool running)
    {
        InstallButton.IsEnabled = !running;
        StopButton.IsEnabled = running;
        RemoveButton.IsEnabled = !running;
        CheckButton.IsEnabled = !running;
        ModelBox.IsEnabled = UsOnlyBox.IsEnabled = !running;
        if (running) foreach (var r in _rows) { r.Mark = "  "; r.Detail = ""; r.MarkColor = Brushes.Gray; }
    }

    // ---------------- Done / remove ----------------

    private void Open_Click(object sender, RoutedEventArgs e) =>
        Process.Start(new ProcessStartInfo($"http://localhost:{_port}") { UseShellExecute = true });

    private void OpenReport_Click(object sender, RoutedEventArgs e)
    {
        if (_reportText is not null && File.Exists(_reportText))
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{_reportText}\"") { UseShellExecute = true });
    }

    private async void Remove_Click(object sender, RoutedEventArgs e)
    {
        var data = DeleteDataBox.IsChecked == true;
        if (MessageBox.Show(this, "Remove Private AI from this computer?" + (data ? "\n\nAll accounts, chats and documents will be DELETED. This can't be undone." : ""),
                "Night Tech AI Setup", MessageBoxButton.YesNo, data ? MessageBoxImage.Warning : MessageBoxImage.Question) != MessageBoxResult.Yes) return;
        RemoveButton.IsEnabled = false;
        var result = await Task.Run(() => Installer.Remove(data));
        App.Log.Info("Removed Private AI. " + result.Replace("\n", " "));
        RemoveButton.IsEnabled = true;
        DoneCard.Visibility = Visibility.Collapsed;
        MessageBox.Show(this, result, "Night Tech AI Setup", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (_cts is null) return;
        if (MessageBox.Show(this, "Setup is running. Stop and close? You can run it again later; finished steps are skipped.",
                "Night Tech AI Setup", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) { e.Cancel = true; return; }
        _cts.Cancel();
    }

    private void Warn(string message) =>
        MessageBox.Show(this, message, "Night Tech AI Setup", MessageBoxButton.OK, MessageBoxImage.Warning);
}
