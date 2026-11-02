using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using NightTech.Business.Core.Security;
using NightTech.SecurityCheckup.Windows;

namespace NightTech.SecurityCheckup;

public partial class MainWindow : Window
{
    private readonly List<QuestionView> _questions = SecurityRules.Questions.Select(q => new QuestionView(q)).ToList();
    private SecurityReportWriter.Saved? _saved;

    public MainWindow()
    {
        InitializeComponent();
        VersionText.Text = $"Version {App.ToolVersion}";
        ModeText.Text = App.Portable ? "Running from the USB kit" : "Installed on this computer";
        AdminCard.Visibility = SecurityCollector.IsAdministrator ? Visibility.Collapsed : Visibility.Visible;
        QuestionList.ItemsSource = _questions;
        LoadSession();
        Closing += (_, _) => SaveSession();
        App.Log.LineWritten += line => Dispatcher.InvokeAsync(() =>
        {
            LogList.Items.Add(line);
            if (LogList.Items.Count > 300) LogList.Items.RemoveAt(0);
            LogList.ScrollIntoView(line);
        });
        App.Log.Info("Reports are saved in: " + App.ReportsFolder);
    }

    // ---------------- Carrying the visit over (next computer, restart as administrator) ----------------

    private sealed class Session
    {
        public DateTime Saved { get; set; }
        public string Business { get; set; } = "";
        public string Ticket { get; set; } = "";
        public string Technician { get; set; } = "";
        public Dictionary<string, Answer> Answers { get; set; } = new();
    }

    private static string SessionPath => Path.Combine(App.ReportsFolder, "current-visit.json");

    /// <summary>Saves the business details and the owner's answers next to the reports, so they carry over to the next computer today.</summary>
    private void SaveSession()
    {
        try
        {
            Directory.CreateDirectory(App.ReportsFolder);
            var session = new Session
            {
                Saved = DateTime.Now, Business = BusinessBox.Text.Trim(), Ticket = TicketBox.Text.Trim(), Technician = TechBox.Text.Trim(),
                Answers = _questions.ToDictionary(q => q.Id, q => q.Answer),
            };
            File.WriteAllText(SessionPath, System.Text.Json.JsonSerializer.Serialize(session, SecurityReportWriter.Json));
        }
        catch (Exception ex) { App.Log.Warn("Couldn't save this visit's answers: " + ex.Message); }
    }

    private void LoadSession()
    {
        try
        {
            if (!File.Exists(SessionPath)) return;
            var session = System.Text.Json.JsonSerializer.Deserialize<Session>(File.ReadAllText(SessionPath), SecurityReportWriter.Json);
            if (session is null || (DateTime.Now - session.Saved).TotalHours > 18) return; // a different visit
            BusinessBox.Text = session.Business;
            TicketBox.Text = session.Ticket;
            TechBox.Text = session.Technician;
            foreach (var q in _questions)
                if (session.Answers.TryGetValue(q.Id, out var a)) q.Answer = a;
            QuestionList.ItemsSource = null;
            QuestionList.ItemsSource = _questions;
            App.Log.Info($"Carried over this visit's details for {(session.Business.Length > 0 ? session.Business : "the business")}.");
        }
        catch (Exception ex) { App.Log.Warn("Couldn't load the last visit's answers: " + ex.Message); }
    }

    private void NewVisit_Click(object sender, RoutedEventArgs e)
    {
        BusinessBox.Text = TicketBox.Text = "";
        foreach (var q in _questions) q.Answer = Answer.NotAsked;
        QuestionList.ItemsSource = null;
        QuestionList.ItemsSource = _questions;
        try { File.Delete(SessionPath); } catch { }
        App.Log.Info("Started a new visit.");
    }

    private async void Run_Click(object sender, RoutedEventArgs e)
    {
        SaveSession();
        RunButton.IsEnabled = false;
        OpenReportButton.IsEnabled = false;
        Busy.Visibility = Visibility.Visible;
        SummaryText.Text = "Checking...";
        ResultList.ItemsSource = null;
        var progress = new Progress<string>(m => { StatusText.Text = m; App.Log.Info(m); });
        try
        {
            var started = DateTime.Now;
            var facts = await Task.Run(() => SecurityCollector.Collect(progress));
            var report = new SecurityReport
            {
                ToolVersion = App.ToolVersion, Business = BusinessBox.Text.Trim(), Ticket = TicketBox.Text.Trim(),
                Technician = TechBox.Text.Trim(), Checked = started, Facts = facts,
                Answers = _questions.ToDictionary(q => q.Id, q => q.Answer),
            };
            report.Results = SecurityRules.Evaluate(facts, report.Answers, DateTime.Now);
            SummaryText.Text = SecurityReportWriter.Summary(report.Results);
            ResultList.ItemsSource = report.Results
                .OrderBy(r => r.Status switch { CheckStatus.Fail => 0, CheckStatus.Warn => 1, CheckStatus.NotChecked => 2, CheckStatus.Info => 3, _ => 4 })
                .ThenBy(r => r.Priority).Select(r => new ResultView(r)).ToList();
            FullText.Text = SecurityReportWriter.ToText(report);
            Tabs.SelectedIndex = 0;
            try
            {
                _saved = SecurityReportWriter.Save(report, App.ReportsFolder);
                SavedText.Text = "Saved " + Path.GetFileNameWithoutExtension(_saved.Html) + " (.html for the owner, .txt for the Hub ticket, .json to combine).";
                App.Log.Info("Report saved: " + _saved.Html);
                OpenReportButton.IsEnabled = true;
            }
            catch (Exception ex)
            {
                SavedText.Text = "The report couldn't be saved: " + ex.Message;
                App.Log.Error("Saving failed.", ex);
            }
            StatusText.Text = $"Finished in {(int)Math.Round((DateTime.Now - started).TotalSeconds)} s. Check the next computer, or make the business summary.";
        }
        catch (Exception ex)
        {
            App.Log.Error("The checkup stopped.", ex);
            StatusText.Text = "The checkup stopped: " + ex.Message;
        }
        finally
        {
            Busy.Visibility = Visibility.Collapsed;
            RunButton.IsEnabled = true;
            RunButton.Content = "Run the checkup again";
        }
    }

    private void Combine_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(App.ReportsFolder);
        var pick = new OpenFileDialog
        {
            Title = "Pick the .json report from each computer at this business",
            Filter = "Security Checkup reports (security-*.json)|security-*.json",
            Multiselect = true,
            InitialDirectory = App.ReportsFolder,
        };
        if (pick.ShowDialog(this) != true) return;
        SaveSession();
        var reports = new List<SecurityReport>();
        foreach (var file in pick.FileNames)
        {
            try
            {
                if (SecurityReportWriter.Load(file) is { } r) reports.Add(r);
                else App.Log.Warn("Not a Security Checkup report: " + file);
            }
            catch (Exception ex) { App.Log.Error("Couldn't read " + file, ex); }
        }
        if (reports.Count == 0) { MessageBox.Show("None of those files is a Security Checkup report.", Title); return; }

        // One report per computer: if a computer was checked twice, use the latest.
        reports = reports.GroupBy(r => r.Facts.ComputerName, StringComparer.OrdinalIgnoreCase).Select(g => g.OrderBy(r => r.Checked).Last()).ToList();
        var business = BusinessBox.Text.Trim().Length > 0 ? BusinessBox.Text.Trim() : reports.Select(r => r.Business).FirstOrDefault(b => b.Length > 0) ?? "the business";
        var html = SecurityReportWriter.ToBusinessSummaryHtml(reports, business);
        var path = Path.Combine(App.ReportsFolder, NightTech.Business.Core.Format.SafeFileName($"security-summary-{business}-{DateTime.Now:yyyyMMdd-HHmmss}", 120) + ".html");
        File.WriteAllText(path, html, new System.Text.UTF8Encoding(true));
        App.Log.Info($"Business summary for {reports.Count} computer(s) saved: {path}");
        Open(path);
    }

    private void OpenReport_Click(object sender, RoutedEventArgs e)
    {
        if (_saved is not null) Open(_saved.Html);
    }

    private void OpenFolder_Click(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(App.ReportsFolder);
        Open(App.ReportsFolder);
    }

    private void Elevate_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (Environment.ProcessPath is not { } exe) return;
            SaveSession(); // the administrator copy picks these up
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" });
            Application.Current.Shutdown();
        }
        catch (Win32Exception) { /* the administrator prompt was declined */ }
    }

    private static void Open(string path)
    {
        try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); }
        catch (Exception ex) { App.Log.Error("Couldn't open " + path, ex); }
    }
}

/// <summary>One owner question with a Yes / No / Not sure picker.</summary>
public sealed class QuestionView
{
    private static readonly string[] Options = { "Not asked", "Yes", "No", "Not sure" };
    public QuestionView(OwnerQuestion q) { Id = q.Id; Question = q.Question; }
    public string Id { get; }
    public string Question { get; }
    public string[] Choices => Options;
    public string Choice { get; set; } = "Not asked";
    public Answer Answer
    {
        get => Choice switch { "Yes" => Answer.Yes, "No" => Answer.No, "Not sure" => Answer.NotSure, _ => Answer.NotAsked };
        set => Choice = value switch { Answer.Yes => "Yes", Answer.No => "No", Answer.NotSure => "Not sure", _ => "Not asked" };
    }
}

public sealed class ResultView
{
    public ResultView(CheckResult r)
    {
        Label = SecurityReportWriter.Label(r.Status);
        Area = r.Area; Title = r.Title; Found = r.Found; Fix = r.Fix;
        var (accent, soft) = r.Status switch
        {
            CheckStatus.Fail => ("#C53030", "#FFF5F5"),
            CheckStatus.Warn => ("#C2410C", "#FFF7ED"),
            CheckStatus.Pass => ("#2F855A", "#F0FFF4"),
            CheckStatus.Info => ("#2B6CB0", "#EBF8FF"),
            _ => ("#718096", "#F7FAFC"),
        };
        Accent = MakeBrush(accent); Soft = MakeBrush(soft);
    }

    public string Label { get; }
    public string Area { get; }
    public string Title { get; }
    public string Found { get; }
    public string Fix { get; }
    public Visibility FixVisibility => Fix.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
    public Brush Accent { get; }
    public Brush Soft { get; }

    private static Brush MakeBrush(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }
}
