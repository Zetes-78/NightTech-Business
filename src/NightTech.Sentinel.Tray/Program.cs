using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using NightTech.Business.Core;

namespace NightTech.Sentinel.Tray;

/// <summary>
/// The Sentinel icon. Runs as the signed-in person (started at sign-in). Shows whether the PC is being looked after,
/// lets the person ask Night Tech for help, and is where Sentinel asks permission before a technician connects.
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        using var single = new Mutex(true, $"Local\\NightTechSentinelTray", out bool first);
        if (!first) return;
        ApplicationConfiguration.Initialize();
        Application.Run(new TrayContext());
    }
}

internal sealed class Msg
{
    public string Type { get; set; } = "";
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Text { get; set; } = "";
    public bool Allow { get; set; }
    public bool Ok { get; set; }
    public bool Active { get; set; }
}

internal sealed class TrayContext : ApplicationContext
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _status;
    private readonly Icon _normal = Load("sentinel.ico"), _alert = Load("sentinel-alert.ico");
    private readonly SynchronizationContext _ui;
    private StreamWriter? _writer;
    private readonly CancellationTokenSource _stop = new();

    public TrayContext()
    {
        _ui = SynchronizationContext.Current ?? new WindowsFormsSynchronizationContext();
        _status = new ToolStripMenuItem("Connecting to Night Tech Sentinel...") { Enabled = false };
        var menu = new ContextMenuStrip();
        menu.Items.Add(_status);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Request help from Night Tech...", null, (_, _) => RequestHelp());
        menu.Items.Add($"Call {Brand.Phone}", null, (_, _) => Open(Brand.PhoneLink));
        menu.Items.Add($"Text {Brand.TextPhone}", null, (_, _) => Open("sms:+18644972701"));
        menu.Items.Add($"Email {Brand.Email}", null, (_, _) => Open("mailto:" + Brand.Email));
        menu.Items.Add("Visit nighttech.solutions", null, (_, _) => Open(Brand.Website + "/"));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("About Night Tech Sentinel", null, (_, _) => About());
        _icon = new NotifyIcon { Icon = _normal, Text = "Night Tech Sentinel", ContextMenuStrip = menu, Visible = true };
        _icon.DoubleClick += (_, _) => About();
        _ = Task.Run(() => Connect(_stop.Token));
    }

    private static Icon Load(string name)
    {
        using var s = typeof(TrayContext).Assembly.GetManifestResourceStream(name);
        return s is null ? SystemIcons.Shield : new Icon(s);
    }

    private static void Open(string url)
    {
        try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true })?.Dispose(); }
        catch (System.ComponentModel.Win32Exception) { }
    }

    private void OnUi(Action a) => _ui.Post(_ => a(), null);

    private async Task Connect(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeClientStream(".", "NightTechSentinel", PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(10000, ct);
                using var reader = new StreamReader(pipe, new UTF8Encoding(false));
                _writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };
                await Send(new Msg { Type = "hello" });
                while (!ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(ct);
                    if (line is null) break;
                    var m = JsonSerializer.Deserialize<Msg>(line, Json);
                    if (m is not null) OnUi(() => Handle(m));
                }
            }
            catch (Exception e) when (e is IOException or TimeoutException or JsonException or UnauthorizedAccessException) { }
            catch (OperationCanceledException) { return; }
            _writer = null;
            OnUi(() => SetStatus("Sentinel service isn't running", ok: false));
            try { await Task.Delay(5000, ct); } catch (OperationCanceledException) { return; }
        }
    }

    private async Task Send(Msg m)
    {
        var w = _writer;
        if (w is null) return;
        try { await w.WriteLineAsync(JsonSerializer.Serialize(m, Json)); } catch (IOException) { }
    }

    private void SetStatus(string text, bool ok)
    {
        _status.Text = text.Length > 60 ? text[..60] + "..." : text;
        _icon.Icon = ok ? _normal : _alert;
        _icon.Text = ("Night Tech Sentinel: " + text) is var t && t.Length > 63 ? t[..63] : t;
    }

    private void Handle(Msg m)
    {
        switch (m.Type)
        {
            case "status":
                SetStatus(m.Text, m.Ok);
                break;
            case "tell":
                using (var f = new MessageForm(m.Title, m.Text, ask: false)) f.ShowDialog();
                break;
            case "ask":
                bool allow;
                using (var f = new MessageForm(m.Title, m.Text, ask: true)) allow = f.ShowDialog() == DialogResult.Yes;
                _ = Send(new Msg { Type = "answer", Id = m.Id, Allow = allow });
                break;
            case "session":
                if (m.Active) _icon.ShowBalloonTip(8000, "Night Tech is connected", m.Text, ToolTipIcon.Info);
                _icon.Icon = m.Active ? _alert : _normal;
                break;
        }
    }

    private void RequestHelp()
    {
        using var f = new HelpForm();
        if (f.ShowDialog() != DialogResult.OK) return;
        if (_writer is null)
        {
            MessageBox.Show($"Sentinel can't reach Night Tech right now. Please call {Brand.Phone} or text {Brand.TextPhone}.", "Request help", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        _ = Send(new Msg { Type = "help", Text = f.Message });
        _icon.ShowBalloonTip(6000, "Help requested", $"Night Tech has your message and will be in touch. For anything urgent, call {Brand.Phone}.", ToolTipIcon.Info);
    }

    private static void About()
    {
        var v = typeof(TrayContext).Assembly.GetName().Version?.ToString(3) ?? "";
        MessageBox.Show(
            $"Night Tech Sentinel {v}\n\nThis PC is looked after by {Brand.Company}. Sentinel checks its health, security and backups, and tells Night Tech when something needs attention.\n\n"
            + "A technician can only connect to this PC when you allow it (unless your business chose otherwise), and a banner shows whenever someone is connected.\n\n"
            + $"Call {Brand.Phone}  ·  Text {Brand.TextPhone}\n{Brand.Email}  ·  nighttech.solutions\n{Brand.Hours}\n\n{Brand.Verse}",
            "About Night Tech Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _stop.Cancel();
            _icon.Visible = false;
            _icon.Dispose();
        }
        base.Dispose(disposing);
    }
}

/// <summary>A message or a permission question from Night Tech. Questions say no by themselves after 3 minutes.</summary>
internal sealed class MessageForm : Form
{
    private int _seconds = 180;

    public MessageForm(string title, string text, bool ask)
    {
        Text = title.Length > 0 ? title : "Night Tech Solutions";
        TopMost = true;
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        Font = new Font("Segoe UI", 10f);
        Width = 520;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(18), AutoSize = true, ColumnCount = 1 };
        layout.Controls.Add(new Label { Text = text, AutoSize = true, MaximumSize = new Size(460, 0), Margin = new Padding(0, 0, 0, 14) });
        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill, AutoSize = true };
        if (ask)
        {
            var no = new Button { Text = "Don't allow", DialogResult = DialogResult.No, AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
            var yes = new Button { Text = "Allow", DialogResult = DialogResult.Yes, AutoSize = true, Padding = new Padding(8, 2, 8, 2) };
            buttons.Controls.Add(no);
            buttons.Controls.Add(yes);
            CancelButton = no;
            AcceptButton = no;   // Enter alone never says yes
            var countdown = new Label { AutoSize = true, ForeColor = Color.DimGray, Margin = new Padding(0, 8, 12, 0) };
            buttons.Controls.Add(countdown);
            var timer = new System.Windows.Forms.Timer { Interval = 1000 };
            timer.Tick += (_, _) =>
            {
                _seconds--;
                countdown.Text = $"Says no in {_seconds / 60}:{_seconds % 60:00}";
                if (_seconds <= 0) { DialogResult = DialogResult.No; Close(); }
            };
            timer.Start();
            FormClosed += (_, _) => timer.Dispose();
        }
        else
        {
            var ok = new Button { Text = "OK", DialogResult = DialogResult.OK, AutoSize = true };
            buttons.Controls.Add(ok);
            AcceptButton = CancelButton = ok;
        }
        layout.Controls.Add(buttons);
        Controls.Add(layout);
    }
}

/// <summary>"Request help": a short note to Night Tech, sent with the PC's next check-in.</summary>
internal sealed class HelpForm : Form
{
    private readonly TextBox _box;
    public string Message => _box.Text.Trim();

    public HelpForm()
    {
        Text = "Request help from Night Tech";
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        Font = new Font("Segoe UI", 10f);
        ClientSize = new Size(480, 270);
        var label = new Label { Text = "What's going on? Night Tech will see this along with your PC's health details.", Location = new Point(16, 14), Size = new Size(448, 40) };
        _box = new TextBox { Multiline = true, Location = new Point(16, 58), Size = new Size(448, 140), MaxLength = 1000, ScrollBars = ScrollBars.Vertical };
        var urgent = new Label { Text = $"Urgent? Call {Brand.Phone}.", Location = new Point(16, 210), Size = new Size(250, 24), ForeColor = Color.DimGray };
        var send = new Button { Text = "Send", DialogResult = DialogResult.OK, Location = new Point(290, 220), Size = new Size(84, 32) };
        var cancel = new Button { Text = "Cancel", DialogResult = DialogResult.Cancel, Location = new Point(380, 220), Size = new Size(84, 32) };
        send.Click += (_, e) => { if (Message.Length == 0) DialogResult = DialogResult.None; };
        Controls.AddRange(new Control[] { label, _box, urgent, send, cancel });
        AcceptButton = send;
        CancelButton = cancel;
    }
}
