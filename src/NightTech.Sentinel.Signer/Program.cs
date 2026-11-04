using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NightTech.Business.Core;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Signer;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        using var single = new Mutex(true, "Local\\NightTechSentinelSigner", out bool first);
        if (!first) return;
        ApplicationConfiguration.Initialize();
        Application.Run(new SignerForm());
    }
}

/// <summary>The Signer's settings: the server, the tech's name, and teammates' keys checked by hand.</summary>
internal sealed class SignerConfig
{
    public string Server { get; set; } = "";
    public string Tech { get; set; } = "";
    /// <summary>Other technicians' keys, added by pasting them here (never taken from the server).</summary>
    public List<TrustedKey> TeamKeys { get; set; } = new();

    private static string Folder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Night Tech Solutions", "Sentinel Signer");
    private static string File_ => Path.Combine(Folder, "signer.json");
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static SignerConfig Load()
    {
        try { return File.Exists(File_) ? JsonSerializer.Deserialize<SignerConfig>(File.ReadAllText(File_), Json) ?? new() : new(); }
        catch (Exception e) when (e is JsonException or IOException) { return new(); }
    }

    public void Save()
    {
        Directory.CreateDirectory(Folder);
        File.WriteAllText(File_, JsonSerializer.Serialize(this, Json));
    }
}

/// <summary>
/// The tech's key, made by Windows and kept in the PC's TPM security chip when it has one. It can't be exported, so it
/// can't be copied off this PC.
/// </summary>
internal static class SignerKey
{
    private const string Name = "NightTechSentinelSigner";

    public static (ECDsa Key, string Where) OpenOrCreate()
    {
        foreach (var (provider, where) in new[] { (CngProvider.MicrosoftPlatformCryptoProvider, "the TPM security chip"), (CngProvider.MicrosoftSoftwareKeyStorageProvider, "Windows' key store for your account") })
        {
            try
            {
                CngKey key = CngKey.Exists(Name, provider)
                    ? CngKey.Open(Name, provider)
                    : CngKey.Create(CngAlgorithm.ECDsaP256, Name, new CngKeyCreationParameters { Provider = provider, ExportPolicy = CngExportPolicies.None, KeyUsage = CngKeyUsages.Signing });
                return (new ECDsaCng(key), where);
            }
            catch (CryptographicException) { /* no TPM, or it's busy: try the next */ }
        }
        throw new InvalidOperationException("Windows couldn't make a signing key on this PC.");
    }
}

internal sealed class SignerForm : Form
{
    private readonly SignerConfig _cfg = SignerConfig.Load();
    private readonly ECDsa _key;
    private readonly string _publicKey, _keyId, _where;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() } };

    private readonly ListBox _pending = new() { Dock = DockStyle.Left, Width = 300, IntegralHeight = false };
    private readonly TextBox _detail = new() { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Font = new Font("Consolas", 10f), WordWrap = true };
    private readonly Button _approve = new() { Text = "Approve", Width = 120, Height = 34, Enabled = false };
    private readonly Button _reject = new() { Text = "Turn down", Width = 120, Height = 34, Enabled = false };
    private readonly Label _status = new() { Dock = DockStyle.Bottom, Height = 24, ForeColor = Color.DimGray, Padding = new Padding(8, 4, 0, 0) };
    private readonly System.Windows.Forms.Timer _poll = new() { Interval = 3000 };
    private List<PendingAction> _items = new();
    private readonly HashSet<string> _handled = new();
    private bool _busy;

    public SignerForm()
    {
        (_key, _where) = SignerKey.OpenOrCreate();
        _publicKey = SentinelCrypto.PublicKey(_key);
        _keyId = SentinelCrypto.KeyId(_publicKey);
        Text = "Night Tech Sentinel Signer";
        Width = 980; Height = 640;
        Font = new Font("Segoe UI", 10f);
        StartPosition = FormStartPosition.CenterScreen;
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch (ArgumentException) { }

        var tabs = new TabControl { Dock = DockStyle.Fill };
        tabs.TabPages.Add(ApprovalsTab());
        tabs.TabPages.Add(EnrollTab());
        tabs.TabPages.Add(TeamTab());
        tabs.TabPages.Add(SettingsTab());
        Controls.Add(tabs);
        Controls.Add(_status);
        var header = new Label
        {
            Dock = DockStyle.Top, Height = 46, BackColor = ColorTranslator.FromHtml(Brand.Navy), ForeColor = Color.White,
            Font = new Font("Segoe UI Semibold", 13f), TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(14, 0, 0, 0),
            Text = "Sentinel Signer  ·  only what you approve here happens on a client PC",
        };
        Controls.Add(header);
        _poll.Tick += async (_, _) => await Refresh();
        _poll.Start();
        Shown += async (_, _) => { if (_cfg.Server.Length == 0) tabs.SelectedIndex = 3; await Refresh(); };
    }

    // ---------------- talking to the server ----------------

    private HttpRequestMessage Request(HttpMethod method, string path, object? body = null)
    {
        var req = new HttpRequestMessage(method, _cfg.Server.TrimEnd('/') + path);
        req.Headers.Add("X-Sentinel-Signer", SignerLogic.Header(_key, _keyId, method.Method, path, DateTimeOffset.UtcNow));
        if (body is not null) req.Content = JsonContent.Create(body, options: Json);
        return req;
    }

    private async Task<T?> Send<T>(HttpMethod method, string path, object? body = null)
    {
        if (!_cfg.Server.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Set the server address (https://...) in Settings.");
        using var res = await _http.SendAsync(Request(method, path, body));
        if (res.StatusCode == System.Net.HttpStatusCode.Unauthorized)
            throw new InvalidOperationException("The server doesn't know this key yet. Register it in the console: Settings, Sentinel Signer keys.");
        var text = await res.Content.ReadAsStringAsync();
        if (!res.IsSuccessStatusCode)
        {
            string msg = $"The server answered {(int)res.StatusCode}.";
            try { msg = JsonDocument.Parse(text).RootElement.GetProperty("error").GetString() ?? msg; } catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException) { }
            throw new InvalidOperationException(msg);
        }
        return typeof(T) == typeof(object) || text.Length == 0 ? default : JsonSerializer.Deserialize<T>(text, Json);
    }

    // ---------------- approvals ----------------

    private TabPage ApprovalsTab()
    {
        var page = new TabPage("Waiting for approval");
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 48, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(6) };
        _approve.BackColor = ColorTranslator.FromHtml(Brand.Orange);
        buttons.Controls.Add(_approve);
        buttons.Controls.Add(_reject);
        var right = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8, 0, 0, 0) };
        right.Controls.Add(_detail);
        right.Controls.Add(buttons);
        page.Controls.Add(right);
        page.Controls.Add(_pending);
        _pending.SelectedIndexChanged += (_, _) => ShowSelected();
        _approve.Click += async (_, _) => await Decide(approve: true);
        _reject.Click += async (_, _) => await Decide(approve: false);
        return page;
    }

    private new async Task Refresh()
    {
        if (_busy || _cfg.Server.Length == 0) return;
        _busy = true;
        try
        {
            var items = await Send<List<PendingAction>>(HttpMethod.Get, "/api/signer/pending") ?? new();
            items = items.Where(i => !_handled.Contains(i.Id)).ToList();
            var selected = (_pending.SelectedItem as Item)?.Action.Id;
            bool isNew = items.Any(i => _items.All(x => x.Id != i.Id));
            _items = items;
            _pending.BeginUpdate();
            _pending.Items.Clear();
            foreach (var i in items) _pending.Items.Add(new Item(i));
            _pending.EndUpdate();
            var again = _pending.Items.Cast<Item>().FirstOrDefault(x => x.Action.Id == selected);
            if (again is not null) _pending.SelectedItem = again;
            else if (_pending.Items.Count > 0) _pending.SelectedIndex = 0;
            ShowSelected();
            _status.Text = items.Count == 0 ? $"Nothing waiting. Checked {DateTime.Now:h:mm:ss tt}." : $"{items.Count} waiting for you.";
            if (isNew && WindowState == FormWindowState.Minimized) { WindowState = FormWindowState.Normal; Activate(); }
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException or JsonException)
        {
            _status.Text = e.Message;
        }
        finally { _busy = false; }
    }

    private sealed record Item(PendingAction Action)
    {
        public override string ToString() => $"{Action.Computer} · {Action.Kind} · {Action.CreatedUtc.ToLocalTime():h:mm tt}";
    }

    private void ShowSelected()
    {
        var a = (_pending.SelectedItem as Item)?.Action;
        _detail.Text = a is null ? "Actions you ask for in the Sentinel console show up here. Nothing happens on a client PC until you approve it." : SignerLogic.Describe(a).Replace("\n", "\r\n");
        _approve.Enabled = _reject.Enabled = a is not null;
    }

    private async Task Decide(bool approve)
    {
        if ((_pending.SelectedItem as Item)?.Action is not { } a) return;
        if (approve && SignerLogic.Powerful(a.Kind) &&
            MessageBox.Show(this, SignerLogic.Describe(a) + "\n\nApprove this?", "Approve", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            return;
        _approve.Enabled = _reject.Enabled = false;
        try
        {
            if (approve)
                await Send<object>(HttpMethod.Post, $"/api/signer/requests/{a.Id}/approve", SignerLogic.Approve(a, _key, _keyId, Name(), DateTime.UtcNow));
            else
                await Send<object>(HttpMethod.Post, $"/api/signer/requests/{a.Id}/reject");
            _handled.Add(a.Id);
            _status.Text = approve ? $"Approved: {a.Kind} on {a.Computer}." : "Turned down.";
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException)
        {
            MessageBox.Show(this, e.Message, "Sentinel Signer", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        await Refresh();
    }

    private string Name() => _cfg.Tech.Length > 0 ? _cfg.Tech : Environment.UserName;

    // ---------------- enrollment codes ----------------

    private TabPage EnrollTab()
    {
        var page = new TabPage("Enrollment code");
        var panel = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 1, AutoScroll = true };
        var clients = new ComboBox { Width = 420, DropDownStyle = ComboBoxStyle.DropDownList };
        var load = new Button { Text = "Load clients", AutoSize = true };
        var uses = new NumericUpDown { Minimum = 1, Maximum = 500, Value = 25, Width = 80 };
        var days = new NumericUpDown { Minimum = 1, Maximum = 30, Value = 7, Width = 80 };
        var keys = new CheckedListBox { Width = 620, Height = 120, CheckOnClick = true };
        var make = new Button { Text = "Make code", AutoSize = true, BackColor = ColorTranslator.FromHtml(Brand.Orange) };
        var output = new TextBox { Multiline = true, ReadOnly = true, Width = 880, Height = 170, Font = new Font("Consolas", 9.5f), ScrollBars = ScrollBars.Vertical };
        void FillKeys()
        {
            keys.Items.Clear();
            keys.Items.Add(new KeyItem(new TrustedKey { KeyId = _keyId, PublicKey = _publicKey, Tech = Name() + " (this PC)" }), true);
            foreach (var k in _cfg.TeamKeys) keys.Items.Add(new KeyItem(k), true);
        }
        page.Enter += (_, _) => FillKeys();
        load.Click += async (_, _) =>
        {
            try
            {
                var list = await Send<List<ClientItem>>(HttpMethod.Get, "/api/signer/clients") ?? new();
                clients.Items.Clear();
                foreach (var c in list) clients.Items.Add(c);
                if (clients.Items.Count > 0) clients.SelectedIndex = 0;
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException) { MessageBox.Show(this, e.Message); }
        };
        make.Click += async (_, _) =>
        {
            if (clients.SelectedItem is not ClientItem c) { MessageBox.Show(this, "Load the clients and choose one first."); return; }
            var chosen = keys.CheckedItems.Cast<KeyItem>().Select(k => k.Key).ToList();
            if (chosen.Count == 0) { MessageBox.Show(this, "Choose at least one key the PCs should trust."); return; }
            try
            {
                var r = await Send<CodeAnswer>(HttpMethod.Post, $"/api/signer/clients/{c.Id}/codes", new { days = (int)days.Value, uses = (int)uses.Value });
                // The key IDs come from this PC, not the server, so the server can't add a key of its own.
                var token = new EnrollToken { Server = _cfg.Server.TrimEnd('/'), Code = r!.Code, KeyIds = chosen.Select(k => k.KeyId).ToList(), Client = c.Name }.Encode();
                output.Text = $"Code for {c.Name} ({r.Uses} PCs, until {r.ExpiresUtc.ToLocalTime():MMM d h:mm tt}). PCs will trust: {string.Join(", ", chosen.Select(k => $"{k.Tech} [{SentinelCrypto.Readable(k.KeyId)[..9]}]"))}\r\n\r\n"
                    + token + "\r\n\r\nSilent install:\r\nNightTechSentinel-Setup.exe /VERYSILENT /CODE=" + token
                    + "\r\n\r\nAdd /UNATTENDED=1 only for servers or PCs nobody sits at.";
                Clipboard.SetText(token);
                _status.Text = "Code copied.";
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException) { MessageBox.Show(this, e.Message); }
        };
        panel.Controls.Add(new Label { Text = "Client", AutoSize = true });
        panel.Controls.Add(Row(clients, load));
        panel.Controls.Add(Row(new Label { Text = "For how many PCs", AutoSize = true, Padding = new Padding(0, 6, 0, 0) }, uses, new Label { Text = "Days it works", AutoSize = true, Padding = new Padding(12, 6, 0, 0) }, days));
        panel.Controls.Add(new Label { Text = "Technician keys the PCs will trust (only keys on this PC are listed)", AutoSize = true, Padding = new Padding(0, 10, 0, 0) });
        panel.Controls.Add(keys);
        panel.Controls.Add(make);
        panel.Controls.Add(output);
        page.Controls.Add(panel);
        return page;
    }

    private static FlowLayoutPanel Row(params Control[] c)
    {
        var f = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        f.Controls.AddRange(c);
        return f;
    }

    private sealed record ClientItem(string Id, string Name) { public override string ToString() => Name; }
    private sealed record CodeAnswer(string Code, DateTime ExpiresUtc, int Uses);
    private sealed record KeyItem(TrustedKey Key) { public override string ToString() => $"{Key.Tech}  [{SentinelCrypto.Readable(Key.KeyId)}]"; }

    // ---------------- team keys ----------------

    private TabPage TeamTab()
    {
        var page = new TabPage("Team keys");
        var list = new ListBox { Dock = DockStyle.Top, Height = 220 };
        void Fill() { list.Items.Clear(); foreach (var k in _cfg.TeamKeys) list.Items.Add(new KeyItem(k)); }
        Fill();
        var name = new TextBox { Width = 300, PlaceholderText = "Their name" };
        var pub = new TextBox { Width = 880, Height = 70, Multiline = true, PlaceholderText = "Paste the public key from their Sentinel Signer (My key in Settings)" };
        var add = new Button { Text = "Add key", AutoSize = true };
        var remove = new Button { Text = "Remove selected", AutoSize = true };
        add.Click += (_, _) =>
        {
            string id;
            try { id = SentinelCrypto.KeyId(pub.Text.Trim()); }
            catch (FormatException) { MessageBox.Show(this, "That isn't a key."); return; }
            if (MessageBox.Show(this, $"Check this with {name.Text} by phone or in person before adding it:\n\n{SentinelCrypto.Readable(id)}\n\nDoes it match what their Signer shows?", "Check the key", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes) return;
            _cfg.TeamKeys.RemoveAll(k => k.KeyId == id);
            _cfg.TeamKeys.Add(new TrustedKey { KeyId = id, PublicKey = pub.Text.Trim(), Tech = name.Text.Trim().Length > 0 ? name.Text.Trim() : "Technician" });
            _cfg.Save();
            Fill();
            pub.Clear(); name.Clear();
        };
        remove.Click += (_, _) =>
        {
            if (list.SelectedItem is KeyItem k) { _cfg.TeamKeys.RemoveAll(x => x.KeyId == k.Key.KeyId); _cfg.Save(); Fill(); }
        };
        var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, Padding = new Padding(10), WrapContents = false };
        panel.Controls.Add(new Label { Text = "Teammates whose keys go in the enrollment codes you make. Add a key only after checking it with that person directly.", AutoSize = true, MaximumSize = new Size(880, 0) });
        panel.Controls.Add(name);
        panel.Controls.Add(pub);
        panel.Controls.Add(Row(add, remove));
        page.Controls.Add(panel);
        page.Controls.Add(list);
        return page;
    }

    // ---------------- settings ----------------

    private TabPage SettingsTab()
    {
        var page = new TabPage("Settings");
        var server = new TextBox { Width = 500, Text = _cfg.Server, PlaceholderText = "https://sentinel.example.com" };
        var tech = new TextBox { Width = 300, Text = _cfg.Tech, PlaceholderText = "Your name (shown to clients)" };
        var save = new Button { Text = "Save", AutoSize = true };
        var keyText = new TextBox { Width = 880, Height = 70, Multiline = true, ReadOnly = true, Text = _publicKey, Font = new Font("Consolas", 9f) };
        var copy = new Button { Text = "Copy public key", AutoSize = true };
        save.Click += (_, _) =>
        {
            var s = server.Text.Trim().TrimEnd('/');
            if (!s.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) { MessageBox.Show(this, "The address must start with https://"); return; }
            _cfg.Server = s;
            _cfg.Tech = tech.Text.Trim();
            _cfg.Save();
            _status.Text = "Saved.";
        };
        copy.Click += (_, _) => Clipboard.SetText(_publicKey);
        var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, Padding = new Padding(12), WrapContents = false };
        panel.Controls.Add(new Label { Text = "Sentinel server address", AutoSize = true });
        panel.Controls.Add(server);
        panel.Controls.Add(new Label { Text = "Your name", AutoSize = true });
        panel.Controls.Add(tech);
        panel.Controls.Add(save);
        panel.Controls.Add(new Label { Text = $"\nMy key, kept in {_where}. Register the public key below in the console (Settings, Sentinel Signer keys), and check the ID matches:", AutoSize = true, MaximumSize = new Size(880, 0) });
        panel.Controls.Add(new Label { Text = SentinelCrypto.Readable(_keyId), AutoSize = true, Font = new Font("Consolas", 13f, FontStyle.Bold) });
        panel.Controls.Add(keyText);
        panel.Controls.Add(copy);
        panel.Controls.Add(new Label { Text = $"\n{Brand.Company} · {Brand.Phone} · {Brand.Verse}", AutoSize = true, ForeColor = Color.DimGray });
        page.Controls.Add(panel);
        return page;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) { _poll.Dispose(); _http.Dispose(); _key.Dispose(); }
        base.Dispose(disposing);
    }
}
