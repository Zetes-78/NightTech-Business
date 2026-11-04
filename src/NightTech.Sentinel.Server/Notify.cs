using System.Net;
using System.Net.Mail;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Server;

/// <summary>
/// Optional email for new critical alerts and help requests. Set SENTINEL_SMTP_HOST, SENTINEL_SMTP_PORT (587),
/// SENTINEL_SMTP_USER, SENTINEL_SMTP_PASSWORD, SENTINEL_ALERT_FROM and SENTINEL_ALERT_TO. Without them, alerts show in
/// the console only. Emails name the PC and the problem; they never include passwords or keys.
/// </summary>
public sealed class Notify
{
    private readonly Store _store;
    private readonly string? _host = Environment.GetEnvironmentVariable("SENTINEL_SMTP_HOST");
    private readonly int _port = int.TryParse(Environment.GetEnvironmentVariable("SENTINEL_SMTP_PORT"), out var p) ? p : 587;
    private readonly string? _user = Environment.GetEnvironmentVariable("SENTINEL_SMTP_USER");
    private readonly string? _password = Environment.GetEnvironmentVariable("SENTINEL_SMTP_PASSWORD");
    private readonly string? _from = Environment.GetEnvironmentVariable("SENTINEL_ALERT_FROM");
    private readonly string? _to = Environment.GetEnvironmentVariable("SENTINEL_ALERT_TO");

    public Notify(Store store) { _store = store; }

    public bool Enabled => !string.IsNullOrEmpty(_host) && !string.IsNullOrEmpty(_from) && !string.IsNullOrEmpty(_to);

    public async Task NewAlerts(Device d, IReadOnlyList<Alert> alerts)
    {
        var urgent = alerts.Where(a => a.Level == AlertLevel.Critical).ToList();
        if (!Enabled || urgent.Count == 0) return;
        var client = _store.Clients.FirstOrDefault(c => c.Id == d.ClientId)?.Name ?? "";
        var subject = urgent.Any(a => a.Key == "help") ? $"Help requested: {d.Computer} ({client})" : $"Sentinel: {urgent[0].Title} on {d.Computer} ({client})";
        var body = string.Join("\n\n", urgent.Select(a => $"{a.Title}\n{a.Detail}")) + "\n\nOpen the Sentinel console to see the details.";
        try
        {
            using var smtp = new SmtpClient(_host, _port) { EnableSsl = true };
            if (!string.IsNullOrEmpty(_user)) smtp.Credentials = new NetworkCredential(_user, _password);
            using var msg = new MailMessage(_from!, _to!, Clip(subject, 200), body);
            await smtp.SendMailAsync(msg);
        }
        catch (Exception e) when (e is SmtpException or InvalidOperationException or FormatException)
        {
            _store.Audit("server", "Alert email didn't send: " + e.Message);
        }
    }

    private static string Clip(string s, int n) => s.Length <= n ? s : s[..n];
}

/// <summary>Every 10 minutes, raises "not checking in" for PCs that have gone quiet.</summary>
public sealed class OfflineWatch : BackgroundService
{
    private readonly Store _store;
    private readonly Notify _notify;

    public OfflineWatch(Store store, Notify notify) { _store = store; _notify = notify; }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var now = DateTime.UtcNow;
            foreach (var d in _store.Devices.Where(d => !d.Retired).ToList())
            {
                var off = AlertRules.Offline(d.LastSeenUtc ?? d.EnrolledUtc, now);
                if (off is null) continue;
                List<Alert> news = new();
                _store.Change(() =>
                {
                    var existing = d.Alerts.FirstOrDefault(a => a.Key == "offline" && a.ClearedUtc is null);
                    if (existing is null) { d.Alerts.Add(off); news.Add(off); }
                    else if (off.Level > existing.Level) { existing.Level = off.Level; existing.Detail = off.Detail; existing.Acknowledged = false; news.Add(existing); }
                    else { existing.Detail = off.Detail; existing.LastSeenUtc = now; }
                    _store.SaveDevice(d);
                });
                if (news.Count > 0) await _notify.NewAlerts(d, news);
            }
            try { await Task.Delay(TimeSpan.FromMinutes(10), ct); } catch (OperationCanceledException) { return; }
        }
    }
}
