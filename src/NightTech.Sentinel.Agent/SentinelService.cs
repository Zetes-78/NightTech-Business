using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Agent;

/// <summary>
/// The check-in loop: every few minutes, read the PC's health and Shield's checks, send them signed with the device
/// key, and carry out any commands that come back (after checking each one's signature, age and this PC's policy).
/// </summary>
public sealed class SentinelService : BackgroundService
{
    public static string Version => Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.1.0";
    public static readonly TimeSpan ShieldEvery = TimeSpan.FromHours(6);

    private readonly AgentLog _log = new();
    private readonly TrayLink _tray;
    private readonly Actions _actions;
    private readonly HttpClient _http;
    private AgentConfig _cfg;
    private DateTime _lastShield = DateTime.MinValue;
    private string _help = "";
    private DateTime _busyUntil = DateTime.MinValue;
    private readonly SemaphoreSlim _wake = new(0);
    private LiveLink? _live;
    private readonly SemaphoreSlim _verifyLock = new(1, 1);

    public SentinelService()
    {
        _cfg = AgentStore.Load() ?? throw new InvalidOperationException("Sentinel isn't set up on this PC. Run the installer with an enrollment code.");
        _tray = new TrayLink(_log);
        _tray.HelpRequested += text => { _help = text; _log.Info("Help requested from the PC: " + text); _wake.Release(); };
        _actions = new Actions(_tray, _log, () => _cfg, c => { _cfg = c; AgentStore.Save(c); });
        _http = Http(_cfg.Server);
    }

    public static HttpClient Http(string server) => new(new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(20), PooledConnectionLifetime = TimeSpan.FromMinutes(10) })
    {
        BaseAddress = new Uri(server.TrimEnd('/') + "/"),
        Timeout = TimeSpan.FromSeconds(100),
        DefaultRequestHeaders = { { "User-Agent", $"NightTechSentinel/{Version}" } },
    };

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _log.Info($"Night Tech Sentinel {Version} started for {_cfg.ClientName}.");
        _tray.Start();
        _live = new LiveLink(() => _cfg, _log, _tray, Handle);
        _actions.Sessions = _live;
        _ = Task.Run(() => _live.Run(ct), ct);

        while (!ct.IsCancellationRequested)
        {
            try { await CheckIn(ct); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { break; }
            catch (Exception e)
            {
                _log.Warn("Check-in failed: " + e.Message);
                _tray.SetStatus("Can't reach Night Tech right now. It will keep trying.", ok: false);
            }
            var wait = DateTime.UtcNow < _busyUntil || _actions.CheckInSoon ? TimeSpan.FromMinutes(1) : TimeSpan.FromMinutes(Math.Clamp(_cfg.CheckInMinutes, 5, 240));
            _actions.CheckInSoon = false;
            try { await _wake.WaitAsync(wait, ct); } catch (OperationCanceledException) { break; }
        }
    }

    private async Task CheckIn(CancellationToken ct)
    {
        if (_actions.LastShield is null || DateTime.UtcNow - _lastShield > ShieldEvery)
        {
            try { SetShield(await Task.Run(() => Actions.ShieldScan(Version), ct)); }
            catch (Exception e) when (e is not OperationCanceledException) { _log.Warn("Shield check failed: " + e.Message); }
        }
        var report = await Task.Run(() => HealthCollector.Collect(_cfg, Version, _shield), ct);
        report.HelpRequest = _help;
        report.Results = _cfg.PendingResults.ToList();

        var payload = JsonSerializer.SerializeToUtf8Bytes(report, SignedCommand.Json);
        using var key = AgentStore.DeviceKey();
        var body = new CheckIn { DeviceId = _cfg.DeviceId, Payload = Convert.ToBase64String(payload), Signature = SentinelCrypto.Sign(key, payload) };
        using var res = await _http.PostAsJsonAsync("api/agent/checkin", body, SignedCommand.Json, ct);
        if (res.StatusCode == System.Net.HttpStatusCode.Gone)
        {
            _tray.SetStatus("This PC was removed from Night Tech Sentinel.", ok: false);
            _log.Warn("The server says this PC was removed. Check-ins stop until Sentinel is set up again.");
            await Task.Delay(TimeSpan.FromHours(6), ct);
            return;
        }
        res.EnsureSuccessStatusCode();
        if (res.Content.Headers.ContentLength is > 4_000_000) throw new InvalidOperationException("The server's answer was too large.");
        var answer = await res.Content.ReadFromJsonAsync<CheckInResponse>(SignedCommand.Json, ct) ?? new CheckInResponse();
        answer.Commands ??= new();
        answer.Status ??= "";

        // Delivered: these results and the help request are on the server now.
        await _verifyLock.WaitAsync(ct);
        try { _cfg.PendingResults.RemoveAll(r => report.Results.Any(x => x.CommandId == r.CommandId)); }
        finally { _verifyLock.Release(); }
        if (_help == report.HelpRequest) _help = "";
        _cfg.CheckInMinutes = Math.Clamp(answer.CheckInMinutes, 5, 240);
        _cfg.LastCheckInUtc = DateTime.UtcNow;
        _cfg.LastStatus = answer.Status;
        AgentStore.Save(_cfg);
        _tray.SetStatus(answer.Status.Length > 0 ? answer.Status : "Monitored by Night Tech Solutions", ok: true);

        foreach (var signed in answer.Commands.Take(20)) await Handle(signed, ct);
    }

    private NightTech.Shield.Core.ScanResult? _shield;

    private void SetShield(NightTech.Shield.Core.ScanResult s)
    {
        _shield = s;
        _lastShield = DateTime.UtcNow;
    }

    /// <summary>Checks a signed command and runs it. Used for check-in commands and ones that arrive over the live link.</summary>
    public async Task Handle(SignedCommand signed, CancellationToken ct)
    {
        Command? c;
        string why;
        // Commands arrive from the check-in and the live link at the same time: checking and recording each ID happens
        // one at a time, and is saved before the command runs, so no command can run twice.
        await _verifyLock.WaitAsync(ct);
        try
        {
            var verifier = new CommandVerifier(_cfg.DeviceId, () => _cfg.TrustedKeys, _cfg.SeenCommands);
            (c, why) = verifier.Verify(signed, DateTime.UtcNow);
            AgentStore.Save(_cfg);
        }
        finally { _verifyLock.Release(); }
        if (c is null)
        {
            _log.Warn($"A command was refused: it {why}.");
            return;
        }
        _busyUntil = DateTime.UtcNow.AddMinutes(10);
        var result = await _actions.Run(c, Version, ct);
        if (_actions.LastShield is { } s && !ReferenceEquals(s, _shield)) SetShield(s);
        await _verifyLock.WaitAsync(ct);
        try
        {
            _cfg.PendingResults.Add(result);
            if (_cfg.PendingResults.Count > 50) _cfg.PendingResults.RemoveRange(0, _cfg.PendingResults.Count - 50);
            AgentStore.Save(_cfg);
        }
        finally { _verifyLock.Release(); }
        _wake.Release();
    }

    public override void Dispose()
    {
        _tray.Dispose();
        _http.Dispose();
        base.Dispose();
    }
}
