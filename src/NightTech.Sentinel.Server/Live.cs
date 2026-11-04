using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Server;

/// <summary>
/// The PCs' live connections (so commands arrive in seconds), and the relay that joins a tech's browser to a PC for a
/// remote session. The relay only copies frames: they're encrypted between the browser and the PC.
/// </summary>
public sealed class Live
{
    private readonly Store _store;
    private readonly ConcurrentDictionary<string, (WebSocket Socket, SemaphoreSlim Lock)> _agents = new();
    private readonly ConcurrentDictionary<string, Pending> _sessions = new();

    public Live(Store store) { _store = store; }

    public bool IsOnline(string deviceId) => _agents.TryGetValue(deviceId, out var a) && a.Socket.State == WebSocketState.Open;

    private sealed class Pending
    {
        public string DeviceId = "";
        public string TechId = "";
        public DateTime CreatedUtc;
        public int Relaying;
        public readonly TaskCompletionSource<WebSocket> Agent = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource<WebSocket> Browser = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public readonly TaskCompletionSource Done = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    public void ExpectSession(string sessionId, string deviceId, string techId)
    {
        foreach (var old in _sessions.Where(s => DateTime.UtcNow - s.Value.CreatedUtc > TimeSpan.FromMinutes(10)).ToList()) _sessions.TryRemove(old.Key, out _);
        _sessions[sessionId] = new Pending { DeviceId = deviceId, TechId = techId, CreatedUtc = DateTime.UtcNow };
    }

    /// <summary>Asks the PC to prove who it is: it signs a one-time challenge with its device key.</summary>
    public async Task<Device?> Authenticate(WebSocket ws, Func<string, string> purpose, CancellationToken ct)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        await Send(ws, new { type = "challenge", nonce }, ct);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(20));
        var (type, data) = await Receive(ws, 64 * 1024, timeout.Token);
        if (type != WebSocketMessageType.Text) return null;
        using var doc = JsonDocument.Parse(data);
        var root = doc.RootElement;
        string Get(string n) => root.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        if (Get("type") != "auth" || Get("nonce") != nonce) return null;
        var device = _store.Device(Get("deviceId"));
        if (device is null || device.Retired) return null;
        return SentinelCrypto.Verify(device.PublicKey, Encoding.UTF8.GetBytes(purpose(device.Id) + "|" + nonce), Get("signature")) ? device : null;
    }

    public async Task AgentLive(WebSocket ws, CancellationToken ct)
    {
        var device = await Authenticate(ws, id => "sentinel-live|" + id, ct);
        if (device is null) { await Close(ws, "not recognized"); return; }
        var entry = (ws, new SemaphoreSlim(1, 1));
        _agents[device.Id] = entry;
        try
        {
            // Anything waiting goes straight away.
            foreach (var q in device.Queue.Where(q => q.DeliveredUtc is null && q.ExpiresUtc > DateTime.UtcNow).ToList()) await Push(device, q);
            var buffer = new byte[1024];
            while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
            {
                var r = await ws.ReceiveAsync(buffer, ct);
                if (r.MessageType == WebSocketMessageType.Close) break;
            }
        }
        catch (Exception e) when (e is WebSocketException or OperationCanceledException) { }
        finally { ((ICollection<KeyValuePair<string, (WebSocket, SemaphoreSlim)>>)_agents).Remove(new(device.Id, entry)); }
    }

    /// <summary>Sends a command over the live connection, if the PC has one. Returns true when it went.</summary>
    public async Task<bool> Push(Device device, QueuedCommand q)
    {
        if (!_agents.TryGetValue(device.Id, out var a) || a.Socket.State != WebSocketState.Open) return false;
        await a.Lock.WaitAsync();
        try { await Send(a.Socket, new { type = "command", command = q.Signed }, CancellationToken.None); }
        catch (WebSocketException) { return false; }
        finally { a.Lock.Release(); }
        _store.Change(() => { q.DeliveredUtc = DateTime.UtcNow; _store.SaveDevice(device); });
        return true;
    }

    public async Task AgentSession(WebSocket ws, string sessionId, CancellationToken ct)
    {
        if (!_sessions.TryGetValue(sessionId, out var p)) { await Close(ws, "no such session"); return; }
        var device = await Authenticate(ws, id => $"sentinel-session|{id}|{sessionId}", ct);
        if (device is null || device.Id != p.DeviceId || !p.Agent.TrySetResult(ws)) { await Close(ws, "not recognized"); return; }
        await Relay(p, sessionId, ct);
    }

    public async Task BrowserSession(WebSocket ws, string sessionId, Tech tech, CancellationToken ct)
    {
        if (!_sessions.TryGetValue(sessionId, out var p) || p.TechId != tech.Id || !p.Browser.TrySetResult(ws)) { await Close(ws, "no such session"); return; }
        await Relay(p, sessionId, ct);
    }

    /// <summary>Both sides wait here; the first to arrive also waits for the other, then frames are copied both ways.</summary>
    private async Task Relay(Pending p, string sessionId, CancellationToken ct)
    {
        var both = Task.WhenAll(p.Agent.Task, p.Browser.Task);
        if (await Task.WhenAny(both, Task.Delay(TimeSpan.FromMinutes(5), ct)) != both)
        {
            _sessions.TryRemove(sessionId, out _);
            p.Done.TrySetResult();
            return;
        }
        if (Interlocked.Exchange(ref p.Relaying, 1) == 1)
        {
            await p.Done.Task;   // the other side's request is doing the copying
            return;
        }
        _sessions.TryRemove(sessionId, out _);
        var agent = p.Agent.Task.Result;
        var browser = p.Browser.Task.Result;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        try { await Task.WhenAny(Copy(agent, browser, cts.Token), Copy(browser, agent, cts.Token)); }
        finally
        {
            cts.Cancel();
            await Close(agent, "ended");
            await Close(browser, "ended");
            p.Done.TrySetResult();
        }
    }

    private static async Task Copy(WebSocket from, WebSocket to, CancellationToken ct)
    {
        var buffer = new byte[64 * 1024];
        try
        {
            while (from.State == WebSocketState.Open && to.State == WebSocketState.Open)
            {
                var r = await from.ReceiveAsync(buffer, ct);
                if (r.MessageType == WebSocketMessageType.Close) return;
                await to.SendAsync(buffer.AsMemory(0, r.Count), r.MessageType, r.EndOfMessage, ct);
            }
        }
        catch (Exception e) when (e is WebSocketException or OperationCanceledException) { }
    }

    public static Task Send(WebSocket ws, object m, CancellationToken ct) =>
        ws.SendAsync(JsonSerializer.SerializeToUtf8Bytes(m, SignedCommand.Json), WebSocketMessageType.Text, true, ct);

    private static async Task<(WebSocketMessageType, byte[])> Receive(WebSocket ws, int max, CancellationToken ct)
    {
        var buffer = new byte[8192];
        using var ms = new MemoryStream();
        while (true)
        {
            var r = await ws.ReceiveAsync(buffer, ct);
            if (r.MessageType == WebSocketMessageType.Close) return (r.MessageType, Array.Empty<byte>());
            ms.Write(buffer, 0, r.Count);
            if (ms.Length > max) throw new WebSocketException("Message too large.");
            if (r.EndOfMessage) return (r.MessageType, ms.ToArray());
        }
    }

    private static async Task Close(WebSocket ws, string why)
    {
        try
        {
            if (ws.State is WebSocketState.Open or WebSocketState.CloseReceived)
                await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, why, CancellationToken.None);
        }
        catch (WebSocketException) { }
    }
}
