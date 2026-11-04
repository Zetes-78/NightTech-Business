using System.Diagnostics;
using System.IO.Pipes;
using System.Net.WebSockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Agent;

/// <summary>The control messages on the live connection and at the start of a session.</summary>
public sealed class LiveMessage
{
    /// <summary>challenge, auth, command, wake, answer, end.</summary>
    public string Type { get; set; } = "";
    public string Nonce { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string SessionId { get; set; } = "";
    public string Signature { get; set; } = "";
    public string Payload { get; set; } = "";
    public SignedCommand? Command { get; set; }
}

/// <summary>What the PC sends the browser to start a session: its half of the key exchange, signed with the device key.</summary>
public sealed class SessionAnswer
{
    public string SessionId { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string AgentKey { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Computer { get; set; } = "";
}

/// <summary>
/// The always-on connection to the Sentinel server, so commands arrive in seconds instead of at the next check-in, and
/// the remote shell and remote desktop sessions that run over it. The server only relays session frames, which are
/// encrypted between the tech's browser and this PC.
/// </summary>
public sealed class LiveLink : ISessions
{
    public static readonly TimeSpan MaxSession = TimeSpan.FromHours(4);
    public static readonly TimeSpan IdleLimit = TimeSpan.FromMinutes(20);
    private readonly Func<AgentConfig> _cfg;
    private readonly AgentLog _log;
    private readonly TrayLink _tray;
    private readonly Func<SignedCommand, CancellationToken, Task> _handle;
    private int _sessions;

    public LiveLink(Func<AgentConfig> cfg, AgentLog log, TrayLink tray, Func<SignedCommand, CancellationToken, Task> handle)
    {
        _cfg = cfg; _log = log; _tray = tray; _handle = handle;
    }

    private Uri Ws(string path)
    {
        var b = new UriBuilder(new Uri(new Uri(_cfg().Server.TrimEnd('/') + "/"), path)) { Scheme = "wss", Port = -1 };
        var server = new Uri(_cfg().Server);
        if (!server.IsDefaultPort) b.Port = server.Port;
        return b.Uri;
    }

    public async Task Run(CancellationToken ct)
    {
        var delay = TimeSpan.FromSeconds(5);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var ws = await Connect(Ws("api/agent/live"), "sentinel-live|" + _cfg().DeviceId, ct);
                delay = TimeSpan.FromSeconds(5);
                while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
                {
                    var text = await ReceiveText(ws, ct);
                    if (text is null) break;
                    var m = JsonSerializer.Deserialize<LiveMessage>(text, SignedCommand.Json);
                    if (m?.Type == "command" && m.Command is not null) _ = Task.Run(() => _handle(m.Command, ct), ct);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception e) when (e is WebSocketException or IOException or JsonException or InvalidOperationException or HttpRequestException) { }
            try { await Task.Delay(delay, ct); } catch (OperationCanceledException) { return; }
            delay = TimeSpan.FromSeconds(Math.Min(delay.TotalSeconds * 2, 300));
        }
    }

    /// <summary>Opens a WebSocket and proves which PC this is by signing the server's one-time challenge.</summary>
    private async Task<ClientWebSocket> Connect(Uri uri, string purpose, CancellationToken ct)
    {
        var ws = new ClientWebSocket();
        ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(30);
        ws.Options.SetRequestHeader("User-Agent", $"NightTechSentinel/{SentinelService.Version}");
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            await ws.ConnectAsync(uri, timeout.Token);
            var challenge = JsonSerializer.Deserialize<LiveMessage>(await ReceiveText(ws, timeout.Token) ?? "", SignedCommand.Json);
            if (challenge?.Type != "challenge" || challenge.Nonce.Length < 16) throw new InvalidOperationException("The server didn't send a challenge.");
            using var key = AgentStore.DeviceKey();
            var proof = SentinelCrypto.Sign(key, Encoding.UTF8.GetBytes(purpose + "|" + challenge.Nonce));
            await SendText(ws, new LiveMessage { Type = "auth", DeviceId = _cfg().DeviceId, Nonce = challenge.Nonce, Signature = proof }, timeout.Token);
            return ws;
        }
        catch { ws.Dispose(); throw; }
    }

    public static async Task<string?> ReceiveText(WebSocket ws, CancellationToken ct)
    {
        var (type, data) = await Receive(ws, 1 << 20, ct);
        return type == WebSocketMessageType.Text ? Encoding.UTF8.GetString(data) : type == WebSocketMessageType.Close ? null : "";
    }

    public static async Task<(WebSocketMessageType Type, byte[] Data)> Receive(WebSocket ws, int max, CancellationToken ct)
    {
        var buffer = new byte[16384];
        using var ms = new MemoryStream();
        while (true)
        {
            var r = await ws.ReceiveAsync(buffer, ct);
            if (r.MessageType == WebSocketMessageType.Close) return (r.MessageType, Array.Empty<byte>());
            ms.Write(buffer, 0, r.Count);
            if (ms.Length > max) throw new InvalidOperationException("Message too large.");
            if (r.EndOfMessage) return (r.MessageType, ms.ToArray());
        }
    }

    public static Task SendText(WebSocket ws, object m, CancellationToken ct) =>
        ws.SendAsync(JsonSerializer.SerializeToUtf8Bytes(m, SignedCommand.Json), WebSocketMessageType.Text, true, ct);

    // ---------------- Sessions ----------------

    public Task<CommandResult> Start(Command c, CommandResult result, CancellationToken ct)
    {
        var sessionId = c.Arg("sessionId");
        var browserKey = c.Arg("browserKey");
        result.FinishedUtc = DateTime.UtcNow;
        if (sessionId.Length is < 16 or > 64 || browserKey.Length == 0)
        {
            result.Outcome = "Failed"; result.Detail = "The session request was incomplete.";
            return Task.FromResult(result);
        }
        if (Interlocked.Increment(ref _sessions) > 2)
        {
            Interlocked.Decrement(ref _sessions);
            result.Outcome = "Refused"; result.Detail = "Two sessions are already open on this PC.";
            return Task.FromResult(result);
        }
        _ = Task.Run(async () =>
        {
            try { await RunSession(c, sessionId, browserKey, ct); }
            catch (Exception e) when (e is not OperationCanceledException) { _log.Warn($"Session {sessionId} ended with an error: {e.Message}"); }
            finally { Interlocked.Decrement(ref _sessions); }
        }, ct);
        result.Outcome = "Done";
        result.Detail = c.Kind == CommandKind.RemoteDesktop ? "Remote desktop started." : "Remote shell started.";
        return Task.FromResult(result);
    }

    private async Task RunSession(Command c, string sessionId, string browserKey, CancellationToken outer)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(outer);
        cts.CancelAfter(MaxSession);
        var ct = cts.Token;
        var cfg = _cfg();
        using var ws = await Connect(Ws("api/agent/session/" + Uri.EscapeDataString(sessionId)), $"sentinel-session|{cfg.DeviceId}|{sessionId}", ct);

        using var mine = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var agentKey = Convert.ToBase64String(mine.ExportSubjectPublicKeyInfo());
        var answer = JsonSerializer.SerializeToUtf8Bytes(new SessionAnswer
        {
            SessionId = sessionId, DeviceId = cfg.DeviceId, AgentKey = agentKey, Kind = c.Kind.ToString(), Computer = Environment.MachineName,
        }, SignedCommand.Json);
        using (var key = AgentStore.DeviceKey())
            await SendText(ws, new LiveMessage { Type = "answer", SessionId = sessionId, Payload = Convert.ToBase64String(answer), Signature = SentinelCrypto.Sign(key, answer) }, ct);
        using var crypto = new SessionCrypto(mine, browserKey, sessionId, browserKey, agentKey, isAgent: true);

        string what = c.Kind == CommandKind.RemoteDesktop ? "remote desktop" : "remote shell";
        _log.Info($"{what} session {sessionId} started by {c.Tech}.");
        await _tray.SessionChanged(true, $"{c.Tech} from Night Tech Solutions is connected ({what}).");
        var sendLock = new SemaphoreSlim(1, 1);
        async Task Send(byte[] inner)
        {
            var frame = crypto.Seal(inner);
            await sendLock.WaitAsync(ct);
            try { await ws.SendAsync(frame, WebSocketMessageType.Binary, true, ct); }
            finally { sendLock.Release(); }
        }
        try
        {
            if (c.Kind == CommandKind.RemoteShell) await Shell(ws, crypto, Send, ct);
            else await Desktop(ws, crypto, Send, c.Tech, ct);
        }
        finally
        {
            _log.Info($"{what} session {sessionId} by {c.Tech} ended.");
            await _tray.SessionChanged(false, "");
            if (ws.State == WebSocketState.Open)
                try { await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "ended", CancellationToken.None); } catch (WebSocketException) { }
        }
    }

    public static byte[] Control(object o) => new byte[] { 1 }.Concat(JsonSerializer.SerializeToUtf8Bytes(o, SignedCommand.Json)).ToArray();

    /// <summary>Reads encrypted frames from the browser and hands each opened message on; stops when idle too long.</summary>
    private static async Task Pump(WebSocket ws, SessionCrypto crypto, Func<byte[], Task<bool>> onMessage, CancellationToken ct)
    {
        while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
        {
            using var idle = CancellationTokenSource.CreateLinkedTokenSource(ct);
            idle.CancelAfter(IdleLimit);
            (WebSocketMessageType type, byte[] data) m;
            try { m = await Receive(ws, 1 << 20, idle.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return; }   // idle
            if (m.type == WebSocketMessageType.Close) return;
            if (m.type != WebSocketMessageType.Binary) continue;
            byte[] inner;
            try { inner = crypto.Open(m.data); }
            catch (CryptographicException) { return; }   // tampered or replayed: end the session
            if (inner.Length == 0) continue;
            if (!await onMessage(inner)) return;
        }
    }

    private sealed class ControlMsg
    {
        public string T { get; set; } = "";
        public string D { get; set; } = "";
        public int X { get; set; }
        public int Y { get; set; }
        public int B { get; set; }
        public int Code { get; set; }
        public bool Ext { get; set; }
        public bool Up { get; set; }
        public int Delta { get; set; }
    }

    // ---------------- Remote shell ----------------

    private static async Task Shell(WebSocket ws, SessionCrypto crypto, Func<byte[], Task> send, CancellationToken ct)
    {
        var ps = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        using var p = Process.Start(new ProcessStartInfo(ps, "-NoLogo -NoProfile -ExecutionPolicy Bypass -Command -")
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8, WorkingDirectory = Environment.SystemDirectory,
        }) ?? throw new InvalidOperationException("PowerShell didn't start.");
        try
        {
            await send(Control(new { t = "out", d = $"Night Tech Sentinel remote shell on {Environment.MachineName} (PowerShell, running as SYSTEM). Every command is logged on this PC.\r\n" }));
            async Task Forward(StreamReader r)
            {
                var buf = new char[4096];
                int n;
                while ((n = await r.ReadAsync(buf, ct)) > 0) await send(Control(new { t = "out", d = new string(buf, 0, n) }));
            }
            var outTask = Forward(p.StandardOutput);
            var errTask = Forward(p.StandardError);
            await Pump(ws, crypto, async inner =>
            {
                if (inner[0] != 1) return true;
                var m = JsonSerializer.Deserialize<ControlMsg>(inner.AsSpan(1), SignedCommand.Json);
                if (m?.T == "end") return false;
                if (m?.T == "in")
                {
                    await p.StandardInput.WriteAsync(m.D.Replace("\r\n", "\n").Replace('\r', '\n'));
                    await p.StandardInput.FlushAsync();
                }
                return !p.HasExited;
            }, ct);
        }
        finally
        {
            try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            try { await send(Control(new { t = "end", d = "Session closed." })); } catch (Exception e) when (e is WebSocketException or OperationCanceledException or ObjectDisposedException) { }
        }
    }

    // ---------------- Remote desktop ----------------

    /// <summary>
    /// The screen can't be seen from a service, so a helper is started in the signed-in person's session (as SYSTEM,
    /// so it also works on the sign-in screen and UAC prompts). It talks to the service over a pipe only SYSTEM can open,
    /// and it shows a banner with a Disconnect button for as long as the session lasts.
    /// </summary>
    private async Task Desktop(WebSocket ws, SessionCrypto crypto, Func<byte[], Task> send, string tech, CancellationToken ct)
    {
        var pipeName = "NightTechSentinelDesktop-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        using var pipe = NamedPipeServerStreamAcl.Create(pipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 1 << 16, 1 << 16, sec);
        using var helper = HelperProcess.StartInConsoleSession(Environment.ProcessPath!, $"--desktop-helper {pipeName} \"{tech.Replace("\"", "")}\"");
        using (var wait = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            wait.CancelAfter(TimeSpan.FromSeconds(30));
            await pipe.WaitForConnectionAsync(wait.Token);
        }
        var fromHelper = Task.Run(async () =>
        {
            while (!ct.IsCancellationRequested)
            {
                var msg = await PipeFrames.Read(pipe, ct);
                if (msg is null) return;
                await send(msg);
                if (msg[0] == 1 && Encoding.UTF8.GetString(msg, 1, msg.Length - 1).Contains("\"t\":\"end\"")) return;
            }
        }, ct);
        var fromBrowser = Pump(ws, crypto, async inner =>
        {
            if (inner[0] == 1)
            {
                var m = JsonSerializer.Deserialize<ControlMsg>(inner.AsSpan(1), SignedCommand.Json);
                if (m?.T == "end") return false;
                if (m?.T == "sas") { Sas.Send(); return true; }
            }
            await PipeFrames.Write(pipe, inner, ct);
            return true;
        }, ct);
        await Task.WhenAny(fromHelper, fromBrowser);
        try { await PipeFrames.Write(pipe, Control(new { t = "end" }), CancellationToken.None); } catch (IOException) { }
        if (!helper.WaitForExit(5000)) try { helper.Kill(); } catch (InvalidOperationException) { }
    }
}

/// <summary>Length-prefixed messages on the helper pipe.</summary>
public static class PipeFrames
{
    public const int Max = 8 << 20;

    public static async Task<byte[]?> Read(Stream s, CancellationToken ct)
    {
        var len = new byte[4];
        if (!await Fill(s, len, ct)) return null;
        int n = BitConverter.ToInt32(len);
        if (n <= 0 || n > Max) return null;
        var data = new byte[n];
        return await Fill(s, data, ct) ? data : null;
    }

    private static async Task<bool> Fill(Stream s, byte[] buffer, CancellationToken ct)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await s.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) return false;
            read += n;
        }
        return true;
    }

    private static readonly SemaphoreSlim WriteLock = new(1, 1);

    public static async Task Write(Stream s, byte[] data, CancellationToken ct)
    {
        await WriteLock.WaitAsync(ct);
        try
        {
            await s.WriteAsync(BitConverter.GetBytes(data.Length), ct);
            await s.WriteAsync(data, ct);
            await s.FlushAsync(ct);
        }
        finally { WriteLock.Release(); }
    }
}

/// <summary>Starts the screen helper in the session at the screen, as SYSTEM.</summary>
public static class HelperProcess
{
    public static Process StartInConsoleSession(string exe, string args)
    {
        uint session = WTSGetActiveConsoleSessionId();
        if (session == 0xFFFFFFFF) throw new InvalidOperationException("Nobody is at this PC's screen.");
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0002 | 0x0008 | 0x0001 | 0x0080 | 0x0100, out var token))   // DUPLICATE|QUERY|ASSIGN_PRIMARY|ADJUST_DEFAULT|ADJUST_SESSIONID
            throw new InvalidOperationException("Couldn't read the service's rights.");
        IntPtr dup = IntPtr.Zero;
        try
        {
            if (!DuplicateTokenEx(token, 0x02000000, IntPtr.Zero, 2, 1, out dup))   // MAXIMUM_ALLOWED, SecurityImpersonation, TokenPrimary
                throw new InvalidOperationException("Couldn't prepare the helper.");
            if (!SetTokenInformation(dup, 12, ref session, sizeof(uint)))   // TokenSessionId
                throw new InvalidOperationException("Couldn't move the helper to the screen's session.");
            var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = "winsta0\\default" };
            var cmd = new StringBuilder($"\"{exe}\" {args}");
            if (!CreateProcessAsUser(dup, exe, cmd, IntPtr.Zero, IntPtr.Zero, false, 0x08000000 | 0x00000400, IntPtr.Zero, Path.GetDirectoryName(exe), ref si, out var pi))   // CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT
                throw new InvalidOperationException("The screen helper didn't start (error " + Marshal.GetLastWin32Error() + ").");
            CloseHandle(pi.hThread);
            var p = Process.GetProcessById(pi.dwProcessId);
            CloseHandle(pi.hProcess);
            return p;
        }
        finally
        {
            CloseHandle(token);
            if (dup != IntPtr.Zero) CloseHandle(dup);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb; public string? lpReserved; public string? lpDesktop; public string? lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool DuplicateTokenEx(IntPtr token, uint access, IntPtr attrs, int level, int type, out IntPtr newToken);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetTokenInformation(IntPtr token, int cls, ref uint info, int length);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessAsUser(IntPtr token, string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string? dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);
}

/// <summary>Ctrl+Alt+Del for a remote desktop session (works when Windows allows services to send it).</summary>
public static class Sas
{
    public static void Send()
    {
        try { SendSAS(false); } catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException) { }
    }

    [DllImport("sas.dll")] private static extern void SendSAS(bool asUser);
}
