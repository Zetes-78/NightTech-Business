using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Agent;

/// <summary>A message between the Sentinel service and the taskbar icon, one JSON object per line.</summary>
public sealed class TrayMessage
{
    /// <summary>ask, answer, tell, status, help, session, hello.</summary>
    public string Type { get; set; } = "";
    public string Id { get; set; } = "";
    public string Title { get; set; } = "";
    public string Text { get; set; } = "";
    public bool Allow { get; set; }
    public bool Ok { get; set; }
    public bool Active { get; set; }
}

/// <summary>
/// The service's side of the connection to the taskbar icon. Only the real Sentinel tray program, running in the
/// session of the person at the screen, can connect: anything else is dropped.
/// </summary>
public sealed class TrayLink : IPersonAtPc, IDisposable
{
    public const string PipeName = "NightTechSentinel";
    private readonly AgentLog _log;
    private readonly ConcurrentDictionary<int, (StreamWriter Writer, uint Session)> _clients = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<bool>> _waiting = new();
    private readonly CancellationTokenSource _stop = new();
    private int _next;
    private string _status = "Starting";
    private bool _ok = true;

    /// <summary>A help request from the person at the PC, to send with the next check-in.</summary>
    public event Action<string>? HelpRequested;

    public TrayLink(AgentLog log) { _log = log; }

    public static string TrayPath => Path.Combine(AppContext.BaseDirectory, "NightTechSentinel.exe");

    public void Start() => _ = Task.Run(() => Listen(_stop.Token));

    private static PipeSecurity Security()
    {
        var ps = new PipeSecurity();
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
        ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
        return ps;
    }

    private async Task Listen(CancellationToken ct)
    {
        bool first = true;
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                // The first one must be new: if another program already made a pipe with this name, it's an impostor.
                var options = PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : PipeOptions.None);
                pipe = NamedPipeServerStreamAcl.Create(PipeName, PipeDirection.InOut, 8, PipeTransmissionMode.Byte, options, 4096, 4096, Security());
                first = false;
                await pipe.WaitForConnectionAsync(ct);
                var p = pipe;
                pipe = null;
                _ = Task.Run(() => Serve(p, ct), ct);
            }
            catch (OperationCanceledException) { pipe?.Dispose(); return; }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                pipe?.Dispose();
                _log.Warn((first ? "Another program is using Sentinel's connection name, so prompts can't be shown until it's gone. " : "Tray connection: ") + e.Message);
                await Task.Delay(first ? 30000 : 2000, ct);
            }
        }
    }

    private async Task Serve(NamedPipeServerStream pipe, CancellationToken ct)
    {
        int id = Interlocked.Increment(ref _next);
        using (pipe)
        {
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out uint pid) || !IsRealTray((int)pid, out uint session))
            {
                _log.Warn($"A program that isn't the Sentinel icon tried to connect (process {pid}). It was refused.");
                return;
            }
            var reader = new StreamReader(pipe, new UTF8Encoding(false));
            var writer = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };
            _clients[id] = (writer, session);
            try
            {
                await Send(writer, new TrayMessage { Type = "status", Text = _status, Ok = _ok });
                while (!ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(ct);
                    if (line is null) break;
                    if (line.Length > 16_384) continue;
                    TrayMessage? m;
                    try { m = JsonSerializer.Deserialize<TrayMessage>(line, SignedCommand.Json); } catch (JsonException) { continue; }
                    if (m is null) continue;
                    // Answers only count from the session at the screen.
                    if (m.Type == "answer" && session == WTSGetActiveConsoleSessionId() && _waiting.TryRemove(m.Id, out var tcs)) tcs.TrySetResult(m.Allow);
                    else if (m.Type == "help" && m.Text.Trim().Length > 0) HelpRequested?.Invoke(m.Text.Trim().Length > 1000 ? m.Text.Trim()[..1000] : m.Text.Trim());
                }
            }
            catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException) { }
            finally { _clients.TryRemove(id, out _); }
        }
    }

    /// <summary>The connecting program must be Sentinel's own tray program from Sentinel's (administrators-only) install folder.</summary>
    private static bool IsRealTray(int pid, out uint session)
    {
        session = 0;
        try
        {
            using var p = Process.GetProcessById(pid);
            session = (uint)p.SessionId;
            var path = p.MainModule?.FileName ?? "";
            return string.Equals(Path.GetFullPath(path), Path.GetFullPath(TrayPath), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { return false; }
    }

    private static Task Send(StreamWriter w, TrayMessage m) => w.WriteLineAsync(JsonSerializer.Serialize(m, SignedCommand.Json));

    private async Task<bool> SendToScreen(TrayMessage m)
    {
        uint console = WTSGetActiveConsoleSessionId();
        bool sent = false;
        foreach (var (_, c) in _clients.Where(c => c.Value.Session == console))
        {
            try { await Send(c.Writer, m); sent = true; }
            catch (Exception e) when (e is IOException or ObjectDisposedException) { }
        }
        return sent;
    }

    public void SetStatus(string text, bool ok)
    {
        _status = text;
        _ok = ok;
        _ = SendToScreen(new TrayMessage { Type = "status", Text = text, Ok = ok });
    }

    public Task SessionChanged(bool active, string text) => SendToScreen(new TrayMessage { Type = "session", Active = active, Text = text });

    public async Task<bool> Ask(Command c, TimeSpan wait, CancellationToken ct)
    {
        var id = Guid.NewGuid().ToString("N");
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _waiting[id] = tcs;
        try
        {
            if (!await SendToScreen(new TrayMessage { Type = "ask", Id = id, Title = "Night Tech Solutions is asking", Text = CommandWords.Prompt(c) }))
                return false;   // nobody signed in with the icon running: the answer is no
            var done = await Task.WhenAny(tcs.Task, Task.Delay(wait, ct));
            return done == tcs.Task && tcs.Task.Result;
        }
        finally { _waiting.TryRemove(id, out _); }
    }

    public async Task Tell(string title, string message, CancellationToken ct)
    {
        if (!await SendToScreen(new TrayMessage { Type = "tell", Title = title, Text = message }))
            throw new InvalidOperationException("Nobody is signed in with the Sentinel icon running.");
    }

    public void Dispose()
    {
        _stop.Cancel();
        _stop.Dispose();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();
}
