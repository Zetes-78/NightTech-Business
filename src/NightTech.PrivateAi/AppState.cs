using System.Diagnostics;
using System.Reflection;
using System.Text;
using NightTech.Business.Core.PrivateAi;

namespace NightTech.PrivateAi;

/// <summary>Everything the server shares between requests.</summary>
public sealed class AppState
{
    public static string Version =>
        Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "0.0.0";

    public AiSettings Settings { get; }
    public string SettingsPath { get; }
    public UserStore Users { get; }
    public Library Library { get; }
    public ChatStore Chats { get; }
    public ServerLog Log { get; }
    public string DataDir { get; }
    public OllamaClient Ollama { get; private set; }
    public SignInLimiter Limiter { get; } = new();
    public SignInLimiter ComputerLimiter { get; } = new(20);
    /// <summary>The AI answers one question at a time per person, and a couple at once overall, so nobody's answer stalls.</summary>
    public SemaphoreSlim Generating { get; } = new(2, 2);
    public HashSet<string> Busy { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Only one document is added at a time, so the library file stays consistent and the computer stays responsive.</summary>
    public SemaphoreSlim Indexing { get; } = new(1, 1);

    public AppState(AiSettings settings, string settingsPath, UserStore users, Library library, ChatStore chats, ServerLog log, string dataDir)
    {
        Settings = settings; SettingsPath = settingsPath; Users = users; Library = library; Chats = chats; Log = log; DataDir = dataDir;
        Ollama = new OllamaClient(settings.OllamaUrl);
    }

    private readonly object _settingsGate = new();
    public void SaveSettings() { lock (_settingsGate) Settings.Save(SettingsPath); }
}

/// <summary>A small daily log file in the data folder's logs folder. No chat text is ever written to it.</summary>
public sealed class ServerLog
{
    private readonly string _folder;
    private readonly object _gate = new();
    public ServerLog(string folder) { _folder = folder; Directory.CreateDirectory(folder); }

    public void Info(string m) => Write("INFO", m);
    public void Warn(string m) => Write("WARN", m);
    public void Error(string m, Exception? ex = null) => Write("ERROR", ex is null ? m : $"{m} {ex.GetType().Name}: {ex.Message}");

    private void Write(string level, string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} {level} {message}";
        Console.WriteLine(line);
        lock (_gate)
        {
            try
            {
                File.AppendAllText(Path.Combine(_folder, $"privateai-{DateTime.Now:yyyyMMdd}.log"), line + Environment.NewLine, Encoding.UTF8);
                foreach (var old in Directory.GetFiles(_folder, "privateai-*.log").OrderByDescending(f => f).Skip(30)) File.Delete(old);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}

/// <summary>
/// Keeps Ollama running. If it isn't answering and we know where ollama.exe is, start "ollama serve" ourselves, listening
/// only on this computer and using the shared models folder. This is what lets the AI work at an office PC nobody is signed in to.
/// </summary>
public sealed class OllamaKeeper : BackgroundService
{
    private readonly AppState _s;
    private Process? _child;
    public OllamaKeeper(AppState s) => _s = s;

    protected override async Task ExecuteAsync(CancellationToken stop)
    {
        var wait = TimeSpan.FromSeconds(5);
        while (!stop.IsCancellationRequested)
        {
            if (await _s.Ollama.VersionAsync(stop) is null)
            {
                var exe = _s.Settings.OllamaExe;
                if (exe.Length > 0 && File.Exists(exe) && (_child is null || _child.HasExited))
                {
                    try
                    {
                        var psi = new ProcessStartInfo(exe, "serve") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                        psi.Environment["OLLAMA_HOST"] = "127.0.0.1:11434";
                        if (_s.Settings.ModelsFolder.Length > 0) psi.Environment["OLLAMA_MODELS"] = _s.Settings.ModelsFolder;
                        _child = Process.Start(psi);
                        if (_child is not null)
                        {
                            _child.OutputDataReceived += (_, _) => { };
                            _child.ErrorDataReceived += (_, _) => { };
                            _child.BeginOutputReadLine();
                            _child.BeginErrorReadLine();
                        }
                        _s.Log.Info("Started the AI engine (ollama serve).");
                    }
                    catch (Exception ex) { _s.Log.Error("Couldn't start the AI engine.", ex); }
                }
                wait = TimeSpan.FromSeconds(Math.Min(60, wait.TotalSeconds * 2));
            }
            else wait = TimeSpan.FromSeconds(30);
            try { await Task.Delay(wait, stop); } catch (TaskCanceledException) { }
        }
    }

    public override async Task StopAsync(CancellationToken ct)
    {
        await base.StopAsync(ct);
        try { if (_child is { HasExited: false }) _child.Kill(true); } catch (InvalidOperationException) { }
    }
}

/// <summary>Jobs the setup tool runs from the command line. Passwords come in on standard input, never as arguments.</summary>
public static class Cli
{
    public static string? Option(string[] args, string name)
    {
        int i = Array.IndexOf(args, name);
        return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
    }

    public static async Task<int> Run(string[] args, UserStore users, AiSettings settings, string dataDir)
    {
        try
        {
            switch (args[0])
            {
                case "add-user":
                {
                    if (args.Length < 2) throw new ArgumentException("Usage: add-user <name> [--admin] [--display \"Full Name\"] (password on standard input)");
                    var pw = (await Console.In.ReadLineAsync()) ?? "";
                    users.Add(args[1], Option(args, "--display") ?? args[1], pw, args.Contains("--admin"), DateTime.Now);
                    Console.WriteLine($"Added {args[1]}.");
                    return 0;
                }
                case "set-password":
                {
                    if (args.Length < 2) throw new ArgumentException("Usage: set-password <name> (password on standard input)");
                    users.SetPassword(args[1], (await Console.In.ReadLineAsync()) ?? "");
                    Console.WriteLine($"Password changed for {args[1]}.");
                    return 0;
                }
                case "status":
                {
                    var ollama = new OllamaClient(settings.OllamaUrl);
                    var v = await ollama.VersionAsync();
                    Console.WriteLine($"Night Tech Private AI {AppState.Version}");
                    Console.WriteLine($"Data folder: {dataDir}");
                    Console.WriteLine($"Company: {settings.CompanyName}  Port: {settings.Port}  Model: {settings.ChatModel}");
                    Console.WriteLine($"Users: {users.All.Count} ({users.All.Count(u => u.IsAdmin)} admin)");
                    Console.WriteLine($"AI engine: {(v is null ? "not running" : "running, version " + v)}");
                    return v is null ? 1 : 0;
                }
                default:
                    Console.Error.WriteLine("Commands: add-user, set-password, status. Or start the server with no command.");
                    return 64;
            }
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }
}
