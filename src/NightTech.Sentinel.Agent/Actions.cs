using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Text;
using System.Text.Json;
using NightTech.Business.Core.Sentinel;
using NightTech.Shield.Windows;
using ShieldCore = NightTech.Shield.Core;

namespace NightTech.Sentinel.Agent;

/// <summary>The connection to the Sentinel icon in the signed-in person's taskbar.</summary>
public interface IPersonAtPc
{
    /// <summary>Asks the person at the PC to allow a command. False if they say no, nobody answers, or nobody is signed in.</summary>
    Task<bool> Ask(Command c, TimeSpan wait, CancellationToken ct);
    Task Tell(string title, string message, CancellationToken ct);
}

/// <summary>Carries out commands that passed the signature and policy checks.</summary>
public sealed class Actions
{
    private readonly IPersonAtPc _person;
    private readonly AgentLog _log;
    private readonly Func<AgentConfig> _config;
    private readonly Action<AgentConfig> _save;

    public Actions(IPersonAtPc person, AgentLog log, Func<AgentConfig> config, Action<AgentConfig> save)
    {
        _person = person; _log = log; _config = config; _save = save;
    }

    /// <summary>Set by the check-in loop: a fresh Shield scan for the next report.</summary>
    public ShieldCore.ScanResult? LastShield { get; private set; }
    public bool CheckInSoon { get; set; }

    public static ShieldCore.ScanResult ShieldScan(string version)
    {
        var user = TargetUser.Find();
        var facts = Collector.Collect(user, new Progress<string>(_ => { }));
        return new ShieldCore.ScanResult { ToolVersion = version, Facts = facts, Findings = ShieldCore.Rules.Evaluate(facts, DateTime.UtcNow) };
    }

    public async Task<CommandResult> Run(Command c, string version, CancellationToken ct)
    {
        var result = new CommandResult { CommandId = c.Id, Kind = c.Kind };
        var cfg = _config();
        var decision = cfg.Policy.Decide(c.Kind);
        _log.Info($"{c.Tech} asked to {CommandWords.Describe(c)} (command {c.Id}). Policy: {decision}.");
        try
        {
            if (decision == Decision.Refuse)
                return Done(result, "Refused", "This PC's Sentinel settings don't allow that.");
            if (decision == Decision.AskFirst && !await _person.Ask(c, TimeSpan.FromMinutes(3), ct))
                return Done(result, "Declined", "The person at the PC didn't allow it (or nobody was there to answer).");

            switch (c.Kind)
            {
                case CommandKind.RefreshNow:
                    CheckInSoon = true;
                    return Done(result, "Done", "");
                case CommandKind.ShieldScan:
                    LastShield = await Task.Run(() => ShieldScan(version), ct);
                    CheckInSoon = true;
                    return Done(result, "Done", ShieldCore.Report.Summary(LastShield));
                case CommandKind.ShieldFix:
                    return await ShieldFix(c, result, version, ct);
                case CommandKind.DefenderUpdate:
                    return FromRun(result, await Defender.UpdateDefinitions(ct), "Definitions updated.");
                case CommandKind.DefenderQuickScan:
                    return FromScan(result, await Defender.Scan(full: false, ct));
                case CommandKind.DefenderFullScan:
                    return FromScan(result, await Defender.Scan(full: true, ct));
                case CommandKind.InstallUpdates:
                    return Done(result, "Done", await Task.Run(InstallUpdates, ct));
                case CommandKind.CleanTemp:
                    return Done(result, "Done", await Task.Run(CleanTemp, ct));
                case CommandKind.CollectLogs:
                    result.Output = CommandResult.Trim(await Task.Run(CollectLogs, ct));
                    return Done(result, "Done", "Error logs from the last 7 days are attached.");
                case CommandKind.Restart:
                    return Restart(c, result);
                case CommandKind.ShowMessage:
                    await _person.Tell(c.Arg("title").Length > 0 ? c.Arg("title") : "Message from Night Tech Solutions", c.Arg("message"), ct);
                    return Done(result, "Done", "Shown.");
                case CommandKind.RunScript:
                    return await RunScript(c, result, ct);
                case CommandKind.UpdateTrustedKeys:
                    return UpdateKeys(c, result);
                case CommandKind.RemoteShell:
                case CommandKind.RemoteDesktop:
                    return await Sessions.Start(c, result, ct);
                default:
                    return Done(result, "Refused", "Sentinel on this PC doesn't know that command.");
            }
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception e)
        {
            _log.Warn($"Command {c.Id} failed: {e.Message}");
            return Done(result, "Failed", e.Message);
        }
    }

    /// <summary>Remote shell and desktop sessions (set by the service once the live connection is up).</summary>
    public ISessions Sessions { get; set; } = new NoSessions();

    private CommandResult Done(CommandResult r, string outcome, string detail)
    {
        r.Outcome = outcome;
        r.Detail = detail.Length > 2000 ? detail[..2000] : detail;
        r.FinishedUtc = DateTime.UtcNow;
        _log.Info($"Command {r.CommandId} ({r.Kind}): {outcome}. {detail}");
        return r;
    }

    private CommandResult FromRun(CommandResult r, Defender.RunResult run, string ok) =>
        run.ExitCode == 0 ? Done(r, "Done", ok) : Done(r, "Failed", run.TimedOut ? "Took too long." : $"Defender said: {Last(run.Output)}");

    private CommandResult FromScan(CommandResult r, Defender.RunResult run)
    {
        CheckInSoon = true;
        return run.ExitCode switch
        {
            0 => Done(r, "Done", "Nothing found."),
            2 => Done(r, "Done", "Defender found something. It's in the next Shield check."),
            _ => Done(r, "Failed", run.TimedOut ? "Took too long." : Last(run.Output)),
        };
    }

    private static string Last(string output) => output.Split('\n', StringSplitOptions.RemoveEmptyEntries).LastOrDefault()?.Trim() ?? "";

    // ---------------- Shield fixes ----------------

    /// <summary>Fixes Shield can make with nobody at the screen. Uninstallers and browser resets need the person (or a remote desktop session).</summary>
    private static readonly ShieldCore.FixKind[] RemoteFixes =
    {
        ShieldCore.FixKind.TurnOnRealTime, ShieldCore.FixKind.UpdateDefinitions, ShieldCore.FixKind.QuickScan, ShieldCore.FixKind.RemoveThreats,
        ShieldCore.FixKind.DisableStartup, ShieldCore.FixKind.RemovePolicy, ShieldCore.FixKind.CleanHosts, ShieldCore.FixKind.TurnOffProxy,
    };

    private async Task<CommandResult> ShieldFix(Command c, CommandResult result, string version, CancellationToken ct)
    {
        var ids = c.Arg("ids").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToHashSet();
        if (ids.Count == 0) return Done(result, "Failed", "No findings were chosen.");
        var scan = await Task.Run(() => ShieldScan(version), ct);
        var fixer = new Fixer(TargetUser.Find());
        var sb = new StringBuilder();
        int ok = 0, skipped = 0, failed = 0;
        foreach (var f in scan.Findings.Where(f => ids.Contains(f.Id)))
        {
            if (!RemoteFixes.Contains(f.Fix)) { skipped++; sb.AppendLine($"Skipped (needs the person at the PC or a remote desktop session): {f.Title}"); continue; }
            try { sb.AppendLine($"{f.Title}: {await fixer.Apply(f, ct)}"); ok++; }
            catch (Exception e) when (e is not OperationCanceledException) { failed++; sb.AppendLine($"{f.Title}: not fixed ({e.Message})"); }
        }
        int gone = ids.Count - scan.Findings.Count(f => ids.Contains(f.Id));
        if (gone > 0) sb.AppendLine($"{gone} of the chosen items weren't found any more.");
        LastShield = await Task.Run(() => ShieldScan(version), ct);
        CheckInSoon = true;
        result.Output = CommandResult.Trim(sb.ToString());
        return Done(result, failed == 0 ? "Done" : "Failed", $"{ok} fixed, {skipped} need the person at the PC, {failed} failed.");
    }

    // ---------------- Windows updates ----------------

    private static string InstallUpdates()
    {
        dynamic session = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.Session")
                                                   ?? throw new InvalidOperationException("Windows Update isn't available."))!;
        session.ClientApplicationID = "Night Tech Sentinel";
        dynamic searcher = session.CreateUpdateSearcher();
        dynamic found = searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0");
        int count = found.Updates.Count;
        if (count == 0) return "Windows is up to date.";
        dynamic list = Activator.CreateInstance(Type.GetTypeFromProgID("Microsoft.Update.UpdateColl")!)!;
        var names = new List<string>();
        for (int i = 0; i < count; i++)
        {
            dynamic u = found.Updates.Item(i);
            if (!(bool)u.EulaAccepted) u.AcceptEula();
            list.Add(u);
            names.Add((string)u.Title);
        }
        dynamic downloader = session.CreateUpdateDownloader();
        downloader.Updates = list;
        downloader.Download();
        dynamic installer = session.CreateUpdateInstaller();
        installer.Updates = list;
        dynamic res = installer.Install();
        int code = res.ResultCode;   // 2 = succeeded, 3 = succeeded with errors, 4 = failed
        bool reboot = res.RebootRequired;
        string outcome = code switch { 2 => "Installed", 3 => "Installed with some errors", 4 => "Failed to install", _ => "Finished" };
        return $"{outcome}: {count} update{(count == 1 ? "" : "s")} ({string.Join("; ", names.Take(8))}{(count > 8 ? "; ..." : "")}).{(reboot ? " A restart is needed." : "")}";
    }

    // ---------------- Temporary files ----------------

    private static string CleanTemp()
    {
        var user = TargetUser.Find();
        var folders = new[] { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"), Path.Combine(user.Local, "Temp") };
        long freed = 0; int files = 0, skipped = 0;
        var cutoff = DateTime.UtcNow.AddDays(-2);
        var options = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.System };
        foreach (var folder in folders.Where(Directory.Exists))
        {
            if ((new DirectoryInfo(folder).Attributes & FileAttributes.ReparsePoint) != 0) continue;
            foreach (var path in Directory.EnumerateFiles(folder, "*", options))
            {
                try
                {
                    var fi = new FileInfo(path);
                    if (fi.LastWriteTimeUtc > cutoff || fi.Name.StartsWith("NightTech", StringComparison.OrdinalIgnoreCase)) continue;
                    long len = fi.Length;
                    fi.Delete();
                    freed += len; files++;
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { skipped++; }
            }
        }
        return $"Cleared {files:N0} temporary file{(files == 1 ? "" : "s")} ({Business.Core.Format.Bytes(freed)}). {skipped:N0} in use were left alone.";
    }

    // ---------------- Logs ----------------

    private static string CollectLogs()
    {
        var sb = new StringBuilder();
        long since = (long)TimeSpan.FromDays(7).TotalMilliseconds;
        foreach (var log in new[] { "System", "Application" })
        {
            sb.AppendLine($"===== {log}: errors and critical events, last 7 days =====");
            var q = new EventLogQuery(log, PathType.LogName, $"*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= {since}]]]") { ReverseDirection = true };
            using var reader = new EventLogReader(q);
            int n = 0;
            for (var e = reader.ReadEvent(); e is not null && n < 150; e = reader.ReadEvent(), n++)
                using (e)
                {
                    string msg;
                    try { msg = e.FormatDescription() ?? ""; } catch (EventLogException) { msg = ""; }
                    sb.AppendLine($"{e.TimeCreated:yyyy-MM-dd HH:mm}  {e.ProviderName} {e.Id}  {msg.Replace("\r", " ").Replace("\n", " ").Trim()}");
                }
        }
        return sb.ToString();
    }

    // ---------------- Restart ----------------

    private CommandResult Restart(Command c, CommandResult result)
    {
        int minutes = int.TryParse(c.Arg("minutes"), out var m) ? Math.Clamp(m, 1, 60) : 5;
        var shutdown = Path.Combine(Environment.SystemDirectory, "shutdown.exe");
        var msg = $"Night Tech Solutions will restart this PC in {minutes} minute{(minutes == 1 ? "" : "s")}. Please save your work.";
        using var p = Process.Start(new ProcessStartInfo(shutdown, $"/r /t {minutes * 60} /d p:4:1 /c \"{msg}\"") { UseShellExecute = false, CreateNoWindow = true });
        p?.WaitForExit(10000);
        return p?.ExitCode == 0 ? Done(result, "Done", $"Restarting in {minutes} minutes.") : Done(result, "Failed", "Windows didn't start the restart.");
    }

    // ---------------- Scripts ----------------

    private async Task<CommandResult> RunScript(Command c, CommandResult result, CancellationToken ct)
    {
        var script = c.Arg("script");
        if (script.Length == 0) return Done(result, "Failed", "The script was empty.");
        int minutes = int.TryParse(c.Arg("minutes"), out var m) ? Math.Clamp(m, 1, 60) : 10;
        _log.Info($"Running script \"{c.Arg("name")}\" for {c.Tech}:\n{(script.Length > 4000 ? script[..4000] + "..." : script)}");
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes("$ProgressPreference='SilentlyContinue'\n" + script));
        var ps = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        var run = await Defender.Run(ps, $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {encoded}", TimeSpan.FromMinutes(minutes), ct);
        result.Output = CommandResult.Trim(run.Output);
        return run.TimedOut ? Done(result, "TimedOut", $"Stopped after {minutes} minutes.")
            : Done(result, run.ExitCode == 0 ? "Done" : "Failed", $"Exit code {run.ExitCode}.");
    }

    // ---------------- Trusted keys ----------------

    private CommandResult UpdateKeys(Command c, CommandResult result)
    {
        List<TrustedKey>? keys;
        try { keys = JsonSerializer.Deserialize<List<TrustedKey>>(c.Arg("keys"), SignedCommand.Json); }
        catch (JsonException) { return Done(result, "Failed", "The key list wasn't readable."); }
        if (keys is null || keys.Count is 0 or > 10) return Done(result, "Failed", "Between 1 and 10 keys are needed.");
        foreach (var k in keys)
        {
            string id;
            try { id = SentinelCrypto.KeyId(k.PublicKey); }
            catch (Exception e) when (e is FormatException or ArgumentNullException) { return Done(result, "Failed", "A key wasn't readable."); }
            if (id != k.KeyId) return Done(result, "Failed", "A key's ID doesn't match it.");
        }
        var cfg = _config();
        cfg.TrustedKeys = keys;
        _save(cfg);
        return Done(result, "Done", $"This PC now trusts: {string.Join(", ", keys.Select(k => $"{k.Tech} ({SentinelCrypto.Readable(k.KeyId)[..9]})"))}.");
    }
}

/// <summary>Remote shell and remote desktop.</summary>
public interface ISessions
{
    Task<CommandResult> Start(Command c, CommandResult result, CancellationToken ct);
}

public sealed class NoSessions : ISessions
{
    public Task<CommandResult> Start(Command c, CommandResult result, CancellationToken ct)
    {
        result.Outcome = "Failed";
        result.Detail = "Sentinel isn't connected live to the server right now.";
        result.FinishedUtc = DateTime.UtcNow;
        return Task.FromResult(result);
    }
}

/// <summary>Sentinel's own entries in the Windows Application log, so what it did is on record at the PC too.</summary>
public sealed class AgentLog
{
    public const string Source = "Night Tech Sentinel";
    private readonly bool _ok;

    public AgentLog()
    {
        try
        {
            if (!EventLog.SourceExists(Source)) EventLog.CreateEventSource(Source, "Application");
            _ok = true;
        }
        catch (Exception e) when (e is System.Security.SecurityException or InvalidOperationException or ArgumentException) { _ok = false; }
    }

    public void Info(string m) => Write(m, EventLogEntryType.Information, 1000);
    public void Warn(string m) => Write(m, EventLogEntryType.Warning, 2000);

    private void Write(string m, EventLogEntryType type, int id)
    {
        if (!_ok) return;
        try { EventLog.WriteEntry(Source, m.Length > 30000 ? m[..30000] : m, type, id); }
        catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }
}
