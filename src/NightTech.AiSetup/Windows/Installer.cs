using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using NightTech.Business.Core.PrivateAi;

namespace NightTech.AiSetup.Windows;

public static class Paths
{
    public const string TaskName = "Night Tech Private AI";
    public const string FirewallRule = "Night Tech Private AI";
    public const string OllamaDownload = "https://ollama.com/download/OllamaSetup.exe";

    public static string InstallDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Night Tech", "Private AI");
    public static string ServerExe => Path.Combine(InstallDir, "NightTechPrivateAi.exe");
    public static string DataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Night Tech Private AI");
    public static string ModelsDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Night Tech Private AI Models");
    public static string OllamaDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Ollama");
    public static string BundledServer => Path.Combine(AppContext.BaseDirectory, "server");

    /// <summary>Downloads go to a folder only administrators can change.</summary>
    public static string DownloadDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Night Tech", "Downloads");

    /// <summary>
    /// Only the copy under Program Files is used: Private AI starts it as Windows itself (SYSTEM), so it must be somewhere
    /// ordinary users can't change. A personal copy in a user's folder is never used.
    /// </summary>
    public static string? FindOllama()
    {
        var exe = Path.Combine(OllamaDir, "ollama.exe");
        return File.Exists(exe) ? exe : null;
    }

    public static bool PersonalOllamaExists =>
        File.Exists(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "Ollama", "ollama.exe"));
}

public sealed record SetupOptions(
    string Customer, string Ticket, string Technician,
    string AdminUser, string AdminDisplay, string AdminPassword,
    string Model, int Port);

public sealed record StepUpdate(int Index, StepResult Result, string Detail);
public sealed record Transfer(string What, double Percent, string Detail);

/// <summary>Installs and configures Private AI, one step at a time. Steps that are already done are recognized and skipped.</summary>
public sealed class Installer
{
    public static readonly string[] StepNames =
    {
        "Get the AI engine (Ollama) ready",
        "Download the AI model",
        "Download the document search model",
        "Install Night Tech Private AI",
        "Save settings and protect the data folder",
        "Create the administrator account",
        "Start Private AI with Windows",
        "Allow this network only (firewall)",
        "Check that it works",
    };

    private readonly SetupOptions _o;
    private readonly IProgress<StepUpdate> _steps;
    private readonly IProgress<Transfer> _transfer;
    private readonly OllamaClient _ollama = new();
    public AiSetupReport Report { get; }
    public int Port { get; private set; }

    public Installer(SetupOptions o, AiSetupReport report, IProgress<StepUpdate> steps, IProgress<Transfer> transfer)
    {
        _o = o; Report = report; _steps = steps; _transfer = transfer;
        Port = o.Port;
        Report.Steps = StepNames.Select(n => new SetupStep { Name = n, Result = StepResult.Pending }).ToList();
    }

    private void Set(int i, StepResult r, string detail = "")
    {
        Report.Steps[i].Result = r;
        Report.Steps[i].Detail = detail;
        _steps.Report(new StepUpdate(i, r, detail));
        if (r is StepResult.Done or StepResult.Warning or StepResult.Failed or StepResult.Skipped)
            App.Log.Info($"Step {i + 1} '{StepNames[i]}': {r}{(detail.Length > 0 ? " - " + detail : "")}");
    }

    public async Task<bool> RunAsync(CancellationToken ct)
    {
        var steps = new Func<CancellationToken, Task<(StepResult, string)>>[]
        {
            EngineAsync, ct2 => PullAsync(_o.Model, ct2), ct2 => PullAsync(ModelCatalog.DocumentSearch.Tag, ct2),
            InstallServerAsync, SettingsAsync, AdminAsync, StartupTaskAsync, FirewallAsync, VerifyAsync,
        };
        for (int i = 0; i < steps.Length; i++)
        {
            ct.ThrowIfCancellationRequested();
            Set(i, StepResult.Running);
            try
            {
                var (r, d) = await steps[i](ct);
                Set(i, r, d);
                if (r == StepResult.Failed) { SkipRest(i + 1); return false; }
            }
            catch (OperationCanceledException) { Set(i, StepResult.Failed, "Stopped."); SkipRest(i + 1); throw; }
            catch (Exception ex)
            {
                App.Log.Error($"Step {i + 1} failed.", ex);
                Set(i, StepResult.Failed, ex.Message);
                SkipRest(i + 1);
                return false;
            }
        }
        return true;
    }

    private void SkipRest(int from)
    {
        for (int j = from; j < StepNames.Length; j++) Set(j, StepResult.Skipped, "Not done because an earlier step didn't finish.");
    }

    // ---------------- 1. The AI engine ----------------

    private async Task<(StepResult, string)> EngineAsync(CancellationToken ct)
    {
        string note = "";
        var exe = Paths.FindOllama();
        Directory.CreateDirectory(Paths.ModelsDir);
        // One models folder for the whole computer. Only administrators and Windows can change it; everyone can read it.
        var acl = Proc.Run(Proc.Sys("icacls.exe"), $"\"{Paths.ModelsDir}\" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F /grant:r *S-1-5-32-544:(OI)(CI)F /grant:r *S-1-5-32-545:(OI)(CI)RX", TimeSpan.FromMinutes(2));
        if (acl.ExitCode != 0) App.Log.Warn("Couldn't set the models folder permissions: " + acl.Output.Trim());
        Environment.SetEnvironmentVariable("OLLAMA_MODELS", Paths.ModelsDir, EnvironmentVariableTarget.Machine);
        Environment.SetEnvironmentVariable("OLLAMA_MODELS", Paths.ModelsDir, EnvironmentVariableTarget.Process);

        if (exe is null)
        {
            Directory.CreateDirectory(Paths.DownloadDir);
            var file = Path.Combine(Paths.DownloadDir, "OllamaSetup.exe");
            await DownloadAsync(Paths.OllamaDownload, file, "Downloading the AI engine", ct);
            ProcResult r;
            // Keep the file open (others may read, nobody may write) from the signature check until it has run.
            using (var hold = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                if (!Trust.IsSignedBy(file, "Ollama", out var signer))
                {
                    hold.Dispose();
                    File.Delete(file);
                    return (StepResult.Failed, $"The downloaded installer isn't signed by Ollama ({signer}), so it wasn't run.");
                }
                App.Log.Info($"AI engine installer signed by {signer}.");
                _transfer.Report(new Transfer("Installing the AI engine", -1, "This takes a minute or two."));
                r = await Task.Run(() => Proc.RunPlain(file, $"/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /DIR=\"{Paths.OllamaDir}\"",
                    TimeSpan.FromMinutes(15), new Dictionary<string, string> { ["OLLAMA_MODELS"] = Paths.ModelsDir }), ct);
            }
            try { File.Delete(file); } catch (IOException) { }
            exe = Paths.FindOllama();
            if (exe is null) return (StepResult.Failed, $"The AI engine installer finished (code {r.ExitCode}) but {Path.Combine(Paths.OllamaDir, "ollama.exe")} wasn't found.");
            note = Paths.PersonalOllamaExists ? "Installed a protected copy for Private AI (the personal copy already on this PC isn't used). " : "Installed. ";
        }
        else note = "Already installed. ";

        // Ollama's own tray app would start a second engine at sign-in; Private AI keeps its own running instead.
        try
        {
            var startup = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Ollama.lnk");
            if (File.Exists(startup)) { File.Delete(startup); note += "Turned off Ollama's own start-at-sign-in. "; }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }

        // Restart the engine so it uses the shared models folder.
        foreach (var name in new[] { "ollama app", "ollama" })
            foreach (var p in Process.GetProcessesByName(name))
                try { p.Kill(true); p.WaitForExit(5000); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        await Task.Delay(1000, ct);
        var psi = new ProcessStartInfo(exe, "serve") { UseShellExecute = false, CreateNoWindow = true };
        psi.Environment["OLLAMA_MODELS"] = Paths.ModelsDir;
        psi.Environment["OLLAMA_HOST"] = "127.0.0.1:11434";
        Process.Start(psi);

        for (int i = 0; i < 60; i++)
        {
            if (await _ollama.VersionAsync(ct) is { } v)
            {
                Report.EngineVersion = "Ollama " + v;
                _engineExe = exe;
                return (StepResult.Done, $"{note}Running (version {v}).");
            }
            await Task.Delay(1000, ct);
        }
        return (StepResult.Failed, "The AI engine didn't start. Restart the computer and run setup again.");
    }

    private string _engineExe = "";

    private async Task DownloadAsync(string url, string file, string what, CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(30) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"NightTechAiSetup/{App.ToolVersion}");
        using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        long total = resp.Content.Headers.ContentLength ?? -1;
        await using var src = await resp.Content.ReadAsStreamAsync(ct);
        await using var dst = File.Create(file);
        var buf = new byte[1024 * 256];
        long done = 0;
        var sw = Stopwatch.StartNew();
        int n;
        while ((n = await src.ReadAsync(buf, ct)) > 0)
        {
            await dst.WriteAsync(buf.AsMemory(0, n), ct);
            done += n;
            if (sw.ElapsedMilliseconds > 250)
            {
                sw.Restart();
                _transfer.Report(new Transfer(what, total > 0 ? 100.0 * done / total : -1, $"{done / 1048576.0:0} MB{(total > 0 ? $" of {total / 1048576.0:0} MB" : "")}"));
            }
        }
    }

    // ---------------- 2-3. Models ----------------

    private async Task<(StepResult, string)> PullAsync(string tag, CancellationToken ct)
    {
        var installed = await _ollama.ModelsAsync(ct);
        var name = ModelCatalog.Find(tag)?.Name ?? tag;
        if (OllamaClient.Has(installed, tag)) return (StepResult.Done, $"{name} is already downloaded.");
        var sw = Stopwatch.StartNew();
        await _ollama.PullAsync(tag, new Progress<PullProgress>(p =>
        {
            if (sw.ElapsedMilliseconds < 250 && p.Total > 0 && p.Completed < p.Total) return;
            sw.Restart();
            _transfer.Report(new Transfer($"Downloading {name}", p.Total > 0 ? p.Percent : -1,
                p.Total > 0 ? $"{p.Completed / 1e9:0.00} GB of {p.Total / 1e9:0.00} GB" : p.Status));
        }), ct);
        return (StepResult.Done, $"{name} downloaded.");
    }

    // ---------------- 4. The Private AI program ----------------

    private async Task<(StepResult, string)> InstallServerAsync(CancellationToken ct)
    {
        if (!File.Exists(Path.Combine(Paths.BundledServer, "NightTechPrivateAi.exe")))
            return (StepResult.Failed, $"The Private AI program wasn't found next to this setup tool ({Paths.BundledServer}). Reinstall Night Tech AI Setup.");
        StopServer();
        var wasThere = File.Exists(Paths.ServerExe);
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                CopyFolder(Paths.BundledServer, Paths.InstallDir);
                break;
            }
            catch (IOException) when (attempt < 5) { await Task.Delay(2000, ct); StopServer(); }
        }
        Report.ServerVersion = "Night Tech Private AI " + (FileVersionInfo.GetVersionInfo(Paths.ServerExe).ProductVersion ?? "");
        Port = PickPort(_o.Port);
        Report.Port = Port;
        return (StepResult.Done, (wasThere ? "Updated in " : "Installed to ") + Paths.InstallDir + (Port != _o.Port ? $". Port {_o.Port} was in use, so it uses port {Port}." : ""));
    }

    private static void StopServer()
    {
        Proc.Run(Proc.Sys("schtasks.exe"), $"/End /TN \"{Paths.TaskName}\"", TimeSpan.FromSeconds(30));
        foreach (var p in Process.GetProcessesByName("NightTechPrivateAi"))
            try { p.Kill(true); p.WaitForExit(10000); } catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
    }

    private static void CopyFolder(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var dir in Directory.GetDirectories(from, "*", SearchOption.AllDirectories))
            Directory.CreateDirectory(Path.Combine(to, Path.GetRelativePath(from, dir)));
        foreach (var file in Directory.GetFiles(from, "*", SearchOption.AllDirectories))
            File.Copy(file, Path.Combine(to, Path.GetRelativePath(from, file)), true);
    }

    /// <summary>The chosen port, or the next free one if another program is using it (our own server was stopped above).</summary>
    private static int PickPort(int wanted)
    {
        var used = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(e => e.Port).ToHashSet();
        for (int p = wanted; p < wanted + 20; p++) if (!used.Contains(p)) return p;
        return wanted;
    }

    // ---------------- 5. Settings ----------------

    private Task<(StepResult, string)> SettingsAsync(CancellationToken ct)
    {
        Directory.CreateDirectory(Paths.DataDir);
        var path = Path.Combine(Paths.DataDir, "settings.json");
        var s = AiSettings.Load(path);
        if (!string.IsNullOrWhiteSpace(_o.Customer)) s.CompanyName = _o.Customer.Trim();
        s.Port = Port;
        s.ChatModel = _o.Model;
        s.SearchModel = ModelCatalog.DocumentSearch.Tag;
        s.OllamaExe = _engineExe.Length > 0 ? _engineExe : Paths.FindOllama() ?? "";
        s.ModelsFolder = Paths.ModelsDir;
        s.Ticket = _o.Ticket;
        s.InstalledBy = string.IsNullOrWhiteSpace(_o.Technician) ? "Night Tech Solutions" : $"{_o.Technician}, Night Tech Solutions";
        s.Save(path);
        // Only Windows itself and administrators can open the accounts, chats and documents.
        var acl = Proc.Run(Proc.Sys("icacls.exe"), $"\"{Paths.DataDir}\" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F /grant:r *S-1-5-32-544:(OI)(CI)F", TimeSpan.FromMinutes(2));
        return Task.FromResult(acl.ExitCode == 0
            ? (StepResult.Done, $"Saved. Data folder {Paths.DataDir} is limited to administrators.")
            : (StepResult.Warning, "Settings saved, but the data folder's permissions couldn't be tightened: " + acl.Output.Trim()));
    }

    // ---------------- 6. Administrator ----------------

    private Task<(StepResult, string)> AdminAsync(CancellationToken ct)
    {
        var users = new UserStore(Path.Combine(Paths.DataDir, "users.json"));
        Report.AdminUser = _o.AdminUser;
        if (users.Find(_o.AdminUser) is not null)
            return Task.FromResult((StepResult.Done, $"{_o.AdminUser} already exists; their password wasn't changed."));
        var args = $"add-user {_o.AdminUser} --admin --display \"{_o.AdminDisplay.Replace("\"", "")}\" --data \"{Paths.DataDir}\"";
        var r = Proc.Run(Paths.ServerExe, args, TimeSpan.FromMinutes(1), stdin: _o.AdminPassword);
        return Task.FromResult(r.ExitCode == 0
            ? (StepResult.Done, $"Administrator {_o.AdminUser} created.")
            : (StepResult.Failed, "Couldn't create the administrator: " + r.Output.Trim()));
    }

    // ---------------- 7. Startup task ----------------

    private Task<(StepResult, string)> StartupTaskAsync(CancellationToken ct)
    {
        var script = $@"
$a = New-ScheduledTaskAction -Execute {Proc.Ps(Paths.ServerExe)} -WorkingDirectory {Proc.Ps(Paths.InstallDir)}
$t = New-ScheduledTaskTrigger -AtStartup
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
# Also every 5 minutes: if Private AI ever stopped, it comes back (a copy already running is left alone).
$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration (New-TimeSpan -Days 3650)
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -Priority 4
Register-ScheduledTask -TaskName {Proc.Ps(Paths.TaskName)} -Description 'Night Tech Private AI: the private AI chat page for this network.' -Action $a -Trigger @($t, $t2) -Principal $p -Settings $s -Force | Out-Null
Start-ScheduledTask -TaskName {Proc.Ps(Paths.TaskName)}";
        var r = Proc.PowerShell(script, TimeSpan.FromMinutes(2));
        return Task.FromResult(r.ExitCode == 0
            ? (StepResult.Done, "Starts automatically when the computer starts, even before anyone signs in.")
            : (StepResult.Failed, "Couldn't create the startup task: " + r.Output.Trim()));
    }

    // ---------------- 8. Firewall ----------------

    private Task<(StepResult, string)> FirewallAsync(CancellationToken ct)
    {
        Proc.Run(Proc.Sys("netsh.exe"), $"advfirewall firewall delete rule name=\"{Paths.FirewallRule}\"", TimeSpan.FromSeconds(30));
        var r = Proc.Run(Proc.Sys("netsh.exe"),
            $"advfirewall firewall add rule name=\"{Paths.FirewallRule}\" dir=in action=allow protocol=TCP localport={Port} remoteip=localsubnet profile=private,domain program=\"{Paths.ServerExe}\" enable=yes",
            TimeSpan.FromSeconds(30));
        if (r.ExitCode != 0) return Task.FromResult((StepResult.Failed, "Couldn't add the firewall rule: " + r.Output.Trim()));

        var prof = Proc.PowerShell("(Get-NetConnectionProfile | ForEach-Object { $_.Name + ': ' + $_.NetworkCategory }) -join '; '", TimeSpan.FromSeconds(30));
        Report.NetworkProfile = prof.Output.Trim();
        if (prof.Output.Contains("Public", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult((StepResult.Warning,
                $"Allowed for the local network on port {Port}, but this computer's network is set to Public ({Report.NetworkProfile}). Other computers can't reach Private AI until it's set to Private: Settings > Network & internet > (the network) > Private network."));
        return Task.FromResult((StepResult.Done, $"Allowed on port {Port}, for this network only ({Report.NetworkProfile})."));
    }

    // ---------------- 9. Check ----------------

    private async Task<(StepResult, string)> VerifyAsync(CancellationToken ct)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        for (int i = 0; i < 45; i++)
        {
            try
            {
                var body = await http.GetStringAsync($"http://127.0.0.1:{Port}/api/me", ct);
                if (body.Contains("\"version\"", StringComparison.Ordinal))
                {
                    Report.Addresses = Addresses(Port);
                    return (StepResult.Done, "Private AI is answering.");
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) { }
            await Task.Delay(1000, ct);
        }
        return (StepResult.Failed, $"Private AI didn't answer on port {Port}. Check the log in {Path.Combine(Paths.DataDir, "logs")}.");
    }

    /// <summary>Addresses other computers on the network can use.</summary>
    public static List<string> Addresses(int port)
    {
        var list = new List<string> { $"http://{Environment.MachineName.ToLowerInvariant()}:{port}" };
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
                foreach (var a in ni.GetIPProperties().UnicastAddresses)
                    if (a.Address.AddressFamily == AddressFamily.InterNetwork && NetworkGuard.IsLocal(a.Address) && !IPAddress.IsLoopback(a.Address) && !a.Address.ToString().StartsWith("169.254.", StringComparison.Ordinal))
                        list.Add($"http://{a.Address}:{port}");
        }
        catch (NetworkInformationException) { }
        return list.Distinct().ToList();
    }

    // ---------------- Removal ----------------

    /// <summary>Removes Private AI: startup task, firewall rule and program. Accounts, chats and documents are kept unless asked.</summary>
    public static string Remove(bool deleteData)
    {
        var log = new List<string>();
        StopServer();
        var t = Proc.Run(Proc.Sys("schtasks.exe"), $"/Delete /TN \"{Paths.TaskName}\" /F", TimeSpan.FromSeconds(30));
        log.Add(t.ExitCode == 0 ? "Startup task removed." : "No startup task to remove.");
        Proc.Run(Proc.Sys("netsh.exe"), $"advfirewall firewall delete rule name=\"{Paths.FirewallRule}\"", TimeSpan.FromSeconds(30));
        log.Add("Firewall rule removed.");
        try { if (Directory.Exists(Paths.InstallDir)) Directory.Delete(Paths.InstallDir, true); log.Add("Program removed."); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Add("Couldn't remove the program folder: " + ex.Message); }
        if (deleteData)
        {
            try { if (Directory.Exists(Paths.DataDir)) Directory.Delete(Paths.DataDir, true); log.Add("Accounts, chats and documents deleted."); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { log.Add("Couldn't delete the data folder: " + ex.Message); }
        }
        else log.Add($"Accounts, chats and documents were kept in {Paths.DataDir}.");
        log.Add("The AI engine (Ollama) and downloaded models were left installed; remove Ollama from Windows Settings > Apps if it's no longer needed.");
        return string.Join("\n", log);
    }
}
