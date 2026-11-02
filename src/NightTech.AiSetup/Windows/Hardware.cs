using System.Diagnostics;
using System.Globalization;
using System.Management;
using Microsoft.Win32;
using NightTech.Business.Core.PrivateAi;

namespace NightTech.AiSetup.Windows;

/// <summary>Reads what the computer has: processor, memory, graphics cards (with their real memory size) and free disk.</summary>
public static class Hardware
{
    private const string DisplayClass = @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";

    public static HardwareProfile Read(string dataDrive)
    {
        string cpu = "Unknown processor";
        int cores = Environment.ProcessorCount;
        double ram = 0;
        try
        {
            using var cs = new ManagementObjectSearcher("SELECT TotalPhysicalMemory FROM Win32_ComputerSystem");
            foreach (ManagementObject o in cs.Get()) ram = Convert.ToDouble(o["TotalPhysicalMemory"], CultureInfo.InvariantCulture) / 1073741824.0;
            using var ps = new ManagementObjectSearcher("SELECT Name, NumberOfCores FROM Win32_Processor");
            int c = 0;
            foreach (ManagementObject o in ps.Get())
            {
                cpu = (o["Name"]?.ToString() ?? cpu).Trim();
                c += Convert.ToInt32(o["NumberOfCores"] ?? 0, CultureInfo.InvariantCulture);
            }
            if (c > 0) cores = c;
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        {
            App.Log.Warn("Couldn't read processor or memory: " + ex.Message);
        }

        double free = 0;
        try { free = new DriveInfo(dataDrive).AvailableFreeSpace / 1073741824.0; } catch (Exception ex) when (ex is IOException or ArgumentException) { }

        return new HardwareProfile(Environment.MachineName, cpu, cores, Math.Round(ram, 1), Gpus(), Math.Round(free), WindowsName());
    }

    /// <summary>Graphics cards from the driver registry (which, unlike WMI, reports memory over 4 GB correctly), corrected by nvidia-smi when present.</summary>
    public static List<GpuInfo> Gpus()
    {
        var list = new List<GpuInfo>();
        try
        {
            using var cls = Registry.LocalMachine.OpenSubKey(DisplayClass);
            if (cls is not null)
                foreach (var sub in cls.GetSubKeyNames().Where(n => n.Length == 4 && n.All(char.IsDigit)))
                {
                    using var k = cls.OpenSubKey(sub);
                    if (k is null) continue;
                    var name = k.GetValue("DriverDesc") as string;
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    double gb = Bytes(k.GetValue("HardwareInformation.qwMemorySize")) ?? Bytes(k.GetValue("HardwareInformation.MemorySize")) ?? 0;
                    gb /= 1073741824.0;
                    if (name.Contains("Basic Display", StringComparison.OrdinalIgnoreCase) || name.Contains("Remote", StringComparison.OrdinalIgnoreCase)) continue;
                    list.Add(new GpuInfo(name.Trim(), Math.Round(gb, 1), Vendor(name, k.GetValue("ProviderName") as string)));
                }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            App.Log.Warn("Couldn't read graphics cards from the registry: " + ex.Message);
        }

        // nvidia-smi knows the exact memory of NVIDIA cards.
        var smi = NvidiaSmi();
        if (smi.Count > 0)
        {
            list.RemoveAll(g => g.Vendor == "NVIDIA");
            list.AddRange(smi);
        }
        return list.GroupBy(g => g.Name + g.MemoryGb).Select(g => g.First()).ToList();
    }

    private static double? Bytes(object? v) => v switch
    {
        long l => l,
        int i => (uint)i,
        byte[] { Length: 8 } b => BitConverter.ToInt64(b, 0),
        byte[] { Length: 4 } b => BitConverter.ToUInt32(b, 0),
        _ => null,
    };

    private static string Vendor(string name, string? provider)
    {
        var s = (name + " " + provider).ToUpperInvariant();
        if (s.Contains("NVIDIA") || s.Contains("GEFORCE") || s.Contains("QUADRO") || s.Contains("RTX")) return "NVIDIA";
        if (s.Contains("AMD") || s.Contains("RADEON") || s.Contains("ADVANCED MICRO")) return "AMD";
        if (s.Contains("INTEL")) return "Intel";
        return "Other";
    }

    private static List<GpuInfo> NvidiaSmi()
    {
        var result = new List<GpuInfo>();
        var exe = new[] { Path.Combine(Environment.SystemDirectory, "nvidia-smi.exe"), @"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe" }.FirstOrDefault(File.Exists);
        if (exe is null) return result;
        try
        {
            var r = Proc.Run(exe, "--query-gpu=name,memory.total --format=csv,noheader,nounits", TimeSpan.FromSeconds(15));
            if (r.ExitCode != 0) return result;
            foreach (var line in r.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                var parts = line.Split(',');
                if (parts.Length >= 2 && double.TryParse(parts[^1].Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out var mib))
                    result.Add(new GpuInfo(string.Join(",", parts[..^1]).Trim(), Math.Round(mib / 1024.0, 1), "NVIDIA"));
            }
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { }
        return result;
    }

    private static string WindowsName()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var product = k?.GetValue("ProductName") as string ?? "Windows";
            var build = k?.GetValue("CurrentBuildNumber") as string ?? "";
            if (int.TryParse(build, out var b) && b >= 22000) product = product.Replace("Windows 10", "Windows 11");
            var display = k?.GetValue("DisplayVersion") as string;
            return $"{product} {display} (build {build})".Replace("  ", " ").Trim();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException) { return "Windows"; }
    }
}

public sealed record ProcResult(int ExitCode, string Output);

public static class Proc
{
    /// <summary>Runs a program without a window and collects what it prints. Optional text is written to its standard input (used for passwords).</summary>
    public static ProcResult Run(string file, string args, TimeSpan timeout, string? stdin = null, IDictionary<string, string>? env = null)
    {
        var psi = new ProcessStartInfo(file, args)
        {
            UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = stdin is not null,
        };
        if (env is not null) foreach (var (k, v) in env) psi.Environment[k] = v;
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Couldn't start " + file);
        var output = new System.Text.StringBuilder();
        p.OutputDataReceived += (_, e) => { if (e.Data is not null) lock (output) output.AppendLine(e.Data); };
        p.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (output) output.AppendLine(e.Data); };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        if (stdin is not null) { p.StandardInput.WriteLine(stdin); p.StandardInput.Close(); }
        if (!p.WaitForExit((int)timeout.TotalMilliseconds))
        {
            try { p.Kill(true); } catch (InvalidOperationException) { }
            return new ProcResult(-1, output + "\n(timed out)");
        }
        // Give the output a moment to finish arriving, without waiting forever on a pipe a child process still holds.
        Thread.Sleep(200);
        lock (output) return new ProcResult(p.ExitCode, output.ToString());
    }

    /// <summary>
    /// Runs a program without capturing its output (installers can leave child processes holding output pipes open,
    /// which would make waiting for them hang), with a time limit.
    /// </summary>
    public static ProcResult RunPlain(string file, string args, TimeSpan timeout, IDictionary<string, string>? env = null)
    {
        var psi = new ProcessStartInfo(file, args) { UseShellExecute = false, CreateNoWindow = true };
        if (env is not null) foreach (var (k, v) in env) psi.Environment[k] = v;
        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Couldn't start " + file);
        if (!p.WaitForExit((int)timeout.TotalMilliseconds))
        {
            try { p.Kill(true); } catch (InvalidOperationException) { }
            return new ProcResult(-1, "(timed out)");
        }
        return new ProcResult(p.ExitCode, "");
    }

    /// <summary>Runs a PowerShell script passed as an encoded command, so paths with quotes or spaces can't break it.</summary>
    public static ProcResult PowerShell(string script, TimeSpan timeout)
    {
        var encoded = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("$ErrorActionPreference='Stop'; " + script));
        var exe = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        return Run(exe, "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded, timeout);
    }

    /// <summary>A Windows program by its full path, so a look-alike earlier on the PATH is never run as administrator.</summary>
    public static string Sys(string exe) => Path.Combine(Environment.SystemDirectory, exe);

    /// <summary>Quotes a value for a PowerShell single-quoted string.</summary>
    public static string Ps(string s) => "'" + s.Replace("'", "''") + "'";
}
