using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NightTech.Business.Core.Sentinel;
using NightTech.Sentinel.Agent;

// NightTechSentinelAgent.exe                      run as the Windows service
// NightTechSentinelAgent.exe enroll <token> ...   set this PC up (the installer runs this)
// NightTechSentinelAgent.exe forget               remove this PC's key and settings (the uninstaller runs this)
// NightTechSentinelAgent.exe --desktop-helper <n> screen helper for a remote desktop session (started by the service)

if (args.Length >= 2 && args[0] == "--desktop-helper")
    return DesktopHelper.Run(args[1]);

if (args.Length >= 1 && args[0] == "enroll")
    return await Enroll(args.Skip(1).ToArray());

if (args.Length >= 1 && args[0] == "forget")
{
    try
    {
        AgentStore.DeleteDeviceKey();
        var path = Path.Combine(AgentStore.Folder, "agent.json");
        if (File.Exists(path)) File.Delete(path);
        Console.WriteLine("This PC's Sentinel key and settings were removed.");
        return 0;
    }
    catch (Exception e) { Console.Error.WriteLine(e.Message); return 1; }
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(o => o.ServiceName = "NightTechSentinel");
builder.Services.AddHostedService<SentinelService>();
await builder.Build().RunAsync();
return 0;

static async Task<int> Enroll(string[] a)
{
    var token = EnrollToken.Parse(a.FirstOrDefault() ?? "");
    if (token is null)
    {
        Console.Error.WriteLine("That enrollment code isn't valid. Copy it again from the Sentinel console (it starts with NTS1.).");
        return 2;
    }
    var policy = new AgentPolicy
    {
        Unattended = a.Contains("--unattended"),
        AllowRemoteDesktop = !a.Contains("--no-remote-desktop"),
        AllowRemoteShell = !a.Contains("--no-remote-shell"),
        AllowScripts = !a.Contains("--no-scripts"),
        RestartWithoutAsking = a.Contains("--restart-without-asking"),
    };
    try
    {
        AgentStore.PrepareFolder();
        AgentStore.DeleteDeviceKey();   // a fresh key for each setup
        using var key = AgentStore.DeviceKey();
        using var http = SentinelService.Http(token.Server);
        var req = new EnrollRequest { Code = token.Code, PublicKey = SentinelCrypto.PublicKey(key), Computer = Environment.MachineName, AgentVersion = SentinelService.Version };
        using var res = await http.PostAsJsonAsync("api/agent/enroll", req, SignedCommand.Json);
        if (!res.IsSuccessStatusCode)
        {
            Console.Error.WriteLine(res.StatusCode == System.Net.HttpStatusCode.Forbidden
                ? "The Sentinel server didn't accept that code. It may have been used already or expired; make a new one in the console."
                : $"The Sentinel server answered {(int)res.StatusCode}. Check the address and try again.");
            return 3;
        }
        var answer = await res.Content.ReadFromJsonAsync<EnrollResponse>(SignedCommand.Json) ?? throw new InvalidOperationException("Empty answer from the server.");
        // Only keys named in the code the tech gave, and only if each really is the key its ID says.
        var keys = answer.TechKeys.Where(k => token.KeyIds.Contains(k.KeyId) && SafeKeyId(k.PublicKey) == k.KeyId).ToList();
        if (keys.Count == 0)
        {
            Console.Error.WriteLine("The server didn't send any of the technician keys named in the enrollment code, so this PC wasn't set up.");
            return 4;
        }
        AgentStore.Save(new AgentConfig
        {
            Server = token.Server, DeviceId = answer.DeviceId, ClientName = answer.ClientName.Length > 0 ? answer.ClientName : token.Client,
            CheckInMinutes = Math.Clamp(answer.CheckInMinutes, 5, 240), TrustedKeys = keys, Policy = policy,
        });
        Console.WriteLine($"This PC is set up for {answer.ClientName}. Trusted technicians: {string.Join(", ", keys.Select(k => k.Tech))}.");
        return 0;
    }
    catch (Exception e) when (e is HttpRequestException or TaskCanceledException or InvalidOperationException or System.Security.Cryptography.CryptographicException or IOException or UnauthorizedAccessException)
    {
        Console.Error.WriteLine("Setup didn't finish: " + e.Message);
        return 5;
    }
}

static string SafeKeyId(string spki)
{
    try { return SentinelCrypto.KeyId(spki); }
    catch (Exception e) when (e is FormatException or ArgumentNullException) { return ""; }
}
