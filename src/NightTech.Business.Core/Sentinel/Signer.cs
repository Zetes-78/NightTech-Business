using System.Security.Cryptography;
using System.Text;

namespace NightTech.Business.Core.Sentinel;

/// <summary>An action waiting for approval, as Sentinel Signer receives it from the server.</summary>
public sealed class PendingAction
{
    public string Id { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string Computer { get; set; } = "";
    public string Client { get; set; } = "";
    public CommandKind Kind { get; set; }
    public Dictionary<string, string> Args { get; set; } = new();
    public string Reason { get; set; } = "";
    public int Minutes { get; set; } = 30;
    public DateTime CreatedUtc { get; set; }
}

/// <summary>What Sentinel Signer does with its key: sign the commands the tech approves, and prove who it is to the server.</summary>
public static class SignerLogic
{
    /// <summary>The X-Sentinel-Signer header: "keyId.unixTime.signature" over "sentinel-signer|keyId|unixTime|METHOD|/path".</summary>
    public static string Header(ECDsa key, string keyId, string method, string path, DateTimeOffset now)
    {
        var unix = now.ToUnixTimeSeconds().ToString();
        var sig = SentinelCrypto.Sign(key, Encoding.UTF8.GetBytes($"sentinel-signer|{keyId}|{unix}|{method}|{path}"));
        return $"{keyId}.{unix}.{sig}";
    }

    /// <summary>The command for an approved action, exactly as shown to the tech.</summary>
    public static SignedCommand Approve(PendingAction a, ECDsa key, string keyId, string tech, DateTime nowUtc)
    {
        var c = new Command
        {
            Id = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            DeviceId = a.DeviceId, Kind = a.Kind, Args = new Dictionary<string, string>(a.Args), Reason = a.Reason, Tech = tech, KeyId = keyId,
            IssuedUtc = nowUtc.AddMinutes(-1), ExpiresUtc = nowUtc.AddMinutes(Math.Clamp(a.Minutes, 5, 240)),
        };
        return SignedCommand.Create(c, key);
    }

    /// <summary>Plain words for the approval window: what will happen, where, and every detail that gets signed.</summary>
    public static string Describe(PendingAction a)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"{Capital(CommandWords.Describe(new Command { Kind = a.Kind, Args = a.Args }))}");
        sb.AppendLine($"on {(a.Computer.Length > 0 ? a.Computer : "a computer")}{(a.Client.Length > 0 ? " (" + a.Client + ")" : "")}");
        sb.AppendLine($"PC ID: {a.DeviceId}");
        if (a.Reason.Length > 0) sb.AppendLine($"Reason shown at the PC: {a.Reason}");
        sb.AppendLine($"Usable for {a.Minutes} minutes.");
        foreach (var (k, v) in a.Args.OrderBy(kv => kv.Key))
        {
            if (k is "sessionId" or "browserKey") continue;
            sb.AppendLine();
            sb.AppendLine($"{k}:");
            sb.AppendLine(v.Length > 20000 ? v[..20000] + "\n[...longer than shown]" : v);
        }
        return sb.ToString().TrimEnd();
    }

    /// <summary>Actions that change things or let someone in get an extra "are you sure".</summary>
    public static bool Powerful(CommandKind k) => k is CommandKind.RunScript or CommandKind.RemoteShell or CommandKind.RemoteDesktop
        or CommandKind.UpdateTrustedKeys or CommandKind.Restart or CommandKind.InstallUpdates or CommandKind.ShieldFix;

    private static string Capital(string s) => s.Length == 0 ? s : char.ToUpperInvariant(s[0]) + s[1..];
}
