using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NightTech.Business.Core.Sentinel;

[JsonConverter(typeof(JsonStringEnumConverter<CommandKind>))]
public enum CommandKind
{
    // Checks and upkeep
    RefreshNow,
    ShieldScan,
    ShieldFix,
    DefenderUpdate,
    DefenderQuickScan,
    DefenderFullScan,
    InstallUpdates,
    CleanTemp,
    CollectLogs,
    Restart,
    ShowMessage,
    // Powerful: always logged and shown at the PC
    RunScript,
    RemoteShell,
    RemoteDesktop,
    // Changes which tech keys this PC trusts
    UpdateTrustedKeys,
}

/// <summary>
/// An instruction from a technician to one client PC. The tech's own browser signs it with a key that never leaves the
/// tech's computer; the PC checks the signature against the keys it was set up to trust. The Sentinel server only
/// passes signed commands along, so even someone who took over the server couldn't make a PC do anything.
/// </summary>
public sealed class Command
{
    public int V { get; set; } = 1;
    public string Id { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public CommandKind Kind { get; set; }
    public Dictionary<string, string> Args { get; set; } = new();
    public DateTime IssuedUtc { get; set; }
    public DateTime ExpiresUtc { get; set; }
    /// <summary>The technician's name, shown at the PC and in the logs.</summary>
    public string Tech { get; set; } = "";
    /// <summary>Which trusted key signed it (SentinelCrypto.KeyId).</summary>
    public string KeyId { get; set; } = "";
    /// <summary>Why: shown to the person at the PC when they're asked to allow it.</summary>
    public string Reason { get; set; } = "";

    public string Arg(string name) => Args.TryGetValue(name, out var v) ? v : "";
}

/// <summary>A command as it travels: the exact JSON bytes the tech signed, and the signature.</summary>
public sealed class SignedCommand
{
    public string Payload { get; set; } = "";     // base64 of the Command JSON
    public string Signature { get; set; } = "";   // ECDSA P-256 SHA-256, r||s, base64

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    /// <summary>Signs a command (what the console does in the browser; used here for tests and tools).</summary>
    public static SignedCommand Create(Command c, System.Security.Cryptography.ECDsa techKey)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(c, Json);
        return new SignedCommand { Payload = Convert.ToBase64String(bytes), Signature = SentinelCrypto.Sign(techKey, bytes) };
    }
}

/// <summary>A tech key this PC trusts, pinned when Sentinel was installed.</summary>
public sealed class TrustedKey
{
    public string KeyId { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public string Tech { get; set; } = "";
}

public enum Decision { Run, AskFirst, Refuse }

/// <summary>
/// What this PC allows, chosen when Sentinel is installed and kept on the PC. The server can't change it: only the
/// installer, or an administrator at the PC, can.
/// </summary>
public sealed class AgentPolicy
{
    /// <summary>Remote desktop and remote shell without asking the person at the PC (for servers and unattended PCs).</summary>
    public bool Unattended { get; set; }
    public bool AllowRemoteDesktop { get; set; } = true;
    public bool AllowRemoteShell { get; set; } = true;
    public bool AllowScripts { get; set; } = true;
    /// <summary>Restart without asking, for PCs nobody sits at.</summary>
    public bool RestartWithoutAsking { get; set; }

    /// <summary>Commands that only read or tidy up: they run without asking.</summary>
    public static readonly CommandKind[] Routine =
    {
        CommandKind.RefreshNow, CommandKind.ShieldScan, CommandKind.DefenderUpdate, CommandKind.DefenderQuickScan,
        CommandKind.DefenderFullScan, CommandKind.CollectLogs, CommandKind.ShowMessage, CommandKind.CleanTemp,
    };

    public Decision Decide(CommandKind kind) => kind switch
    {
        _ when Routine.Contains(kind) => Decision.Run,
        CommandKind.RemoteDesktop when !AllowRemoteDesktop => Decision.Refuse,
        CommandKind.RemoteShell when !AllowRemoteShell => Decision.Refuse,
        CommandKind.RunScript when !AllowScripts => Decision.Refuse,
        CommandKind.RemoteDesktop or CommandKind.RemoteShell or CommandKind.RunScript => Unattended ? Decision.Run : Decision.AskFirst,
        CommandKind.Restart => RestartWithoutAsking ? Decision.Run : Decision.AskFirst,
        CommandKind.ShieldFix or CommandKind.InstallUpdates => Unattended ? Decision.Run : Decision.AskFirst,
        // A new trusted key is always confirmed at the PC unless it's unattended.
        CommandKind.UpdateTrustedKeys => Unattended ? Decision.Run : Decision.AskFirst,
        _ => Decision.Refuse,
    };
}

/// <summary>The checks a client PC makes before it does anything a command asks.</summary>
public sealed class CommandVerifier
{
    /// <summary>The longest a signed command stays usable.</summary>
    public static readonly TimeSpan MaxLife = TimeSpan.FromHours(24);
    /// <summary>How far the tech's clock may be ahead of the PC's.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    private readonly string _deviceId;
    private readonly Func<IReadOnlyList<TrustedKey>> _keys;
    /// <summary>IDs already run, with when they expire, so the same signed command can't be used twice.</summary>
    private readonly Dictionary<string, DateTime> _seen;

    public CommandVerifier(string deviceId, Func<IReadOnlyList<TrustedKey>> keys, Dictionary<string, DateTime>? seen = null)
    {
        _deviceId = deviceId;
        _keys = keys;
        _seen = seen ?? new();
    }

    public IReadOnlyDictionary<string, DateTime> Seen => _seen;

    /// <summary>Returns the command when it's genuine, for this PC, current and new; otherwise null and why.</summary>
    public (Command? Command, string Why) Verify(SignedCommand signed, DateTime nowUtc)
    {
        byte[] bytes;
        try { bytes = Convert.FromBase64String(signed.Payload ?? ""); }
        catch (FormatException) { return (null, "not readable"); }
        Command? c;
        try { c = JsonSerializer.Deserialize<Command>(bytes, SignedCommand.Json); }
        catch (JsonException) { return (null, "not readable"); }
        if (c is null || c.V != 1 || c.Id.Length is < 16 or > 64) return (null, "not readable");

        var key = _keys().FirstOrDefault(k => k.KeyId == c.KeyId);
        if (key is null) return (null, "signed by a key this PC doesn't trust");
        if (SentinelCrypto.KeyId(key.PublicKey) != key.KeyId) return (null, "trusted key list is damaged");
        if (!SentinelCrypto.Verify(key.PublicKey, bytes, signed.Signature ?? "")) return (null, "signature doesn't match");
        if (c.DeviceId != _deviceId) return (null, "meant for a different PC");
        if (c.IssuedUtc.Kind != DateTimeKind.Utc) c.IssuedUtc = DateTime.SpecifyKind(c.IssuedUtc, DateTimeKind.Utc);
        if (c.ExpiresUtc.Kind != DateTimeKind.Utc) c.ExpiresUtc = DateTime.SpecifyKind(c.ExpiresUtc, DateTimeKind.Utc);
        if (c.ExpiresUtc <= c.IssuedUtc || c.ExpiresUtc - c.IssuedUtc > MaxLife) return (null, "has an impossible lifetime");
        if (c.IssuedUtc > nowUtc + ClockSkew) return (null, "dated in the future");
        if (nowUtc > c.ExpiresUtc) return (null, "expired");

        foreach (var old in _seen.Where(kv => kv.Value < nowUtc).Select(kv => kv.Key).ToList()) _seen.Remove(old);
        if (_seen.ContainsKey(c.Id)) return (null, "already used");
        _seen[c.Id] = c.ExpiresUtc;
        if (string.IsNullOrWhiteSpace(c.Tech)) c.Tech = key.Tech;
        return (c, "");
    }
}

/// <summary>What happened when a PC got a command, sent back with its next check-in (signed with the device key).</summary>
public sealed class CommandResult
{
    public string CommandId { get; set; } = "";
    public CommandKind Kind { get; set; }
    /// <summary>Done, Failed, Refused, Declined (the person at the PC said no), TimedOut.</summary>
    public string Outcome { get; set; } = "";
    public string Detail { get; set; } = "";
    public DateTime FinishedUtc { get; set; }
    /// <summary>Text output (scripts, logs), trimmed to 64 KB.</summary>
    public string Output { get; set; } = "";

    public const int MaxOutput = 64 * 1024;

    public static string Trim(string s) => s.Length <= MaxOutput ? s : s[..MaxOutput] + "\n[output trimmed]";
}

/// <summary>Plain words for each command, used in prompts at the PC and in the console.</summary>
public static class CommandWords
{
    public static string Describe(Command c) => c.Kind switch
    {
        CommandKind.RefreshNow => "check this PC now",
        CommandKind.ShieldScan => "run a Night Tech Shield scan",
        CommandKind.ShieldFix => "fix what Night Tech Shield found",
        CommandKind.DefenderUpdate => "update Microsoft Defender",
        CommandKind.DefenderQuickScan => "run a Microsoft Defender quick scan",
        CommandKind.DefenderFullScan => "run a Microsoft Defender full scan",
        CommandKind.InstallUpdates => "install Windows updates",
        CommandKind.CleanTemp => "clear temporary files",
        CommandKind.CollectLogs => "collect error logs",
        CommandKind.Restart => "restart this PC",
        CommandKind.ShowMessage => "show you a message",
        CommandKind.RunScript => "run a maintenance script" + (c.Arg("name").Length > 0 ? $" ({c.Arg("name")})" : ""),
        CommandKind.RemoteShell => "open a remote command window",
        CommandKind.RemoteDesktop => "see and control this screen",
        CommandKind.UpdateTrustedKeys => "change which Night Tech technicians this PC trusts",
        _ => "do something Sentinel doesn't recognize",
    };

    public static string Prompt(Command c) =>
        $"{(c.Tech.Length > 0 ? c.Tech : "A technician")} from {Brand.Company} would like to {Describe(c)}."
        + (c.Reason.Length > 0 ? $"\n\nReason: {c.Reason}" : "")
        + $"\n\nIf you weren't expecting this, choose Don't allow and call us at {Brand.Phone}.";
}
