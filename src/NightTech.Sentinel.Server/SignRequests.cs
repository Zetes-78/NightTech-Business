using System.Collections.Concurrent;
using System.Text;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Server;

/// <summary>
/// An action a tech asked for in the console, waiting for that tech to approve it in Sentinel Signer on their own PC.
/// The console never signs anything: only the Signer holds a key the client PCs trust, and it shows exactly what it
/// signs. So someone who took over this server could ask, but couldn't approve.
/// </summary>
public sealed class SignRequest
{
    public string Id { get; set; } = "";
    public string TechId { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string Computer { get; set; } = "";
    public string Client { get; set; } = "";
    public CommandKind Kind { get; set; }
    public Dictionary<string, string> Args { get; set; } = new();
    public string Reason { get; set; } = "";
    public int Minutes { get; set; } = 30;
    public DateTime CreatedUtc { get; set; }
    /// <summary>Waiting, Approved, Rejected, Expired.</summary>
    public string Status { get; set; } = "Waiting";
    public bool Delivered { get; set; }
    public string Error { get; set; } = "";
}

public sealed class SignRequests
{
    public static readonly TimeSpan Life = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<string, SignRequest> _all = new();

    public SignRequest Add(SignRequest r)
    {
        foreach (var old in _all.Values.Where(x => DateTime.UtcNow - x.CreatedUtc > TimeSpan.FromHours(1)).ToList()) _all.TryRemove(old.Id, out _);
        if (_all.Values.Count(x => x.TechId == r.TechId && x.Status == "Waiting") >= 20) throw new InvalidOperationException("Twenty requests are already waiting for approval.");
        r.Id = SentinelCrypto.RandomCode(20).ToLowerInvariant();
        r.CreatedUtc = DateTime.UtcNow;
        _all[r.Id] = r;
        return r;
    }

    public SignRequest? Get(string id)
    {
        if (!_all.TryGetValue(id ?? "", out var r)) return null;
        if (r.Status == "Waiting" && DateTime.UtcNow - r.CreatedUtc > Life) r.Status = "Expired";
        return r;
    }

    public IEnumerable<SignRequest> Waiting(string techId) =>
        _all.Values.Where(r => r.TechId == techId).Select(r => Get(r.Id)!).Where(r => r.Status == "Waiting").OrderBy(r => r.CreatedUtc);
}

/// <summary>
/// How Sentinel Signer proves which tech it is: each request carries the key ID, the time, and a signature over
/// "sentinel-signer|keyId|unix time|METHOD|/path" made with the Signer's key.
/// </summary>
public sealed class SignerAuth
{
    private readonly Store _store;
    private readonly ConcurrentDictionary<string, DateTime> _seen = new();

    public SignerAuth(Store store) { _store = store; }

    public (Tech Tech, TrustedKey Key)? Check(HttpContext ctx)
    {
        var header = ctx.Request.Headers["X-Sentinel-Signer"].ToString();
        var parts = header.Split('.');
        if (parts.Length != 3 || !long.TryParse(parts[1], out long unix)) return null;
        var when = DateTimeOffset.FromUnixTimeSeconds(unix).UtcDateTime;
        if (Math.Abs((DateTime.UtcNow - when).TotalSeconds) > 120) return null;
        foreach (var tech in _store.Techs.Where(t => !t.Disabled))
        {
            var key = tech.Keys.FirstOrDefault(k => k.KeyId == parts[0]);
            if (key is null) continue;
            var message = $"sentinel-signer|{parts[0]}|{parts[1]}|{ctx.Request.Method}|{ctx.Request.Path}";
            if (!SentinelCrypto.Verify(key.PublicKey, Encoding.UTF8.GetBytes(message), parts[2])) return null;
            // Each signed header works once.
            foreach (var old in _seen.Where(s => DateTime.UtcNow - s.Value > TimeSpan.FromMinutes(5)).ToList()) _seen.TryRemove(old.Key, out _);
            if (!_seen.TryAdd(parts[2], DateTime.UtcNow)) return null;
            return (tech, key);
        }
        return null;
    }
}
