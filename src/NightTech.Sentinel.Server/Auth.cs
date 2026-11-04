using System.Collections.Concurrent;
using System.Security.Cryptography;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Server;

/// <summary>
/// Technician sign-in: password and a two-step code every time. Sessions live in memory (signing in again after a
/// server restart is fine), last 12 hours at most and end after 30 minutes without use.
/// </summary>
public sealed class Auth
{
    public const string Cookie = "__Host-sentinel";
    public static readonly TimeSpan Idle = TimeSpan.FromMinutes(30), MaxAge = TimeSpan.FromHours(12);
    private readonly Store _store;
    private readonly ConcurrentDictionary<string, (string TechId, DateTime Created, DateTime Seen)> _sessions = new();
    private readonly ConcurrentDictionary<string, (int Count, DateTime Since)> _failures = new();

    public Auth(Store store) { _store = store; }

    public sealed record LoginResult(bool Ok, string Error, string Token);

    public LoginResult Login(string user, string password, string code, string ip)
    {
        var key = (user ?? "").ToLowerInvariant() + "|" + ip;
        if (_failures.TryGetValue(key, out var f) && f.Count >= 5 && DateTime.UtcNow - f.Since < TimeSpan.FromMinutes(15))
            return new(false, "Too many tries. Wait 15 minutes and try again.", "");
        var tech = _store.Techs.FirstOrDefault(t => string.Equals(t.User, user, StringComparison.OrdinalIgnoreCase) && !t.Disabled);
        // Always do the slow password check, so a wrong user name takes as long as a wrong password.
        bool passwordOk = Passwords.Check(password ?? "", tech?.PasswordHash ?? Passwords.Hash("x"));
        long? step = tech is null || !passwordOk ? null : Totp.Check(Convert.FromBase64String(tech.TotpSecret), code ?? "", DateTimeOffset.UtcNow);
        // Checking and using up the code happen together, so the same code can't sign in twice at once.
        bool fresh = step is not null && _store.Change(() =>
        {
            if (step <= tech!.LastTotpStep) return false;
            tech.LastTotpStep = step.Value;
            _store.SaveTechs();
            return true;
        });
        if (tech is null || !passwordOk || !fresh)
        {
            _failures.AddOrUpdate(key, (1, DateTime.UtcNow), (_, old) => DateTime.UtcNow - old.Since > TimeSpan.FromMinutes(15) ? (1, DateTime.UtcNow) : (old.Count + 1, old.Since));
            _store.Audit(user ?? "", $"Sign-in failed from {ip}");
            return new(false, "That user name, password or code isn't right.", "");
        }
        _failures.TryRemove(key, out _);
        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        _sessions[token] = (tech.Id, DateTime.UtcNow, DateTime.UtcNow);
        _store.Audit(tech.User, $"Signed in from {ip}");
        return new(true, "", token);
    }

    public Tech? Current(HttpContext ctx)
    {
        if (!ctx.Request.Cookies.TryGetValue(Cookie, out var token) || !_sessions.TryGetValue(token, out var s)) return null;
        var now = DateTime.UtcNow;
        if (now - s.Seen > Idle || now - s.Created > MaxAge) { _sessions.TryRemove(token, out _); return null; }
        _sessions[token] = s with { Seen = now };
        var tech = _store.Techs.FirstOrDefault(t => t.Id == s.TechId && !t.Disabled);
        if (tech is null) _sessions.TryRemove(token, out _);
        return tech;
    }

    public void Logout(HttpContext ctx)
    {
        if (ctx.Request.Cookies.TryGetValue(Cookie, out var token)) _sessions.TryRemove(token, out _);
    }

    /// <summary>Ends every session a tech has (after a password change or when they're turned off).</summary>
    public void EndSessions(string techId)
    {
        foreach (var kv in _sessions.Where(kv => kv.Value.TechId == techId).ToList()) _sessions.TryRemove(kv.Key, out _);
    }

    public static void SetCookie(HttpContext ctx, string token) =>
        ctx.Response.Cookies.Append(Cookie, token, new CookieOptions { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Strict, Path = "/", MaxAge = MaxAge });

    /// <summary>The one-time code printed when the server first starts, needed to create the first technician.</summary>
    public static string SetupToken(string dataDir)
    {
        var p = Path.Combine(dataDir, "setup-token.txt");
        if (File.Exists(p)) return File.ReadAllText(p).Trim();
        var t = SentinelCrypto.RandomCode(20);
        File.WriteAllText(p, t);
        return t;
    }
}
