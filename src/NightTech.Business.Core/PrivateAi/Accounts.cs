using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NightTech.Business.Core.PrivateAi;

public sealed class UserAccount
{
    public string Name { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public bool IsAdmin { get; set; }
    public string Salt { get; set; } = "";
    public string Hash { get; set; } = "";
    public int Iterations { get; set; }
    public DateTime Created { get; set; }
    /// <summary>Changes whenever the password changes, so sign-ins made with the old password end.</summary>
    public string Stamp { get; set; } = "";
}

/// <summary>
/// The people allowed to use this private AI. Passwords are never stored: only a salted PBKDF2-SHA256 hash,
/// on the customer's own computer.
/// </summary>
public sealed class UserStore
{
    public const int MinPasswordLength = 8;
    private const int Iterations = 210_000;
    private readonly string _path;
    private readonly object _gate = new();
    private List<UserAccount> _users = new();
    private DateTime _loadedStamp = DateTime.MinValue;
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public UserStore(string path)
    {
        _path = path;
        Refresh();
    }

    /// <summary>Picks up changes made by the setup tool (for example a password reset) while the server is running.</summary>
    private void Refresh()
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(_path)) return;
                var stamp = File.GetLastWriteTimeUtc(_path);
                if (stamp == _loadedStamp) return;
                _users = JsonSerializer.Deserialize<List<UserAccount>>(File.ReadAllText(_path), Json) ?? new();
                _loadedStamp = stamp;
            }
            catch (IOException) { /* being written right now; keep what we have */ }
        }
    }

    public IReadOnlyList<UserAccount> All { get { Refresh(); lock (_gate) return _users.ToList(); } }
    public bool Any { get { Refresh(); lock (_gate) return _users.Count > 0; } }

    public static string? CheckName(string name) =>
        Regex.IsMatch(name ?? "", @"^[A-Za-z0-9][A-Za-z0-9._-]{1,31}$") ? null : "User names are 2 to 32 letters or numbers (dots, dashes and underscores are fine).";

    public static string? CheckPassword(string password) =>
        (password ?? "").Length >= MinPasswordLength ? null : $"Passwords need at least {MinPasswordLength} characters.";

    public UserAccount? Find(string name)
    {
        Refresh();
        lock (_gate) return _users.FirstOrDefault(u => string.Equals(u.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    public UserAccount Add(string name, string displayName, string password, bool admin, DateTime now)
    {
        if (CheckName(name) is { } n) throw new ArgumentException(n);
        if (CheckPassword(password) is { } p) throw new ArgumentException(p);
        lock (_gate)
        {
            if (Find(name) is not null) throw new ArgumentException("That user name is already taken.");
            // The first person is always an administrator, so the AI can always be managed.
            var u = new UserAccount { Name = name, DisplayName = string.IsNullOrWhiteSpace(displayName) ? name : displayName.Trim(), IsAdmin = admin || _users.Count == 0, Created = now };
            SetHash(u, password);
            _users.Add(u);
            Save();
            return u;
        }
    }

    public void SetPassword(string name, string password)
    {
        if (CheckPassword(password) is { } p) throw new ArgumentException(p);
        lock (_gate)
        {
            var u = Find(name) ?? throw new ArgumentException("No such user.");
            SetHash(u, password);
            Save();
        }
    }

    public void SetAdmin(string name, bool admin)
    {
        lock (_gate)
        {
            var u = Find(name) ?? throw new ArgumentException("No such user.");
            if (!admin && u.IsAdmin && _users.Count(x => x.IsAdmin) == 1) throw new ArgumentException("There must always be at least one administrator.");
            u.IsAdmin = admin;
            Save();
        }
    }

    public void Remove(string name)
    {
        lock (_gate)
        {
            var u = Find(name) ?? throw new ArgumentException("No such user.");
            if (u.IsAdmin && _users.Count(x => x.IsAdmin) == 1) throw new ArgumentException("You can't remove the last administrator.");
            _users.Remove(u);
            Save();
        }
    }

    /// <summary>The account if the password is right; null otherwise. Takes the same time either way.</summary>
    public UserAccount? Verify(string name, string password)
    {
        var u = Find(name ?? "");
        var salt = u is null ? new byte[16] : Convert.FromBase64String(u.Salt);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password ?? "", salt, u?.Iterations ?? Iterations, HashAlgorithmName.SHA256, 32);
        if (u is null) return null;
        return CryptographicOperations.FixedTimeEquals(hash, Convert.FromBase64String(u.Hash)) ? u : null;
    }

    private static void SetHash(UserAccount u, string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        u.Salt = Convert.ToBase64String(salt);
        u.Iterations = Iterations;
        u.Hash = Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32));
        u.Stamp = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
    }

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_users, Json));
        File.Move(tmp, _path, true);
        _loadedStamp = File.GetLastWriteTimeUtc(_path);
    }
}

/// <summary>
/// Slows down password guessing: after too many wrong tries, a user name (5 tries) or a computer (20 tries, since
/// several people may share one) waits a few minutes.
/// </summary>
public sealed class SignInLimiter
{
    private readonly Dictionary<string, (int Fails, DateTime Until)> _state = new();
    private readonly object _gate = new();
    public const int MaxFails = 5;
    private readonly int _max;
    public static readonly TimeSpan Lockout = TimeSpan.FromMinutes(5);

    public SignInLimiter(int maxFails = MaxFails) => _max = maxFails;

    public TimeSpan? Blocked(string key, DateTime now)
    {
        lock (_gate)
            return _state.TryGetValue(key, out var s) && s.Until > now ? s.Until - now : null;
    }

    public void Failed(string key, DateTime now)
    {
        lock (_gate)
        {
            var s = _state.GetValueOrDefault(key);
            s.Fails++;
            if (s.Fails >= _max) { s.Until = now + Lockout; s.Fails = 0; }
            _state[key] = s;
            if (_state.Count > 10_000) _state.Clear();
        }
    }

    public void Succeeded(string key) { lock (_gate) _state.Remove(key); }
}

/// <summary>Private AI only answers computers on the same home or office network.</summary>
public static class NetworkGuard
{
    public static bool IsLocal(IPAddress? ip)
    {
        if (ip is null) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] == 10
                || b[0] == 172 && b[1] >= 16 && b[1] <= 31
                || b[0] == 192 && b[1] == 168
                || b[0] == 169 && b[1] == 254;
        }
        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = ip.GetAddressBytes();
            return (b[0] & 0xFE) == 0xFC           // fc00::/7 unique local
                || b[0] == 0xFE && (b[1] & 0xC0) == 0x80; // fe80::/10 link local
        }
        return false;
    }
}
