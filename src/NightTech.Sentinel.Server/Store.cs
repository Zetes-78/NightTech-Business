using System.Collections.Concurrent;
using System.Text.Json;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Server;

public sealed class Client
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string Contact { get; set; } = "";
    public string Email { get; set; } = "";
    public string Notes { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
}

public sealed class Tech
{
    public string Id { get; set; } = "";
    public string User { get; set; } = "";
    public string Name { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    /// <summary>Two-step sign-in secret (base64). Required for every tech.</summary>
    public string TotpSecret { get; set; } = "";
    public long LastTotpStep { get; set; }
    /// <summary>Signing keys made in this tech's browsers. PCs only trust the ones named in their enrollment code.</summary>
    public List<TrustedKey> Keys { get; set; } = new();
    public bool Disabled { get; set; }
}

public sealed class EnrollCode
{
    public string Code { get; set; } = "";
    public string ClientId { get; set; } = "";
    public DateTime ExpiresUtc { get; set; }
    public int UsesLeft { get; set; }
    public string CreatedBy { get; set; } = "";
}

public sealed class Device
{
    public string Id { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string Computer { get; set; } = "";
    public string PublicKey { get; set; } = "";
    public DateTime EnrolledUtc { get; set; }
    public DateTime? LastSeenUtc { get; set; }
    public string LastIp { get; set; } = "";
    public bool Retired { get; set; }
    public HealthReport? Latest { get; set; }
    public List<Alert> Alerts { get; set; } = new();
    public List<CommandResult> History { get; set; } = new();
    /// <summary>Commands waiting to be picked up (signed by a tech's browser; the PC checks them itself).</summary>
    public List<QueuedCommand> Queue { get; set; } = new();
    public string Note { get; set; } = "";
}

public sealed class QueuedCommand
{
    public string Id { get; set; } = "";
    public CommandKind Kind { get; set; }
    public string Tech { get; set; } = "";
    public DateTime ExpiresUtc { get; set; }
    public SignedCommand Signed { get; set; } = new();
    public DateTime? DeliveredUtc { get; set; }
}

/// <summary>
/// Sentinel's data: one JSON file per kind of thing, and one per PC, in the data folder. Every write goes to a
/// temporary file first, so a crash can't leave a half-written file. Fine for hundreds of PCs.
/// </summary>
public sealed class Store
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string _dir;
    private readonly object _gate = new();
    private readonly ConcurrentDictionary<string, Device> _devices = new();
    private List<Client> _clients;
    private List<Tech> _techs;
    private List<EnrollCode> _codes;

    public Store(string dir)
    {
        _dir = dir;
        Directory.CreateDirectory(Path.Combine(dir, "devices"));
        _clients = Read<List<Client>>("clients.json") ?? new();
        _techs = Read<List<Tech>>("techs.json") ?? new();
        _codes = Read<List<EnrollCode>>("codes.json") ?? new();
        foreach (var f in Directory.GetFiles(Path.Combine(dir, "devices"), "*.json"))
            if (JsonSerializer.Deserialize<Device>(File.ReadAllText(f), Json) is { } d) _devices[d.Id] = d;
    }

    private T? Read<T>(string name)
    {
        var p = Path.Combine(_dir, name);
        return File.Exists(p) ? JsonSerializer.Deserialize<T>(File.ReadAllText(p), Json) : default;
    }

    private void Write(string name, object value)
    {
        var p = Path.Combine(_dir, name);
        var tmp = p + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(value, Json));
        File.Move(tmp, p, overwrite: true);
    }

    // Each change happens inside the lock and is saved before the lock is let go.
    public T Change<T>(Func<T> change)
    {
        lock (_gate) return change();
    }

    public void Change(Action change)
    {
        lock (_gate) change();
    }

    public IReadOnlyList<Client> Clients { get { lock (_gate) return _clients.ToList(); } }
    public IReadOnlyList<Tech> Techs { get { lock (_gate) return _techs.ToList(); } }
    public IEnumerable<Device> Devices => _devices.Values;
    public Device? Device(string id) => _devices.TryGetValue(id ?? "", out var d) ? d : null;

    public void SaveClients() => Write("clients.json", _clients);
    public void SaveTechs() => Write("techs.json", _techs);
    public void SaveCodes() => Write("codes.json", _codes);
    public void SaveDevice(Device d)
    {
        _devices[d.Id] = d;
        Write(Path.Combine("devices", d.Id + ".json"), d);
    }

    public List<Client> ClientList => _clients;
    public List<Tech> TechList => _techs;
    public List<EnrollCode> CodeList => _codes;

    /// <summary>Everything that matters for later, one line each, never edited.</summary>
    public void Audit(string who, string what)
    {
        var line = $"{DateTime.UtcNow:O}\t{who.Replace('\t', ' ')}\t{what.Replace('\t', ' ').Replace('\n', ' ').Replace('\r', ' ')}\n";
        lock (_gate)
        {
            var p = Path.Combine(_dir, "audit.log");
            // Kept, never edited: a full log is set aside under its date and a new one started.
            if (File.Exists(p) && new FileInfo(p).Length > 10_000_000) File.Move(p, Path.Combine(_dir, $"audit-{DateTime.UtcNow:yyyyMMdd-HHmmss}.log"));
            File.AppendAllText(p, line);
        }
    }

    public IEnumerable<string> AuditTail(int n)
    {
        var p = Path.Combine(_dir, "audit.log");
        if (!File.Exists(p)) return Array.Empty<string>();
        lock (_gate) return File.ReadLines(p).TakeLast(n).Reverse().ToList();
    }
}
