namespace NightTech.Business.Core.Sentinel;

/// <summary>One health check from a client PC. Read-only facts: no files, screen, keystrokes or passwords, ever.</summary>
public sealed class HealthReport
{
    public int Schema { get; set; } = 1;
    public string DeviceId { get; set; } = "";
    public DateTime TakenUtc { get; set; }
    public string AgentVersion { get; set; } = "";

    public string Computer { get; set; } = "";
    public string Make { get; set; } = "";
    public string Model { get; set; } = "";
    public string Serial { get; set; } = "";
    public string Windows { get; set; } = "";
    public string WindowsBuild { get; set; } = "";
    public long RamBytes { get; set; }
    public DateTime? LastBootUtc { get; set; }
    public string LoggedOnUser { get; set; } = "";

    public List<DriveHealth> Drives { get; set; } = new();
    public List<VolumeSpace> Volumes { get; set; } = new();
    public AntivirusState Antivirus { get; set; } = new();
    public UpdateState Updates { get; set; } = new();
    public BackupState Backup { get; set; } = new();
    public bool? FirewallOn { get; set; }
    public int? BatteryHealthPercent { get; set; }

    /// <summary>Counts from the Windows event log for the last 7 days.</summary>
    public int UnexpectedShutdowns7d { get; set; }
    public int BlueScreens7d { get; set; }
    public int DiskErrors7d { get; set; }

    /// <summary>Checks that couldn't be completed, in plain words.</summary>
    public List<string> Notes { get; set; } = new();

    /// <summary>A help request the person at the PC sent with the tray icon (empty if none).</summary>
    public string HelpRequest { get; set; } = "";

    /// <summary>Night Tech Shield's findings (adware, hijacks, startup items, Defender detections), most serious first.</summary>
    public List<SecurityItem> Security { get; set; } = new();
    /// <summary>When Shield's checks last ran on this PC.</summary>
    public DateTime? SecurityCheckedUtc { get; set; }

    /// <summary>What happened to commands since the last check-in.</summary>
    public List<CommandResult> Results { get; set; } = new();

    /// <summary>What this PC allows (set at install), so the console knows before asking.</summary>
    public AgentPolicy Policy { get; set; } = new();

    public long? UptimeHours => LastBootUtc is { } b ? (long)(TakenUtc - b).TotalHours : null;
}

/// <summary>One Night Tech Shield finding, as reported to the console.</summary>
public sealed class SecurityItem
{
    public string Id { get; set; } = "";
    public string Area { get; set; } = "";
    /// <summary>Risk, Warning or Info.</summary>
    public string Severity { get; set; } = "";
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    /// <summary>Shield can fix it (and would tick it by default).</summary>
    public bool Fixable { get; set; }
    public bool Recommended { get; set; }
}

public sealed class DriveHealth
{
    public string Name { get; set; } = "";
    public string Serial { get; set; } = "";
    public string MediaType { get; set; } = "";     // SSD, HDD
    public string Health { get; set; } = "Unknown"; // Healthy, Warning, Unhealthy, Unknown
    public int? WearPercent { get; set; }
    public int? TemperatureC { get; set; }
    public long? ReadErrorsUncorrected { get; set; }
    public long? PowerOnHours { get; set; }
    public long? SizeBytes { get; set; }
}

public sealed class VolumeSpace
{
    public string Name { get; set; } = "";
    public string Label { get; set; } = "";
    public long SizeBytes { get; set; }
    public long FreeBytes { get; set; }
    public bool IsSystem { get; set; }
    public double FreePercent => SizeBytes > 0 ? FreeBytes * 100.0 / SizeBytes : 0;
}

public sealed class AntivirusState
{
    /// <summary>Products Windows Security Center lists ("Microsoft Defender Antivirus", "Bitdefender").</summary>
    public List<string> Products { get; set; } = new();
    public bool? Enabled { get; set; }
    public bool? UpToDate { get; set; }
    public bool? RealTime { get; set; }
    /// <summary>Microsoft Defender's own figures, when it's the active antivirus.</summary>
    public int? DefenderSignatureAgeDays { get; set; }
    public int? DefenderQuickScanAgeDays { get; set; }
}

public sealed class UpdateState
{
    public DateTime? LastInstalledUtc { get; set; }
    public bool RebootPending { get; set; }
}

public sealed class BackupState
{
    /// <summary>"Backup Buddy", or "" when no backup program we know about is set up.</summary>
    public string Tool { get; set; } = "";
    public DateTime? LastSuccessUtc { get; set; }
    public DateTime? LastRunUtc { get; set; }
    public bool LastRunFailed { get; set; }
    public string Destination { get; set; } = "";
}

public enum AlertLevel { Info, Warning, Critical }

/// <summary>Something worth a technician's attention. The key stays the same while the problem lasts.</summary>
public sealed class Alert
{
    public string Key { get; set; } = "";
    public AlertLevel Level { get; set; }
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public bool Acknowledged { get; set; }
    public DateTime? ClearedUtc { get; set; }
}

// ---------------- What the agent sends ----------------

public sealed class EnrollRequest
{
    public string Code { get; set; } = "";
    public string AgentVersion { get; set; } = "";
    public string PublicKey { get; set; } = "";   // SubjectPublicKeyInfo, base64
    public string Computer { get; set; } = "";
}

public sealed class EnrollResponse
{
    public string DeviceId { get; set; } = "";
    /// <summary>Tech keys offered by the server. The PC keeps only those whose IDs are in its enrollment token.</summary>
    public List<TrustedKey> TechKeys { get; set; } = new();
    public string ClientName { get; set; } = "";
    public int CheckInMinutes { get; set; } = 15;
}

/// <summary>A signed check-in: the report's exact bytes, and the agent's signature over them.</summary>
public sealed class CheckIn
{
    public string DeviceId { get; set; } = "";
    public string Payload { get; set; } = "";     // the HealthReport JSON, base64
    public string Signature { get; set; } = "";   // ECDSA P-256 SHA-256, base64
}

public sealed class CheckInResponse
{
    public int CheckInMinutes { get; set; } = 15;
    /// <summary>Signed commands waiting for this PC. The PC checks each one itself.</summary>
    public List<SignedCommand> Commands { get; set; } = new();
    /// <summary>Shown in the tray icon: "All good" or a plain-words status for the person at the PC.</summary>
    public string Status { get; set; } = "";
}
