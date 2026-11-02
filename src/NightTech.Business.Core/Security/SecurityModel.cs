using System.Text.Json.Serialization;

namespace NightTech.Business.Core.Security;

/// <summary>What one computer showed. Null means "couldn't check" (often: needs administrator rights).</summary>
public sealed class SecurityFacts
{
    public string ComputerName { get; set; } = "";
    public string OsName { get; set; } = "";
    public string OsBuild { get; set; } = "";
    /// <summary>Home, Pro, Enterprise, Education, Server... as Windows names it (the edition ID).</summary>
    public string OsEdition { get; set; } = "";
    public DateTime? LastUpdateInstalled { get; set; }
    public bool RanAsAdministrator { get; set; }

    // Device protection
    /// <summary>"On", "Suspended", "Off", or empty when not checked.</summary>
    public string BitLockerSystemDrive { get; set; } = "";
    public List<AntivirusInfo> Antivirus { get; set; } = new();
    public bool? DefenderRealTime { get; set; }
    public int? DefenderSignatureAgeDays { get; set; }
    public bool? DefenderTamperProtected { get; set; }
    public bool? FirewallServiceRunning { get; set; }
    /// <summary>Firewalls other than Windows' own that Security Center reports.</summary>
    public List<AntivirusInfo> OtherFirewalls { get; set; } = new();
    public bool? FirewallDomain { get; set; }
    public bool? FirewallPrivate { get; set; }
    public bool? FirewallPublic { get; set; }
    public bool? SecureBoot { get; set; }
    public bool? TpmReady { get; set; }

    // Accounts
    public bool? UacEnabled { get; set; }
    /// <summary>"Never notify" for admins: UAC is on but never asks.</summary>
    public bool? UacNeverNotify { get; set; }
    /// <summary>The admin list couldn't be read completely (for example work-account members that didn't resolve).</summary>
    public bool AdminListIncomplete { get; set; }
    public List<string> LocalAdmins { get; set; } = new();
    public bool? BuiltInAdminEnabled { get; set; }
    public bool? GuestEnabled { get; set; }
    public List<string> PasswordNeverExpires { get; set; } = new();
    public List<string> PasswordNotRequired { get; set; } = new();
    public int? MinPasswordLength { get; set; }
    /// <summary>Failed sign-ins before lockout; 0 means never locks.</summary>
    public int? LockoutThreshold { get; set; }
    public bool? CurrentUserIsAdmin { get; set; }
    public bool? AutoLogon { get; set; }
    public bool? AutoLogonPasswordStored { get; set; }
    /// <summary>Seconds of no use before the screen locks (screen saver with password, or sleep with sign-in on wake).</summary>
    public int? ScreenLockSeconds { get; set; }
    public bool ScreenLockChecked { get; set; }
    public bool? DomainJoined { get; set; }
    /// <summary>Joined to Microsoft Entra ID (work or school account).</summary>
    public bool? EntraJoined { get; set; }

    // Exposure
    public bool AccountsChecked { get; set; }
    public bool? RemoteDesktopOn { get; set; }
    public bool? RemoteDesktopNla { get; set; }
    public bool? Smb1On { get; set; }
    public bool? PowerShell2On { get; set; }
    public List<int> ListeningPorts { get; set; } = new();
    public bool PortsChecked { get; set; }
    public List<string> Shares { get; set; } = new();
    public bool? AutoRunOff { get; set; }

    // Software
    public bool SoftwareChecked { get; set; }
    public List<string> RemoteAccessApps { get; set; } = new();
    public List<string> EndOfLifeApps { get; set; } = new();

    public List<string> Notes { get; set; } = new();
}

public sealed class AntivirusInfo
{
    public string Name { get; set; } = "";
    public bool Enabled { get; set; }
    public bool UpToDate { get; set; }

    /// <summary>Decodes Windows Security Center's productState number.</summary>
    public static AntivirusInfo FromProductState(string name, uint state) => new()
    {
        Name = name,
        Enabled = ((state >> 12) & 0xF) == 1,
        UpToDate = ((state >> 4) & 0xF) == 0,
    };
}

[JsonConverter(typeof(JsonStringEnumConverter<Answer>))]
public enum Answer { NotAsked, Yes, No, NotSure }

[JsonConverter(typeof(JsonStringEnumConverter<CheckStatus>))]
public enum CheckStatus
{
    /// <summary>Good.</summary>
    Pass,
    /// <summary>Not urgent, but worth fixing.</summary>
    Warn,
    /// <summary>A real risk: fix soon.</summary>
    Fail,
    /// <summary>Worth knowing; nothing to fix.</summary>
    Info,
    /// <summary>Couldn't be checked on this computer.</summary>
    NotChecked,
}

public sealed class CheckResult
{
    public string Id { get; set; } = "";
    public string Area { get; set; } = "";
    public string Title { get; set; } = "";
    public CheckStatus Status { get; set; }
    /// <summary>What was found, in plain words.</summary>
    public string Found { get; set; } = "";
    /// <summary>What to do about it. Empty when nothing needs doing.</summary>
    public string Fix { get; set; } = "";
    /// <summary>1 = most important. Used to order the fixes.</summary>
    public int Priority { get; set; } = 2;
}

/// <summary>One question the technician asks the owner, because a computer can't show the answer.</summary>
public sealed record OwnerQuestion(string Id, string Area, string Question, string Title, string FixIfNot, int Priority);

/// <summary>One Security Checkup of one computer, with the owner's answers.</summary>
public sealed class SecurityReport
{
    public string Tool { get; set; } = "Night Tech Security Checkup";
    public string ToolVersion { get; set; } = "";
    public string Business { get; set; } = "";
    public string Ticket { get; set; } = "";
    public string Technician { get; set; } = "";
    public DateTime Checked { get; set; }
    public SecurityFacts Facts { get; set; } = new();
    public Dictionary<string, Answer> Answers { get; set; } = new();
    public List<CheckResult> Results { get; set; } = new();
}
