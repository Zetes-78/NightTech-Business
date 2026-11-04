using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Sentinel.Agent;

/// <summary>What this PC knows about its Sentinel setup. Kept in an administrators-only folder.</summary>
public sealed class AgentConfig
{
    public int Schema { get; set; } = 1;
    public string Server { get; set; } = "";
    public string DeviceId { get; set; } = "";
    public string ClientName { get; set; } = "";
    public int CheckInMinutes { get; set; } = 15;
    /// <summary>Tech keys this PC trusts. Pinned at install from the enrollment token; changed only by a command signed with one of them.</summary>
    public List<TrustedKey> TrustedKeys { get; set; } = new();
    /// <summary>Chosen at install; the server can't change it.</summary>
    public AgentPolicy Policy { get; set; } = new();
    /// <summary>Command IDs already run (until they expire), so a signed command can't be used twice, even after a restart.</summary>
    public Dictionary<string, DateTime> SeenCommands { get; set; } = new();
    /// <summary>Results waiting to go to the server with the next check-in.</summary>
    public List<CommandResult> PendingResults { get; set; } = new();
    public DateTime? LastCheckInUtc { get; set; }
    public string LastStatus { get; set; } = "";
}

public static class AgentStore
{
    public static string Folder => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Night Tech Solutions", "Sentinel");
    private static string ConfigPath => Path.Combine(Folder, "agent.json");
    private const string KeyName = "NightTechSentinelDevice";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private static readonly object Gate = new();

    /// <summary>
    /// Makes Sentinel's folder administrators-and-SYSTEM only, refusing one that someone else made first or that is a
    /// link to somewhere else (ProgramData lets any account create folders).
    /// </summary>
    public static void PrepareFolder()
    {
        var company = Path.GetDirectoryName(Folder)!;
        foreach (var path in new[] { company, Folder })
        {
            var dir = new DirectoryInfo(path);
            if (!dir.Exists) dir.Create();
            dir.Refresh();
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"{path} is a link to another folder; Sentinel won't use it.");
            var owner = dir.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
            if (owner is null || !(owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || owner.IsWellKnown(WellKnownSidType.LocalSystemSid)))
                throw new InvalidOperationException($"{path} was made by another account; Sentinel won't trust it.");
            var sec = new DirectorySecurity();
            sec.SetAccessRuleProtection(true, false);
            var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            if (path == company)
                sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
            sec.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
            dir.SetAccessControl(sec);
        }
    }

    public static AgentConfig? Load()
    {
        lock (Gate)
        {
            if (!File.Exists(ConfigPath)) return null;
            return JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(ConfigPath), Json);
        }
    }

    public static void Save(AgentConfig c)
    {
        lock (Gate)
        {
            PrepareFolder();
            var tmp = ConfigPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(c, Json));
            File.Move(tmp, ConfigPath, overwrite: true);
        }
    }

    /// <summary>
    /// The PC's own signing key, made once and kept by Windows in the machine key store. It can't be exported, so the
    /// key can't be copied to impersonate this PC from somewhere else.
    /// </summary>
    public static ECDsa DeviceKey()
    {
        CngKey key;
        if (CngKey.Exists(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey))
            key = CngKey.Open(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey);
        else
            key = CngKey.Create(CngAlgorithm.ECDsaP256, KeyName, new CngKeyCreationParameters
            {
                Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                KeyCreationOptions = CngKeyCreationOptions.MachineKey,
                ExportPolicy = CngExportPolicies.None,
                KeyUsage = CngKeyUsages.Signing,
            });
        return new ECDsaCng(key);
    }

    /// <summary>Forgets the device key (when Sentinel is removed or set up again for another client).</summary>
    public static void DeleteDeviceKey()
    {
        if (CngKey.Exists(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey))
            CngKey.Open(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider, CngKeyOpenOptions.MachineKey).Delete();
    }
}
