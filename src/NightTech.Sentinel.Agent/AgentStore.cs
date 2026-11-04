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

    private static readonly SecurityIdentifier Admins = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);

    private static DirectorySecurity FolderSecurity(bool usersMayRead)
    {
        var sec = new DirectorySecurity();
        sec.SetAccessRuleProtection(true, false);
        var inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        sec.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        sec.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
        if (usersMayRead)
            sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), FileSystemRights.ReadAndExecute, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
        sec.SetOwner(Admins);
        return sec;
    }

    private static bool OwnedByAdmins(FileSystemSecurity sec) =>
        sec.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier o && (o.Equals(Admins) || o.Equals(SystemSid));

    /// <summary>
    /// Makes Sentinel's folder administrators-and-SYSTEM only. A new folder is created already locked; one that already
    /// exists must belong to administrators and not be a link (ProgramData lets any account create folders and files).
    /// Files in it that another account made are removed.
    /// </summary>
    public static void PrepareFolder()
    {
        var company = Path.GetDirectoryName(Folder)!;
        foreach (var path in new[] { company, Folder })
        {
            var dir = new DirectoryInfo(path);
            if (!dir.Exists) dir.Create(FolderSecurity(path == company));
            dir.Refresh();
            if ((dir.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException($"{path} is a link to another folder; Sentinel won't use it.");
            if (!OwnedByAdmins(dir.GetAccessControl()))
                throw new InvalidOperationException($"{path} was made by another account; Sentinel won't trust it. An administrator should delete it and run setup again.");
            dir.SetAccessControl(FolderSecurity(path == company));
        }
        foreach (var f in new DirectoryInfo(Folder).GetFiles())
            if ((f.Attributes & FileAttributes.ReparsePoint) != 0 || !OwnedByAdmins(f.GetAccessControl())) f.Delete();
    }

    public static AgentConfig? Load()
    {
        lock (Gate)
        {
            var fi = new FileInfo(ConfigPath);
            if (!fi.Exists) return null;
            if ((fi.Attributes & FileAttributes.ReparsePoint) != 0 || !OwnedByAdmins(fi.GetAccessControl()))
                throw new InvalidOperationException("Sentinel's settings file wasn't made by Sentinel, so it won't be used. Run setup again.");
            return JsonSerializer.Deserialize<AgentConfig>(File.ReadAllText(ConfigPath), Json);
        }
    }

    public static void Save(AgentConfig c)
    {
        lock (Gate)
        {
            PrepareFolder();
            var tmp = new FileInfo(ConfigPath + ".tmp");
            if (tmp.Exists) tmp.Delete();
            var fileSec = new FileSecurity();
            fileSec.SetAccessRuleProtection(true, false);
            fileSec.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
            fileSec.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, AccessControlType.Allow));
            fileSec.SetOwner(Admins);
            using (var fs = tmp.Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, fileSec))
                JsonSerializer.Serialize(fs, c, Json);
            File.Move(tmp.FullName, ConfigPath, overwrite: true);
        }
    }

    /// <summary>An administrators-only working file in Sentinel's folder (for scripts), deleted by the caller.</summary>
    public static string PrivateFile(string extension, string text)
    {
        PrepareFolder();
        var fi = new FileInfo(Path.Combine(Folder, "run-" + Guid.NewGuid().ToString("N") + extension));
        var fileSec = new FileSecurity();
        fileSec.SetAccessRuleProtection(true, false);
        fileSec.AddAccessRule(new FileSystemAccessRule(SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
        fileSec.AddAccessRule(new FileSystemAccessRule(Admins, FileSystemRights.FullControl, AccessControlType.Allow));
        using (var fs = fi.Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, fileSec))
        using (var w = new StreamWriter(fs, new System.Text.UTF8Encoding(true)))
            w.Write(text);
        return fi.FullName;
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
