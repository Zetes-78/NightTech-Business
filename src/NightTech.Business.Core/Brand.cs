namespace NightTech.Business.Core;

/// <summary>Shared Night Tech Solutions branding and contact details used by every tool.</summary>
public static class Brand
{
    public const string Company = "Night Tech Solutions";
    public const string Website = "https://nighttech.solutions";
    public const string Phone = "(864) 381-8510";
    public const string ServiceArea = "Serving all of the Upstate, SC";

    // Colors (hex) match the website and printed materials.
    public const string Navy = "#1A365D";
    public const string Blue = "#4299E1";
    public const string Orange = "#FF6B35";
    public const string OrangeAccessible = "#C2410C";
    public const string Gray = "#F7FAFC";

    /// <summary>Folder for a tool's logs and settings: %LOCALAPPDATA%\Night Tech\&lt;tool&gt;.</summary>
    public static string AppDataFolder(string toolName)
    {
        var baseDir = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(baseDir))
            baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        var dir = Path.Combine(baseDir, "Night Tech", toolName);
        Directory.CreateDirectory(dir);
        return dir;
    }
}
