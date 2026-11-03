namespace NightTech.Business.Core;

/// <summary>Shared Night Tech Solutions branding and contact details used by every tool.</summary>
public static class Brand
{
    public const string Company = "Night Tech Solutions";
    public const string Website = "https://nighttech.solutions";
    public const string Phone = "(864) 381-8510";
    public const string ServiceArea = "Serving all of the Upstate, SC";
    public const string PhoneLink = "tel:+18643818510";
    public const string TextPhone = "(864) 497-2701";
    public const string Email = "nighttechsolutions1@gmail.com";
    public const string ContactUrl = "https://nighttech.solutions/contact/";
    public const string BusinessItUrl = "https://nighttech.solutions/business-it/";
    public const string SentinelUrl = "https://nighttech.solutions/sentinel/";
    public const string Hours = "Weeknights 6-11 PM, weekends 9 AM-6 PM, remote help during the day";
    /// <summary>The quiet scripture line used in Night Tech footers.</summary>
    public const string Verse = "\u201cWhatever you do, work heartily, as for the Lord.\u201d Colossians 3:23";

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
