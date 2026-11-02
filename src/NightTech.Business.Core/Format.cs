using System.Globalization;
using System.Text;

namespace NightTech.Business.Core;

public static class Format
{
    private static readonly string[] Units = { "bytes", "KB", "MB", "GB", "TB", "PB" };

    /// <summary>Size the way Windows shows it (1 GB = 1024 MB).</summary>
    public static string Bytes(long? bytes)
    {
        if (bytes is not { } b) return "unknown";
        if (b < 1024) return b.ToString(CultureInfo.InvariantCulture) + " bytes";
        double v = b;
        var i = 0;
        while (v >= 1024 && i < Units.Length - 1) { v /= 1024; i++; }
        return v.ToString(v >= 100 ? "0" : "0.#", CultureInfo.InvariantCulture) + " " + Units[i];
    }

    public static string Date(DateTime? d) =>
        d is { } x ? x.ToString("MMM d, yyyy", CultureInfo.InvariantCulture) : "unknown";

    public static string DateAndTime(DateTime? d) =>
        d is { } x ? x.ToString("MMM d, yyyy h:mm tt", CultureInfo.InvariantCulture) : "unknown";

    public static string YesNo(bool? b, string yes = "Yes", string no = "No") => b switch
    {
        true => yes,
        false => no,
        null => "not checked",
    };

    private static readonly string[] Placeholders =
    {
        "system manufacturer", "system product name", "system serial number", "system version",
        "to be filled by o.e.m.", "to be filled by oem", "default string", "default", "o.e.m.", "oem",
        "not applicable", "not specified", "not available", "none", "n/a", "invalid", "unknown",
        "base board serial number", "chassis serial number", "0", "00000000", "123456789", "1234567890", "x.x",
    };

    /// <summary>
    /// True for the filler text motherboard makers leave in the BIOS when no PC maker filled it in
    /// (common on custom-built PCs), such as "System Product Name" or "To Be Filled By O.E.M.".
    /// </summary>
    public static bool IsPlaceholder(string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 0) return true;
        if (v.Trim('0', ' ', '-', '.', 'x', 'X', 'f', 'F').Length == 0) return true;
        return Placeholders.Contains(v.ToLowerInvariant());
    }

    /// <summary>A file name made only of safe characters, e.g. "NT-0012-DESKTOP-ABC-20261101-1830".</summary>
    public static string SafeFileName(string text, int max = 80)
    {
        var sb = new StringBuilder();
        foreach (var ch in text.Trim())
        {
            if (char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_') sb.Append(ch);
            else if (ch is ' ' or '.' && sb.Length > 0 && sb[^1] != '-') sb.Append('-');
        }
        var s = sb.ToString().Trim('-');
        if (s.Length > max) s = s[..max].TrimEnd('-');
        return s.Length == 0 ? "computer" : s;
    }
}
