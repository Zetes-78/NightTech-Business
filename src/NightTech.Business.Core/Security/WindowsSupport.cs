namespace NightTech.Business.Core.Security;

/// <summary>
/// When Microsoft stops security updates for a Windows version, from its build number and edition.
/// Keep this table up to date as Microsoft publishes new versions and dates (learn.microsoft.com/lifecycle).
/// </summary>
public static class WindowsSupport
{
    public sealed record Support(string Version, DateTime? Ends, string Note);

    // (build, Home/Pro end, Enterprise/Education end)
    private static readonly (int Build, string Name, DateTime HomePro, DateTime Enterprise)[] Win11 =
    {
        (22000, "Windows 11 21H2", new(2023, 10, 10), new(2024, 10, 8)),
        (22621, "Windows 11 22H2", new(2024, 10, 8), new(2025, 10, 14)),
        (22631, "Windows 11 23H2", new(2025, 11, 11), new(2026, 11, 10)),
        (26100, "Windows 11 24H2", new(2026, 10, 13), new(2027, 10, 12)),
        (26200, "Windows 11 25H2", new(2027, 10, 12), new(2028, 10, 10)),
    };

    public static Support For(string caption, string build, string edition)
    {
        int.TryParse(build, out var b);
        var name = caption ?? "";
        var ed = (edition ?? "") + " " + name;
        bool Has(string s) => ed.Contains(s, StringComparison.OrdinalIgnoreCase);
        bool enterprise = Has("Enterprise") || Has("Education");
        bool ltsc = Has("LTSC") || Has("LTSB");
        bool iot = Has("IoT");

        if (Has("Server"))
        {
            return b switch
            {
                >= 26100 => new("Windows Server 2025", new(2034, 10, 10), ""),
                >= 20348 => new("Windows Server 2022", new(2031, 10, 14), ""),
                >= 17763 => new("Windows Server 2019", new(2029, 1, 9), ""),
                >= 14393 => new("Windows Server 2016", new(2027, 1, 12), ""),
                > 0 => new("Windows Server 2012 R2 or older", new(2023, 10, 10), ""),
                _ => new("Windows Server", null, ""),
            };
        }

        if (b >= 22000)
        {
            if (ltsc && b >= 26100)
                return new("Windows 11 Enterprise LTSC 2024", iot ? new(2034, 10, 10) : new(2029, 10, 9), "");
            // Newest known version at or below this build (preview builds count as the version they follow).
            var row = Win11.Where(r => r.Build <= b).OrderByDescending(r => r.Build).FirstOrDefault();
            if (row.Name is null) return new("Windows 11", null, "");
            if (b > Win11[^1].Build + 99) return new("Windows 11 (newer than this tool knows)", null, "");
            return new(row.Name, enterprise ? row.Enterprise : row.HomePro, "");
        }

        if (b >= 10240)
        {
            if (ltsc)
                return b switch
                {
                    >= 19044 => new("Windows 10 Enterprise LTSC 2021", iot ? new(2032, 1, 13) : new(2027, 1, 12), ""),
                    >= 17763 => new("Windows 10 Enterprise LTSC 2019", new(2029, 1, 9), ""),
                    >= 14393 => new("Windows 10 Enterprise LTSB 2016", new(2026, 10, 13), ""),
                    _ => new("Windows 10 Enterprise LTSB 2015", new(2025, 10, 14), ""),
                };
            return new("Windows 10", new(2025, 10, 14),
                "Businesses can pay Microsoft for Extended Security Updates for a limited time.");
        }

        if (b > 0) return new("Windows 8.1 or older", new(2023, 1, 10), "");
        return new(name.Length > 0 ? name : "Windows", null, "");
    }
}
