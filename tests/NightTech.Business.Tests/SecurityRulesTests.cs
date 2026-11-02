using NightTech.Business.Core.Security;

namespace NightTech.Business.Tests;

public class SecurityRulesTests
{
    private static readonly DateTime Now = new(2026, 11, 2, 19, 0, 0);

    /// <summary>A well-set-up Windows 11 PC.</summary>
    private static SecurityFacts Good() => new()
    {
        ComputerName = "FRONT-DESK", OsName = "Microsoft Windows 11 Pro", LastUpdateInstalled = Now.AddDays(-10), RanAsAdministrator = true,
        BitLockerSystemDrive = "On",
        Antivirus = { AntivirusInfo.FromProductState("Microsoft Defender Antivirus", 397568) },
        DefenderRealTime = true, DefenderSignatureAgeDays = 0, DefenderTamperProtected = true,
        FirewallDomain = true, FirewallPrivate = true, FirewallPublic = true, SecureBoot = true, TpmReady = true,
        UacEnabled = true, LocalAdmins = { "ShopAdmin" }, BuiltInAdminEnabled = false, GuestEnabled = false,
        MinPasswordLength = 14, LockoutThreshold = 10, CurrentUserIsAdmin = false, AutoLogon = false, ScreenLockSeconds = 600,
        DomainJoined = false, RemoteDesktopOn = false, Smb1On = false, PowerShell2On = false, ListeningPorts = { 135, 445 }, AutoRunOff = true,
    };

    private static Dictionary<string, Answer> AllYes() => SecurityRules.Questions.ToDictionary(q => q.Id, _ => Answer.Yes);

    private static List<CheckResult> Eval(SecurityFacts f, Dictionary<string, Answer>? a = null) => SecurityRules.Evaluate(f, a ?? AllYes(), Now);

    private static CheckResult One(List<CheckResult> r, string id) => r.Single(x => x.Id == id);

    [Fact]
    public void Well_set_up_pc_passes_everything()
    {
        var r = Eval(Good());
        Assert.Empty(r.Where(x => x.Status is CheckStatus.Fail or CheckStatus.Warn));
        Assert.Empty(SecurityRules.TopFixes(r));
        Assert.DoesNotContain(r, x => x.Status != CheckStatus.Pass && x.Status != CheckStatus.Info);
    }

    [Theory]
    [InlineData("Off", CheckStatus.Fail)]
    [InlineData("Suspended", CheckStatus.Warn)]
    [InlineData("On", CheckStatus.Pass)]
    [InlineData("", CheckStatus.NotChecked)]
    public void Bitlocker(string state, CheckStatus expected)
    {
        var f = Good(); f.BitLockerSystemDrive = state;
        Assert.Equal(expected, One(Eval(f), "bitlocker").Status);
    }

    [Fact]
    public void Not_checked_items_say_why()
    {
        var f = Good(); f.BitLockerSystemDrive = ""; f.RanAsAdministrator = false;
        Assert.Contains("Run as administrator", One(Eval(f), "bitlocker").Found);
    }

    [Fact]
    public void Antivirus_off_or_stale_fails()
    {
        var f = Good(); f.Antivirus = new() { AntivirusInfo.FromProductState("Microsoft Defender Antivirus", 393472) };
        Assert.Equal(CheckStatus.Fail, One(Eval(f), "antivirus").Status);
        f = Good(); f.DefenderSignatureAgeDays = 9;
        Assert.Equal(CheckStatus.Fail, One(Eval(f), "antivirus").Status);
        f = Good(); f.DefenderSignatureAgeDays = 4;
        Assert.Equal(CheckStatus.Warn, One(Eval(f), "antivirus").Status);
    }

    [Fact]
    public void Firewall_off_on_any_profile_fails_and_names_it()
    {
        var f = Good(); f.FirewallPublic = false;
        var c = One(Eval(f), "firewall");
        Assert.Equal(CheckStatus.Fail, c.Status);
        Assert.Contains("Public", c.Found);
        Assert.NotEmpty(c.Fix);
    }

    [Fact]
    public void Windows_10_is_flagged_but_not_ltsc()
    {
        var f = Good(); f.OsName = "Microsoft Windows 10 Pro";
        Assert.Equal(CheckStatus.Fail, One(Eval(f), "os_support").Status);
        f.OsName = "Microsoft Windows 10 Enterprise LTSC";
        Assert.Equal(CheckStatus.Pass, One(Eval(f), "os_support").Status);
    }

    [Fact]
    public void Updates_age()
    {
        var f = Good(); f.LastUpdateInstalled = Now.AddDays(-60);
        Assert.Equal(CheckStatus.Warn, One(Eval(f), "updates").Status);
        f.LastUpdateInstalled = Now.AddDays(-120);
        Assert.Equal(CheckStatus.Fail, One(Eval(f), "updates").Status);
    }

    [Fact]
    public void Account_problems()
    {
        var f = Good();
        f.GuestEnabled = true; f.PasswordNotRequired = new() { "Kiosk" }; f.UacEnabled = false; f.CurrentUserIsAdmin = true;
        f.AutoLogon = true; f.AutoLogonPasswordStored = true; f.LockoutThreshold = 0; f.MinPasswordLength = 0;
        var r = Eval(f);
        Assert.Equal(CheckStatus.Fail, One(r, "guest").Status);
        Assert.Equal(CheckStatus.Warn, One(r, "pw_required").Status);
        Assert.Equal(CheckStatus.Fail, One(r, "uac").Status);
        Assert.Equal(CheckStatus.Warn, One(r, "daily_admin").Status);
        Assert.Equal(CheckStatus.Fail, One(r, "autologon").Status);
        Assert.Equal(CheckStatus.Warn, One(r, "lockout").Status);
        Assert.Contains("never lock", One(r, "lockout").Found);
        Assert.Equal(CheckStatus.Warn, One(r, "pw_length").Status);
    }

    [Fact]
    public void Domain_pc_doesnt_judge_local_password_rules()
    {
        var f = Good(); f.DomainJoined = true; f.MinPasswordLength = 0;
        var r = Eval(f);
        Assert.DoesNotContain(r, x => x.Id == "pw_length");
        Assert.Equal(CheckStatus.Info, One(r, "pw_policy").Status);
    }

    [Fact]
    public void Remote_desktop_without_nla_fails_with_nla_warns()
    {
        var f = Good(); f.RemoteDesktopOn = true; f.RemoteDesktopNla = false;
        Assert.Equal(CheckStatus.Fail, One(Eval(f), "rdp").Status);
        f.RemoteDesktopNla = true;
        Assert.Equal(CheckStatus.Warn, One(Eval(f), "rdp").Status);
    }

    [Fact]
    public void Risky_ports_and_old_protocols()
    {
        var f = Good(); f.ListeningPorts = new() { 135, 445, 23, 5900 }; f.Smb1On = true; f.PowerShell2On = true;
        var r = Eval(f);
        var ports = One(r, "ports");
        Assert.Equal(CheckStatus.Fail, ports.Status);
        Assert.Contains("Telnet (port 23)", ports.Found);
        Assert.Contains("VNC (port 5900)", ports.Found);
        Assert.Equal(CheckStatus.Fail, One(r, "smb1").Status);
        Assert.Equal(CheckStatus.Warn, One(r, "ps2").Status);
    }

    [Fact]
    public void Software_lists_match_by_name()
    {
        var installed = new[] { "TeamViewer 15", "AnyDesk", "Google Chrome", "Java(TM) 6 Update 45", "Java 17.0.2 (64-bit)", "Microsoft Office 2013" };
        Assert.Equal(new[] { "AnyDesk", "TeamViewer 15" }, SecurityRules.Match(installed, SecurityRules.RemoteAccessNames));
        Assert.Equal(new[] { "Java(TM) 6 Update 45", "Microsoft Office 2013" }, SecurityRules.Match(installed, SecurityRules.EndOfLifeNames));
    }

    [Fact]
    public void Owner_answers()
    {
        var a = AllYes();
        a["mfa_email"] = Answer.No; a["training"] = Answer.No; a["backup_tested"] = Answer.NotSure; a.Remove("wifi_guest");
        var r = Eval(Good(), a);
        Assert.Equal(CheckStatus.Fail, One(r, "q_mfa_email").Status);     // priority 1 "no" = fix soon
        Assert.Equal(CheckStatus.Warn, One(r, "q_training").Status);       // lower priority "no" = improve
        Assert.Equal(CheckStatus.Warn, One(r, "q_backup_tested").Status);
        Assert.StartsWith("Find out", One(r, "q_backup_tested").Fix);
        Assert.Equal(CheckStatus.NotChecked, One(r, "q_wifi_guest").Status);
        Assert.Equal("q_mfa_email", SecurityRules.TopFixes(r)[0].Id);
    }

    [Fact]
    public void Top_fixes_put_fix_soon_before_improve_then_by_priority()
    {
        var f = Good(); f.SecureBoot = false; f.FirewallPublic = false; f.CurrentUserIsAdmin = true;
        var fixes = SecurityRules.TopFixes(Eval(f));
        Assert.Equal("firewall", fixes[0].Id);
        Assert.Equal("daily_admin", fixes[1].Id);   // warn, priority 2
        Assert.Equal("secureboot", fixes[2].Id);    // warn, priority 3
    }

    [Fact]
    public void Report_saves_escapes_and_round_trips()
    {
        var f = Good(); f.ComputerName = "<b>PC</b>"; f.GuestEnabled = true;
        var rep = new SecurityReport { ToolVersion = "0.1.0", Business = "Joe's Diner & Grill", Ticket = "NT-0050", Checked = Now, Facts = f, Answers = AllYes() };
        rep.Results = SecurityRules.Evaluate(rep.Facts, rep.Answers, Now);
        var html = SecurityReportWriter.ToHtml(rep);
        Assert.DoesNotContain("<b>PC</b>", html);
        Assert.Contains("Joe&#39;s Diner &amp; Grill", html);
        Assert.Contains(SecurityReportWriter.Disclaimer, html);
        Assert.Contains("FIX SOON", html);
        var dir = Path.Combine(Path.GetTempPath(), "ntsc-" + Guid.NewGuid().ToString("N"));
        try
        {
            var saved = SecurityReportWriter.Save(rep, dir);
            Assert.StartsWith("security-NT-0050-", Path.GetFileName(saved.Json));
            var back = SecurityReportWriter.Load(saved.Json)!;
            Assert.Equal("Joe's Diner & Grill", back.Business);
            Assert.Equal(Answer.Yes, back.Answers["mfa_email"]);
            Assert.Equal(rep.Results.Count, back.Results.Count);
            Assert.Contains("\"status\": \"Fail\"", File.ReadAllText(saved.Json));
            Assert.Contains("WHAT TO FIX", File.ReadAllText(saved.Text));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void Business_summary_counts_problems_across_computers()
    {
        SecurityReport Rep(string pc, Action<SecurityFacts> change, DateTime when)
        {
            var f = Good(); f.ComputerName = pc; change(f);
            var rep = new SecurityReport { Business = "Joe's Diner", Checked = when, Facts = f, Answers = AllYes() };
            rep.Results = SecurityRules.Evaluate(f, rep.Answers, when);
            return rep;
        }
        var reports = new[]
        {
            Rep("FRONT", f => f.BitLockerSystemDrive = "Off", Now.AddHours(-2)),
            Rep("OFFICE", f => f.BitLockerSystemDrive = "Off", Now.AddHours(-1)),
            Rep("KITCHEN", _ => { }, Now),
        };
        var html = SecurityReportWriter.ToBusinessSummaryHtml(reports, "Joe's Diner");
        Assert.Contains("On 2 of 3 computer(s): FRONT, OFFICE.", html);
        Assert.Contains("OK on every computer checked.", html);
        Assert.Contains("KITCHEN", html);
    }
}
