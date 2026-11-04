using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NightTech.Business.Core.Sentinel;

namespace NightTech.Business.Tests;

public class SentinelTests
{
    private static readonly DateTime Now = new(2026, 11, 3, 12, 0, 0, DateTimeKind.Utc);

    // ---------------- Signatures and commands ----------------

    private static (ECDsa Key, TrustedKey Trusted) Tech(string name = "Jason")
    {
        var k = SentinelCrypto.NewSigningKey();
        var pub = SentinelCrypto.PublicKey(k);
        return (k, new TrustedKey { KeyId = SentinelCrypto.KeyId(pub), PublicKey = pub, Tech = name });
    }

    private static Command Cmd(TrustedKey t, CommandKind kind = CommandKind.RefreshNow, string device = "dev-1") => new()
    {
        Id = Guid.NewGuid().ToString("N"), DeviceId = device, Kind = kind, IssuedUtc = Now.AddMinutes(-1), ExpiresUtc = Now.AddMinutes(30),
        Tech = t.Tech, KeyId = t.KeyId,
    };

    [Fact]
    public void Genuine_command_is_accepted_once()
    {
        var (key, trusted) = Tech();
        var v = new CommandVerifier("dev-1", () => new[] { trusted });
        var signed = SignedCommand.Create(Cmd(trusted), key);
        var (c, why) = v.Verify(signed, Now);
        Assert.NotNull(c);
        Assert.Equal("", why);
        Assert.Equal("already used", v.Verify(signed, Now).Why);
    }

    [Fact]
    public void Command_from_an_untrusted_key_is_refused()
    {
        var (_, trusted) = Tech();
        var (otherKey, other) = Tech("Mallory");
        var v = new CommandVerifier("dev-1", () => new[] { trusted });
        Assert.Equal("signed by a key this PC doesn't trust", v.Verify(SignedCommand.Create(Cmd(other), otherKey), Now).Why);
        // A command claiming the trusted key ID but signed by another key.
        var forged = SignedCommand.Create(Cmd(trusted), otherKey);
        Assert.Equal("signature doesn't match", v.Verify(forged, Now).Why);
    }

    [Fact]
    public void Tampered_command_is_refused()
    {
        var (key, trusted) = Tech();
        var v = new CommandVerifier("dev-1", () => new[] { trusted });
        var signed = SignedCommand.Create(Cmd(trusted), key);
        var json = Encoding.UTF8.GetString(Convert.FromBase64String(signed.Payload)).Replace("RefreshNow", "RemoteShell");
        var tampered = new SignedCommand { Payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(json)), Signature = signed.Signature };
        Assert.Equal("signature doesn't match", v.Verify(tampered, Now).Why);
        Assert.Equal("not readable", v.Verify(new SignedCommand { Payload = "!!", Signature = "x" }, Now).Why);
        Assert.Equal("not readable", v.Verify(new SignedCommand { Payload = Convert.ToBase64String(Encoding.UTF8.GetBytes("{nope")), Signature = "x" }, Now).Why);
    }

    [Fact]
    public void Wrong_pc_expired_future_and_long_lived_commands_are_refused()
    {
        var (key, trusted) = Tech();
        var v = new CommandVerifier("dev-1", () => new[] { trusted });
        Assert.Equal("meant for a different PC", v.Verify(SignedCommand.Create(Cmd(trusted, device: "dev-2"), key), Now).Why);
        var old = Cmd(trusted); old.IssuedUtc = Now.AddHours(-3); old.ExpiresUtc = Now.AddHours(-1);
        Assert.Equal("expired", v.Verify(SignedCommand.Create(old, key), Now).Why);
        var future = Cmd(trusted); future.IssuedUtc = Now.AddHours(1); future.ExpiresUtc = Now.AddHours(2);
        Assert.Equal("dated in the future", v.Verify(SignedCommand.Create(future, key), Now).Why);
        var forever = Cmd(trusted); forever.ExpiresUtc = Now.AddDays(30);
        Assert.Equal("has an impossible lifetime", v.Verify(SignedCommand.Create(forever, key), Now).Why);
        var shortId = Cmd(trusted); shortId.Id = "abc";
        Assert.Equal("not readable", v.Verify(SignedCommand.Create(shortId, key), Now).Why);
    }

    [Fact]
    public void Damaged_trusted_key_list_is_refused()
    {
        var (key, trusted) = Tech();
        var (_, other) = Tech();
        var swapped = new TrustedKey { KeyId = trusted.KeyId, PublicKey = other.PublicKey, Tech = "x" };
        var v = new CommandVerifier("dev-1", () => new[] { swapped });
        Assert.Equal("trusted key list is damaged", v.Verify(SignedCommand.Create(Cmd(trusted), key), Now).Why);
    }

    [Fact]
    public void Seen_ids_are_forgotten_after_they_expire()
    {
        var (key, trusted) = Tech();
        var seen = new Dictionary<string, DateTime> { ["old"] = Now.AddHours(-1) };
        var v = new CommandVerifier("dev-1", () => new[] { trusted }, seen);
        v.Verify(SignedCommand.Create(Cmd(trusted), key), Now);
        Assert.False(v.Seen.ContainsKey("old"));
        Assert.Equal(1, v.Seen.Count);
    }

    [Fact]
    public void Webcrypto_style_signature_verifies()
    {
        // WebCrypto exports SPKI and signs with r||s (P1363): the same formats used here.
        using var k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var data = Encoding.UTF8.GetBytes("hello");
        var sig = k.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.Equal(64, sig.Length);
        Assert.True(SentinelCrypto.Verify(Convert.ToBase64String(k.ExportSubjectPublicKeyInfo()), data, Convert.ToBase64String(sig)));
        var der = k.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        Assert.False(SentinelCrypto.Verify(Convert.ToBase64String(k.ExportSubjectPublicKeyInfo()), data, Convert.ToBase64String(der)));
        Assert.False(SentinelCrypto.Verify("not-a-key", data, Convert.ToBase64String(sig)));
        using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        Assert.False(SentinelCrypto.Verify(Convert.ToBase64String(p384.ExportSubjectPublicKeyInfo()), data, Convert.ToBase64String(sig)));
    }

    [Fact]
    public void Key_ids_are_stable_and_readable()
    {
        var (_, t) = Tech();
        Assert.Equal(32, t.KeyId.Length);
        Assert.Equal(t.KeyId, SentinelCrypto.KeyId(t.PublicKey));
        Assert.Equal(8, SentinelCrypto.Readable(t.KeyId).Split(' ').Length);
        var code = SentinelCrypto.RandomCode(12);
        Assert.Equal(12, code.Length);
        Assert.DoesNotContain(code, ch => "01OI".Contains(ch));
    }

    // ---------------- Policy ----------------

    [Fact]
    public void Default_policy_asks_before_anything_powerful()
    {
        var p = new AgentPolicy();
        Assert.Equal(Decision.Run, p.Decide(CommandKind.ShieldScan));
        Assert.Equal(Decision.Run, p.Decide(CommandKind.DefenderUpdate));
        Assert.Equal(Decision.AskFirst, p.Decide(CommandKind.RemoteDesktop));
        Assert.Equal(Decision.AskFirst, p.Decide(CommandKind.RemoteShell));
        Assert.Equal(Decision.AskFirst, p.Decide(CommandKind.RunScript));
        Assert.Equal(Decision.AskFirst, p.Decide(CommandKind.Restart));
        Assert.Equal(Decision.AskFirst, p.Decide(CommandKind.ShieldFix));
        Assert.Equal(Decision.AskFirst, p.Decide(CommandKind.UpdateTrustedKeys));
        Assert.Equal(Decision.AskFirst, new AgentPolicy { Unattended = true }.Decide(CommandKind.UpdateTrustedKeys));
        Assert.Equal(Decision.Refuse, p.Decide((CommandKind)999));
    }

    [Fact]
    public void Unattended_and_turned_off_features()
    {
        var p = new AgentPolicy { Unattended = true, RestartWithoutAsking = true, AllowRemoteShell = false };
        Assert.Equal(Decision.Run, p.Decide(CommandKind.RemoteDesktop));
        Assert.Equal(Decision.Refuse, p.Decide(CommandKind.RemoteShell));
        Assert.Equal(Decision.Run, p.Decide(CommandKind.Restart));
        Assert.Equal(Decision.Refuse, new AgentPolicy { AllowScripts = false }.Decide(CommandKind.RunScript));
    }

    [Fact]
    public void Prompt_names_the_tech_and_how_to_say_no()
    {
        var c = new Command { Kind = CommandKind.RemoteDesktop, Tech = "Jason", Reason = "Printer won't print" };
        var p = CommandWords.Prompt(c);
        Assert.Contains("Jason from Night Tech Solutions would like to see and control this screen", p);
        Assert.Contains("Printer won't print", p);
        Assert.Contains("(864) 381-8510", p);
    }

    // ---------------- Encrypted sessions ----------------

    private static (SessionCrypto Browser, SessionCrypto Agent) Pair(string id = "sess-1")
    {
        using var b = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var a = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var bp = Convert.ToBase64String(b.ExportSubjectPublicKeyInfo());
        var ap = Convert.ToBase64String(a.ExportSubjectPublicKeyInfo());
        return (new SessionCrypto(b, ap, id, bp, ap, isAgent: false), new SessionCrypto(a, bp, id, bp, ap, isAgent: true));
    }

    [Fact]
    public void Session_frames_round_trip_both_ways()
    {
        var (b, a) = Pair();
        using (b) using (a)
        {
            Assert.Equal("dir", Encoding.UTF8.GetString(a.Open(b.Seal(Encoding.UTF8.GetBytes("dir")))));
            Assert.Equal("ok", Encoding.UTF8.GetString(b.Open(a.Seal(Encoding.UTF8.GetBytes("ok")))));
            Assert.Equal(0, a.Open(b.Seal(Array.Empty<byte>())).Length);
        }
    }

    [Fact]
    public void Session_rejects_tampering_replay_reflection_and_reordering()
    {
        var (b, a) = Pair();
        using (b) using (a)
        {
            var f1 = b.Seal(new byte[] { 1, 2, 3 });
            var f2 = b.Seal(new byte[] { 4 });
            var bad = (byte[])f1.Clone(); bad[10] ^= 1;
            Assert.ThrowsAny<CryptographicException>(() => a.Open(bad));
            a.Open(f2);
            Assert.ThrowsAny<CryptographicException>(() => a.Open(f1));       // older counter
            Assert.ThrowsAny<CryptographicException>(() => a.Open(f2));       // replay
            Assert.ThrowsAny<CryptographicException>(() => b.Open(b.Seal(new byte[] { 9 })));   // own frame sent back
            Assert.ThrowsAny<CryptographicException>(() => a.Open(new byte[10]));
        }
    }

    [Fact]
    public void Sessions_with_different_ids_cant_read_each_other()
    {
        var (b1, a1) = Pair("one");
        var (b2, a2) = Pair("two");
        using (b1) using (a1) using (b2) using (a2)
            Assert.ThrowsAny<CryptographicException>(() => a2.Open(b1.Seal(new byte[] { 1 })));
    }

    // ---------------- Sign-in ----------------

    [Fact]
    public void Totp_matches_rfc6238()
    {
        var secret = Encoding.ASCII.GetBytes("12345678901234567890");
        Assert.Equal("94287082", Totp.Code(secret, DateTimeOffset.FromUnixTimeSeconds(59), 8));
        Assert.Equal("07081804", Totp.Code(secret, DateTimeOffset.FromUnixTimeSeconds(1111111109), 8));
        Assert.Equal("287082", Totp.Code(secret, DateTimeOffset.FromUnixTimeSeconds(59)));
        var now = DateTimeOffset.FromUnixTimeSeconds(1111111109);
        Assert.NotNull(Totp.Check(secret, Totp.Code(secret, now.AddSeconds(-30)), now));
        Assert.Null(Totp.Check(secret, Totp.Code(secret, now.AddSeconds(-120)), now));
        Assert.Null(Totp.Check(secret, "12", now));
        Assert.Equal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Totp.Base32(secret));
        Assert.StartsWith("otpauth://totp/Night%20Tech%20Sentinel%3Ajason?secret=", Totp.SetupUri("jason", secret));
    }

    [Fact]
    public void Passwords_hash_and_check()
    {
        var h = Passwords.Hash("Correct horse battery 7");
        Assert.True(Passwords.Check("Correct horse battery 7", h));
        Assert.False(Passwords.Check("correct horse battery 7", h));
        Assert.False(Passwords.Check("x", "garbage"));
        Assert.False(Passwords.Check("x", "pbkdf2-sha256$10$AA==$AA=="));
        Assert.NotNull(Passwords.Problem("short"));
        Assert.NotNull(Passwords.Problem("MyPassword2026!"));
        Assert.NotNull(Passwords.Problem("aaaaaaaaaaaaaaaa"));
        Assert.Null(Passwords.Problem("Blue-Tractor-Gaffney-91"));
    }

    // ---------------- Enrollment ----------------

    [Fact]
    public void Enroll_token_round_trips_and_rejects_bad_input()
    {
        var (_, t) = Tech();
        var token = new EnrollToken { Server = "https://sentinel.example.com", Code = "ABCD2345EFGH", KeyIds = { t.KeyId }, Client = "Acme" }.Encode();
        Assert.StartsWith("NTS1.", token);
        var back = EnrollToken.Parse(token);
        Assert.NotNull(back);
        Assert.Equal(t.KeyId, back!.KeyIds.Single());
        Assert.Null(EnrollToken.Parse(new EnrollToken { Server = "http://sentinel.example.com", Code = "ABCD2345EFGH", KeyIds = { t.KeyId } }.Encode()));
        Assert.Null(EnrollToken.Parse(new EnrollToken { Server = "https://x.test", Code = "ABCD2345EFGH" }.Encode()));
        Assert.Null(EnrollToken.Parse("NTS1.!!!"));
        Assert.Null(EnrollToken.Parse("hello"));
    }

    // ---------------- Alerts ----------------

    private static HealthReport Healthy() => new()
    {
        TakenUtc = Now, Computer = "FRONT-DESK", LastBootUtc = Now.AddDays(-1),
        Antivirus = new AntivirusState { Products = { "Microsoft Defender Antivirus" }, Enabled = true, RealTime = true, UpToDate = true, DefenderSignatureAgeDays = 0 },
        Updates = new UpdateState { LastInstalledUtc = Now.AddDays(-5) },
        Backup = new BackupState { Tool = "Backup Buddy", LastSuccessUtc = Now.AddHours(-20), LastRunUtc = Now.AddHours(-20) },
        FirewallOn = true,
        Volumes = { new VolumeSpace { Name = "C:", SizeBytes = 500_000_000_000, FreeBytes = 200_000_000_000, IsSystem = true } },
        Drives = { new DriveHealth { Name = "Samsung SSD", Serial = "S1", Health = "Healthy", WearPercent = 3 } },
    };

    [Fact]
    public void Healthy_pc_has_no_alerts() => Assert.Empty(AlertRules.Evaluate(Healthy(), Now).Select(a => a.Key));

    [Fact]
    public void Problems_become_alerts()
    {
        var r = Healthy();
        r.HelpRequest = "Printer won't print";
        r.LoggedOnUser = "Front Desk";
        r.Volumes[0].FreeBytes = 10_000_000_000;
        r.Drives[0].WearPercent = 96;
        r.Antivirus.RealTime = false;
        r.Antivirus.DefenderSignatureAgeDays = 9;
        r.Updates.LastInstalledUtc = Now.AddDays(-70);
        r.Updates.RebootPending = true;
        r.LastBootUtc = Now.AddDays(-12);
        r.Backup.LastSuccessUtc = Now.AddDays(-8);
        r.BatteryHealthPercent = 55;
        r.BlueScreens7d = 3;
        r.FirewallOn = false;
        r.Security.Add(new SecurityItem { Id = "threat:1", Severity = "Risk", Title = "Malware found: Trojan", Detail = "x" });
        r.Security.Add(new SecurityItem { Id = "program:Wave", Severity = "Warning", Title = "Remove Wave Browser" });
        var a = AlertRules.Evaluate(r, Now).ToDictionary(x => x.Key);
        Assert.Equal(AlertLevel.Critical, a["help"].Level);
        Assert.Contains("Printer won't print", a["help"].Detail);
        Assert.Equal(AlertLevel.Critical, a["disk:C:"].Level);
        Assert.Equal(AlertLevel.Critical, a["drive-wear:S1"].Level);
        Assert.Equal(AlertLevel.Critical, a["av-realtime"].Level);
        Assert.Equal(AlertLevel.Critical, a["av-definitions"].Level);
        Assert.Equal(AlertLevel.Critical, a["updates"].Level);
        Assert.Equal(AlertLevel.Warning, a["reboot"].Level);
        Assert.Equal(AlertLevel.Critical, a["backup-old"].Level);
        Assert.Equal(AlertLevel.Warning, a["battery"].Level);
        Assert.Equal(AlertLevel.Critical, a["bsod"].Level);
        Assert.Equal(AlertLevel.Critical, a["firewall"].Level);
        Assert.Equal(AlertLevel.Critical, a["shield:threat:1"].Level);
        Assert.Contains("Remove Wave Browser", a["shield-warnings"].Detail);
    }

    [Fact]
    public void Backup_never_set_up_or_never_finished()
    {
        var r = Healthy(); r.Backup = new BackupState();
        Assert.Contains(AlertRules.Evaluate(r, Now), a => a.Key == "backup-none");
        r.Backup = new BackupState { Tool = "Backup Buddy", LastRunFailed = true };
        var keys = AlertRules.Evaluate(r, Now).Select(a => a.Key).ToList();
        Assert.Contains(keys, k => k == "backup-failed");
        Assert.Contains(keys, k => k == "backup-old");
    }

    [Fact]
    public void Offline_alert_after_a_day()
    {
        Assert.Null(AlertRules.Offline(Now.AddHours(-3), Now));
        Assert.Equal(AlertLevel.Warning, AlertRules.Offline(Now.AddHours(-30), Now)!.Level);
        Assert.Equal(AlertLevel.Critical, AlertRules.Offline(Now.AddDays(-4), Now)!.Level);
        Assert.Null(AlertRules.Offline(null, Now));
    }

    [Fact]
    public void Merge_keeps_start_time_clears_and_reraises_when_worse()
    {
        var first = new[] { new Alert { Key = "disk:C:", Level = AlertLevel.Warning, Title = "x", FirstSeenUtc = Now.AddDays(-2), LastSeenUtc = Now.AddDays(-2) } };
        var (all1, new1) = AlertRules.Merge(Array.Empty<Alert>(), first, Now.AddDays(-2));
        Assert.Equal(1, new1.Count);
        all1[0].Acknowledged = true;
        var (all2, new2) = AlertRules.Merge(all1, new[] { new Alert { Key = "disk:C:", Level = AlertLevel.Warning, Title = "x" } }, Now);
        Assert.Empty(new2.Select(a => a.Key));
        Assert.Equal(Now.AddDays(-2), all2[0].FirstSeenUtc);
        Assert.True(all2[0].Acknowledged);
        var (all3, new3) = AlertRules.Merge(all2, new[] { new Alert { Key = "disk:C:", Level = AlertLevel.Critical, Title = "y" } }, Now);
        Assert.Equal(1, new3.Count);
        Assert.False(all3[0].Acknowledged);
        var (all4, _) = AlertRules.Merge(all3, Array.Empty<Alert>(), Now);
        Assert.NotNull(all4[0].ClearedUtc);
        var (all5, new5) = AlertRules.Merge(all4, new[] { new Alert { Key = "disk:C:", Level = AlertLevel.Warning, Title = "z", FirstSeenUtc = Now } }, Now);
        Assert.Equal(2, all5.Count);
        Assert.Equal(1, new5.Count);
        var (all6, _) = AlertRules.Merge(all5, Array.Empty<Alert>(), Now.AddDays(1));
        var (all7, _) = AlertRules.Merge(all6, Array.Empty<Alert>(), Now.AddDays(200));
        Assert.Empty(all7.Select(a => a.Key));   // cleared alerts are kept 90 days
    }

    [Fact]
    public void Merge_leaves_the_offline_alert_to_the_server()
    {
        var off = new Alert { Key = "offline", Level = AlertLevel.Warning, Title = "o" };
        var (all, _) = AlertRules.Merge(Array.Empty<Alert>(), new[] { off }, Now);
        var (after, _) = AlertRules.Merge(all, Array.Empty<Alert>(), Now);
        Assert.Null(after[0].ClearedUtc);
        var (cleared, _) = AlertRules.Merge(all, Array.Empty<Alert>(), Now, includeOffline: true);
        Assert.NotNull(cleared[0].ClearedUtc);
    }

    // ---------------- Monthly report ----------------

    [Fact]
    public void Monthly_report_is_branded_and_encoded()
    {
        var month = new DateTime(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc);
        var devices = new List<DeviceMonth>
        {
            new()
            {
                Computer = "<FRONT>", LastSeenUtc = Now, Latest = Healthy(),
                Alerts =
                {
                    new Alert { Key = "disk:C:", Level = AlertLevel.Warning, Title = "C: is almost full", FirstSeenUtc = month.AddDays(3), ClearedUtc = month.AddDays(5) },
                    new Alert { Key = "battery", Level = AlertLevel.Warning, Title = "Battery is worn", FirstSeenUtc = month.AddDays(10) },
                },
                Work = { new CommandResult { Kind = CommandKind.CleanTemp, Outcome = "Done", FinishedUtc = month.AddDays(5) } },
            },
        };
        var html = MonthlyReport.Html("Acme & Sons", month, devices, Now);
        Assert.Contains("Acme &amp; Sons", html);
        Assert.Contains("&lt;FRONT&gt;", html);
        Assert.DoesNotContain("<FRONT>", html);
        Assert.Contains("October 2026", html);
        Assert.Contains("Battery is worn", html);
        Assert.Contains("Clear temporary files", html);
        Assert.Contains("(864) 381-8510", html);
        Assert.Contains("can't promise", html);
    }
}
