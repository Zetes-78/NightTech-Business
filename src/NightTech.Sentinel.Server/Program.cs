using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using NightTech.Business.Core.Sentinel;
using NightTech.Sentinel.Server;

var builder = WebApplication.CreateBuilder(args);
var dataDir = Environment.GetEnvironmentVariable("SENTINEL_DATA") ?? Path.Combine(AppContext.BaseDirectory, "data");
Directory.CreateDirectory(dataDir);
var store = new Store(dataDir);
var auth = new Auth(store);
var live = new Live(store);
var notify = new Notify(store);
var requests = new SignRequests();
var signerAuth = new SignerAuth(store);
var minCheckIn = TimeSpan.FromSeconds(int.TryParse(Environment.GetEnvironmentVariable("SENTINEL_MIN_CHECKIN_SECONDS"), out var mc) ? mc : 20);
builder.Services.AddSingleton(store).AddSingleton(auth).AddSingleton(live).AddSingleton(notify);
builder.Services.AddHostedService<OfflineWatch>();
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    o.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
});
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    // Caddy or Cloudflare Tunnel sits in front on the same private network.
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownNetworks.Clear();
    o.KnownProxies.Clear();
    foreach (var net in new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8" })
        o.KnownNetworks.Add(Microsoft.AspNetCore.HttpOverrides.IPNetwork.Parse(net));
});
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddPolicy("strict", ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "?",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 20, Window = TimeSpan.FromMinutes(5) }));
});
builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = 2 * 1024 * 1024);

var app = builder.Build();
app.UseForwardedHeaders();
app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data: blob:; connect-src 'self' wss:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    h["X-Content-Type-Options"] = "nosniff";
    h["Referrer-Policy"] = "no-referrer";
    h["X-Frame-Options"] = "DENY";
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    await next();
});
app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(30) });
app.UseRateLimiter();
app.UseDefaultFiles();
app.UseStaticFiles();

var setupToken = Auth.SetupToken(dataDir);
if (store.Techs.Count == 0)
    app.Logger.LogWarning("No technicians yet. Open the console and use this setup code to create the first one: {Token}", setupToken);

string Ip(HttpContext c) => c.Connection.RemoteIpAddress?.ToString() ?? "";
var json = new JsonSerializerOptions(JsonSerializerDefaults.Web);

// ======================= Client PCs =======================

app.MapPost("/api/agent/enroll", (EnrollRequest req, HttpContext ctx) =>
{
    var result = store.Change<IResult>(() =>
    {
        var code = store.CodeList.FirstOrDefault(c => SentinelCrypto.FixedTimeEquals(c.Code, req.Code ?? ""));
        if (code is null || code.ExpiresUtc < DateTime.UtcNow || code.UsesLeft <= 0) return Results.StatusCode(403);
        string deviceId;
        try { deviceId = SentinelCrypto.DeviceId(req.PublicKey); } catch (Exception e) when (e is FormatException or ArgumentNullException) { return Results.BadRequest(); }
        if (store.Device(deviceId) is { Retired: false }) return Results.StatusCode(409);
        var client = store.ClientList.FirstOrDefault(c => c.Id == code.ClientId);
        if (client is null) return Results.StatusCode(403);
        code.UsesLeft--;
        store.SaveCodes();
        var device = new Device
        {
            Id = deviceId, ClientId = client.Id, Computer = Clip(req.Computer, 64),
            PublicKey = req.PublicKey, EnrolledUtc = DateTime.UtcNow, LastIp = Ip(ctx),
        };
        store.SaveDevice(device);
        store.Audit("pc:" + device.Id, $"{device.Computer} joined {client.Name} from {Ip(ctx)}");
        var keys = store.TechList.Where(t => !t.Disabled).SelectMany(t => t.Keys).ToList();
        return Results.Ok(new EnrollResponse { DeviceId = device.Id, ClientName = client.Name, CheckInMinutes = 15, TechKeys = keys });
    });
    return result;
}).RequireRateLimiting("strict");

app.MapPost("/api/agent/checkin", (CheckIn body, HttpContext ctx) =>
{
    var device = store.Device(body.DeviceId);
    if (device is null) return Results.StatusCode(403);
    if (device.Retired) return Results.StatusCode(410);
    byte[] payload;
    try { payload = Convert.FromBase64String(body.Payload ?? ""); } catch (FormatException) { return Results.BadRequest(); }
    if (payload.Length > 1_500_000 || !SentinelCrypto.Verify(device.PublicKey, payload, body.Signature ?? "")) return Results.StatusCode(403);
    HealthReport? report;
    try { report = JsonSerializer.Deserialize<HealthReport>(payload, json); } catch (JsonException) { return Results.BadRequest(); }
    var now = DateTime.UtcNow;
    // A replayed (older) report, or one from far in the future, is refused.
    if (report is null || report.DeviceId != device.Id || Math.Abs((report.TakenUtc - now).TotalMinutes) > 15
        || device.Latest is { } prev && report.TakenUtc <= prev.TakenUtc) return Results.StatusCode(409);
    if (device.LastSeenUtc is { } seen && now - seen < minCheckIn) return Results.StatusCode(429);
    Limit(report);

    List<Alert> fresh = new();
    var queued = store.Change(() =>
    {
        device.Latest = report;
        device.LastSeenUtc = now;
        device.LastIp = Ip(ctx);
        device.Computer = Clip(report.Computer, 64);
        var (all, news) = AlertRules.Merge(device.Alerts, AlertRules.Evaluate(report, now), now);
        all.RemoveAll(a => a.Key == "offline" && a.ClearedUtc is null);   // it's back
        if (all.Count > 300) all = all.OrderBy(a => a.ClearedUtc is null).ThenBy(a => a.LastSeenUtc).Skip(all.Count - 300).ToList();
        device.Alerts = all;
        fresh = news;
        foreach (var r in report.Results.Where(r => device.History.All(h => h.CommandId != r.CommandId)))
        {
            r.Output = CommandResult.Trim(r.Output ?? "");
            device.History.Add(r);
            store.Audit("pc:" + device.Id, $"{r.Kind} {r.CommandId}: {r.Outcome}. {Clip(r.Detail, 300)}");
        }
        if (device.History.Count > 500) device.History.RemoveRange(0, device.History.Count - 500);
        device.Queue.RemoveAll(q => q.ExpiresUtc < now || q.DeliveredUtc is { } d && now - d > TimeSpan.FromDays(1));
        var waiting = device.Queue.Where(q => q.DeliveredUtc is null).ToList();
        foreach (var q in waiting) q.DeliveredUtc = now;
        store.SaveDevice(device);
        return waiting;
    });
    if (fresh.Count > 0) _ = notify.NewAlerts(device, fresh);
    var help = device.Alerts.FirstOrDefault(a => a.Key == "help" && a.ClearedUtc is null);
    return Results.Ok(new CheckInResponse
    {
        CheckInMinutes = 15,
        Commands = queued.Select(q => q.Signed).ToList(),
        Status = help is not null && help.Acknowledged ? "Night Tech has your help request." : "Monitored by Night Tech Solutions",
    });
});

app.Map("/api/agent/live", async ctx =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 400; return; }
    using var ws = await ctx.WebSockets.AcceptWebSocketAsync();
    await live.AgentLive(ws, ctx.RequestAborted);
});

app.Map("/api/agent/session/{sid}", async (HttpContext ctx, string sid) =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 400; return; }
    using var ws = await ctx.WebSockets.AcceptWebSocketAsync();
    await live.AgentSession(ws, sid, ctx.RequestAborted);
});

// ======================= Technician console =======================

// Every console change needs this header as well as the SameSite cookie, so other sites can't make the browser send requests.
bool CsrfOk(HttpContext c) => c.Request.Headers["X-Sentinel"] == "1";

IResult? Guard(HttpContext c, out Tech tech)
{
    tech = auth.Current(c)!;
    if (tech is null) return Results.Unauthorized();
    if (!HttpMethods.IsGet(c.Request.Method) && !CsrfOk(c)) return Results.StatusCode(403);
    return null;
}

app.MapGet("/api/setup", () => Results.Ok(new { needed = store.Techs.Count == 0 }));

app.MapPost("/api/setup", (SetupRequest r, HttpContext ctx) =>
{
    if (!CsrfOk(ctx)) return Results.StatusCode(403);
    return store.Change<IResult>(() =>
    {
        if (store.TechList.Count > 0) return Results.StatusCode(403);
        if (!SentinelCrypto.FixedTimeEquals(r.SetupToken?.Trim() ?? "", setupToken)) return Results.BadRequest(new { error = "That setup code isn't right. It's in the server's log and in setup-token.txt in the data folder." });
        return NewTech(r.User, r.Name, r.Password, "setup");
    });
}).RequireRateLimiting("strict");

IResult NewTech(string user, string name, string password, string by)
{
    user = (user ?? "").Trim().ToLowerInvariant();
    if (!System.Text.RegularExpressions.Regex.IsMatch(user, "^[a-z0-9._-]{2,32}$")) return Results.BadRequest(new { error = "Use 2 to 32 letters, numbers, dots or dashes for the user name." });
    if (store.TechList.Any(t => t.User == user)) return Results.BadRequest(new { error = "That user name is taken." });
    if (Passwords.Problem(password) is { } problem) return Results.BadRequest(new { error = problem });
    var secret = Totp.NewSecret();
    var tech = new Tech { Id = "tech_" + SentinelCrypto.RandomCode(12).ToLowerInvariant(), User = user, Name = Clip(name, 60), PasswordHash = Passwords.Hash(password), TotpSecret = Convert.ToBase64String(secret) };
    store.TechList.Add(tech);
    store.SaveTechs();
    store.Audit(by, $"Added technician {user}");
    return Results.Ok(new { totpSecret = Totp.Base32(secret), totpUri = Totp.SetupUri(user, secret) });
}

app.MapPost("/api/login", (LoginRequest r, HttpContext ctx) =>
{
    if (!CsrfOk(ctx)) return Results.StatusCode(403);
    var result = auth.Login(r.User, r.Password, r.Code, Ip(ctx));
    if (!result.Ok) return Results.BadRequest(new { error = result.Error });
    Auth.SetCookie(ctx, result.Token);
    return Results.Ok();
}).RequireRateLimiting("strict");

app.MapPost("/api/logout", (HttpContext ctx) => { auth.Logout(ctx); ctx.Response.Cookies.Delete(Auth.Cookie); return Results.Ok(); });

app.MapGet("/api/me", (HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    return Results.Ok(new { t.User, t.Name, keys = t.Keys, allKeys = store.Techs.Where(x => !x.Disabled).SelectMany(x => x.Keys) });
});

app.MapPost("/api/techs", (NewTechRequest r, HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    return store.Change(() => NewTech(r.User, r.Name, r.Password, t.User));
});

app.MapPost("/api/keys", (TrustedKey k, HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    string id;
    try { id = SentinelCrypto.KeyId(k.PublicKey); } catch (FormatException) { return Results.BadRequest(new { error = "That isn't a key." }); }
    return store.Change<IResult>(() =>
    {
        var tech = store.TechList.First(x => x.Id == t.Id);
        if (tech.Keys.Any(x => x.KeyId == id)) return Results.Ok(new { keyId = id });
        if (tech.Keys.Count >= 5) return Results.BadRequest(new { error = "Five keys at most. Remove an old one first." });
        tech.Keys.Add(new TrustedKey { KeyId = id, PublicKey = k.PublicKey, Tech = tech.Name.Length > 0 ? tech.Name : tech.User });
        store.SaveTechs();
        store.Audit(t.User, $"Added signing key {id}");
        return Results.Ok(new { keyId = id });
    });
});

app.MapGet("/api/clients", (HttpContext ctx) =>
{
    if (Guard(ctx, out _) is { } bad) return bad;
    return Results.Ok(store.Clients.Select(c => new
    {
        c.Id, c.Name, c.Contact, c.Email, c.Notes,
        devices = store.Devices.Count(d => d.ClientId == c.Id && !d.Retired),
        alerts = store.Devices.Where(d => d.ClientId == c.Id && !d.Retired).Sum(d => d.Alerts.Count(a => a.ClearedUtc is null && !a.Acknowledged)),
    }));
});

app.MapPost("/api/clients", (Client c, HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    if (string.IsNullOrWhiteSpace(c.Name)) return Results.BadRequest(new { error = "The client needs a name." });
    var client = new Client { Id = "cli_" + SentinelCrypto.RandomCode(10).ToLowerInvariant(), Name = Clip(c.Name, 80), Contact = Clip(c.Contact, 80), Email = Clip(c.Email, 120), Notes = Clip(c.Notes, 1000), CreatedUtc = DateTime.UtcNow };
    store.Change(() => { store.ClientList.Add(client); store.SaveClients(); });
    store.Audit(t.User, $"Added client {client.Name}");
    return Results.Ok(client);
});

app.MapPost("/api/clients/{id}/codes", (string id, CodeRequest r, HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    if (store.Clients.All(c => c.Id != id)) return Results.NotFound();
    var code = new EnrollCode { Code = SentinelCrypto.RandomCode(16), ClientId = id, ExpiresUtc = DateTime.UtcNow.AddDays(Math.Clamp(r.Days, 1, 30)), UsesLeft = Math.Clamp(r.Uses, 1, 500), CreatedBy = t.User };
    store.Change(() => { store.CodeList.RemoveAll(c => c.ExpiresUtc < DateTime.UtcNow || c.UsesLeft <= 0); store.CodeList.Add(code); store.SaveCodes(); });
    store.Audit(t.User, $"Made an enrollment code for {id} ({code.UsesLeft} PCs, {r.Days} days)");
    return Results.Ok(new { code = code.Code, expiresUtc = code.ExpiresUtc, uses = code.UsesLeft });
});

object Summary(Device d) => new
{
    d.Id, d.ClientId, client = store.Clients.FirstOrDefault(c => c.Id == d.ClientId)?.Name ?? "", d.Computer, d.LastSeenUtc, online = live.IsOnline(d.Id),
    user = d.Latest?.LoggedOnUser ?? "", windows = d.Latest?.Windows ?? "", d.Note,
    critical = d.Alerts.Count(a => a.ClearedUtc is null && a.Level == AlertLevel.Critical && !a.Acknowledged),
    warnings = d.Alerts.Count(a => a.ClearedUtc is null && a.Level == AlertLevel.Warning && !a.Acknowledged),
};

app.MapGet("/api/devices", (HttpContext ctx) =>
{
    if (Guard(ctx, out _) is { } bad) return bad;
    return Results.Ok(store.Devices.Where(d => !d.Retired).OrderBy(d => d.Computer).Select(Summary));
});

app.MapGet("/api/devices/{id}", (string id, HttpContext ctx) =>
{
    if (Guard(ctx, out _) is { } bad) return bad;
    var d = store.Device(id);
    if (d is null || d.Retired) return Results.NotFound();
    // Copied while holding the lock, so a check-in can't change the lists halfway through.
    var text = store.Change(() => JsonSerializer.Serialize(new
    {
        summary = Summary(d), d.PublicKey, keyId = SentinelCrypto.KeyId(d.PublicKey), latest = d.Latest,
        alerts = d.Alerts.OrderByDescending(a => a.ClearedUtc is null).ThenByDescending(a => a.Level).ThenByDescending(a => a.LastSeenUtc).ToList(),
        history = d.History.AsEnumerable().Reverse().Take(100).ToList(), queue = d.Queue.Select(q => new { q.Id, q.Kind, q.Tech, q.ExpiresUtc, q.DeliveredUtc }).ToList(),
    }, json));
    return Results.Content(text, "application/json");
});

app.MapPost("/api/devices/{id}/note", (string id, NoteRequest r, HttpContext ctx) =>
{
    if (Guard(ctx, out _) is { } bad) return bad;
    var d = store.Device(id);
    if (d is null) return Results.NotFound();
    store.Change(() => { d.Note = Clip(r.Note, 2000); store.SaveDevice(d); });
    return Results.Ok();
});

app.MapPost("/api/devices/{id}/alerts/{key}/ack", (string id, string key, HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    var d = store.Device(id);
    if (d is null) return Results.NotFound();
    store.Change(() =>
    {
        foreach (var a in d.Alerts.Where(a => a.Key == key && a.ClearedUtc is null)) a.Acknowledged = true;
        store.SaveDevice(d);
    });
    store.Audit(t.User, $"Acknowledged {key} on {d.Computer}");
    return Results.Ok();
});

app.MapPost("/api/devices/{id}/retire", (string id, HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    var d = store.Device(id);
    if (d is null) return Results.NotFound();
    store.Change(() => { d.Retired = true; d.Queue.Clear(); store.SaveDevice(d); });
    store.Audit(t.User, $"Removed {d.Computer} ({d.Id})");
    return Results.Ok();
});

// The browser signs commands with the tech's own key. The server checks the signature too (so it doesn't queue junk),
// but the PC checks again: the server is never the one deciding what a PC runs.
app.MapPost("/api/devices/{id}/commands", async (string id, SignedCommand signed, HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    var d = store.Device(id);
    if (d is null || d.Retired) return Results.NotFound();
    var verifier = new CommandVerifier(d.Id, () => t.Keys);
    var (c, why) = verifier.Verify(signed, DateTime.UtcNow);
    if (c is null) return Results.BadRequest(new { error = $"The command was refused: it {why}." });
    return await Queue(d, c, signed, t);
});

// ======================= Approval in Sentinel Signer =======================

// Queues a command the Signer signed, after checking it's really what was asked for.
async Task<IResult> Queue(Device d, Command c, SignedCommand signed, Tech t)
{
    var q = new QueuedCommand { Id = c.Id, Kind = c.Kind, Tech = t.User, ExpiresUtc = c.ExpiresUtc, Signed = signed };
    store.Change(() => { d.Queue.Add(q); store.SaveDevice(d); });
    if (c.Kind is CommandKind.RemoteDesktop or CommandKind.RemoteShell) live.ExpectSession(c.Arg("sessionId"), d.Id, t.Id);
    store.Audit(t.User, $"Sent {c.Kind} ({c.Id}) to {d.Computer}{(c.Reason.Length > 0 ? ": " + Clip(c.Reason, 200) : "")}");
    return Results.Ok(new { delivered = await live.Push(d, q) });
}

app.MapPost("/api/devices/{id}/requests", (string id, ActionRequest r, HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    var d = store.Device(id);
    if (d is null || d.Retired) return Results.NotFound();
    if (!Enum.TryParse<CommandKind>(r.Kind, out var kind) || !Enum.IsDefined(kind)) return Results.BadRequest(new { error = "Unknown action." });
    var args = (r.Args ?? new()).Take(10).ToDictionary(kv => Clip(kv.Key, 40), kv => kv.Value is { Length: > 200_000 } ? kv.Value[..200_000] : kv.Value ?? "");
    try
    {
        var req = requests.Add(new SignRequest
        {
            TechId = t.Id, DeviceId = d.Id, Computer = d.Computer, Client = store.Clients.FirstOrDefault(c => c.Id == d.ClientId)?.Name ?? "",
            Kind = kind, Args = args, Reason = Clip(r.Reason, 300), Minutes = Math.Clamp(r.Minutes, 5, 240),
        });
        return Results.Ok(new { id = req.Id });
    }
    catch (InvalidOperationException e) { return Results.BadRequest(new { error = e.Message }); }
});

app.MapGet("/api/requests/{rid}", (string rid, HttpContext ctx) =>
{
    if (Guard(ctx, out var t) is { } bad) return bad;
    var r = requests.Get(rid);
    if (r is null || r.TechId != t.Id) return Results.NotFound();
    return Results.Ok(new { r.Status, r.Delivered, r.Error });
});

app.MapGet("/api/signer/pending", (HttpContext ctx) =>
{
    if (signerAuth.Check(ctx) is not { } who) return Results.Unauthorized();
    return Results.Ok(requests.Waiting(who.Tech.Id).Select(r => new { r.Id, r.DeviceId, r.Computer, r.Client, r.Kind, r.Args, r.Reason, r.Minutes, r.CreatedUtc }));
});

app.MapPost("/api/signer/requests/{rid}/approve", async (string rid, SignedCommand signed, HttpContext ctx) =>
{
    if (signerAuth.Check(ctx) is not { } who) return Results.Unauthorized();
    var r = requests.Get(rid);
    if (r is null || r.TechId != who.Tech.Id || r.Status != "Waiting") return Results.NotFound();
    var d = store.Device(r.DeviceId);
    if (d is null || d.Retired) return Results.NotFound();
    var (c, why) = new CommandVerifier(d.Id, () => new[] { who.Key }).Verify(signed, DateTime.UtcNow);
    if (c is null) { r.Error = "The signed command was refused: it " + why + "."; return Results.BadRequest(new { error = r.Error }); }
    if (c.Kind != r.Kind || c.Reason != r.Reason || c.Args.Count != r.Args.Count || c.Args.Any(kv => !r.Args.TryGetValue(kv.Key, out var v) || v != kv.Value))
        return Results.BadRequest(new { error = "The signed command isn't the one that was asked for." });
    r.Status = "Approved";
    var result = await Queue(d, c, signed, who.Tech);
    r.Delivered = live.IsOnline(d.Id);
    return result;
});

app.MapPost("/api/signer/requests/{rid}/reject", (string rid, HttpContext ctx) =>
{
    if (signerAuth.Check(ctx) is not { } who) return Results.Unauthorized();
    var r = requests.Get(rid);
    if (r is null || r.TechId != who.Tech.Id) return Results.NotFound();
    r.Status = "Rejected";
    store.Audit(who.Tech.User, $"Rejected {r.Kind} for {r.Computer} in Sentinel Signer");
    return Results.Ok();
});

app.MapGet("/api/signer/clients", (HttpContext ctx) =>
{
    if (signerAuth.Check(ctx) is not { } who) return Results.Unauthorized();
    return Results.Ok(store.Clients.Select(c => new { c.Id, c.Name }));
});

app.MapPost("/api/signer/clients/{id}/codes", (string id, CodeRequest r, HttpContext ctx) =>
{
    if (signerAuth.Check(ctx) is not { } who) return Results.Unauthorized();
    if (store.Clients.All(c => c.Id != id)) return Results.NotFound();
    var code = new EnrollCode { Code = SentinelCrypto.RandomCode(16), ClientId = id, ExpiresUtc = DateTime.UtcNow.AddDays(Math.Clamp(r.Days, 1, 30)), UsesLeft = Math.Clamp(r.Uses, 1, 500), CreatedBy = who.Tech.User };
    store.Change(() => { store.CodeList.RemoveAll(c => c.ExpiresUtc < DateTime.UtcNow || c.UsesLeft <= 0); store.CodeList.Add(code); store.SaveCodes(); });
    store.Audit(who.Tech.User, $"Made an enrollment code for {id} in Sentinel Signer ({code.UsesLeft} PCs, {r.Days} days)");
    return Results.Ok(new { code = code.Code, expiresUtc = code.ExpiresUtc, uses = code.UsesLeft });
});

// ======================= Technicians and keys =======================

app.MapGet("/api/techs", (HttpContext ctx) =>
{
    if (Guard(ctx, out _) is { } bad) return bad;
    return Results.Ok(store.Techs.Select(t => new { t.Id, t.User, t.Name, t.Disabled, keys = t.Keys.Select(k => k.KeyId) }));
});

app.MapPost("/api/techs/{id}/disable", (string id, HttpContext ctx) =>
{
    if (Guard(ctx, out var me) is { } bad) return bad;
    if (id == me.Id) return Results.BadRequest(new { error = "You can't turn off your own account." });
    var ok = store.Change(() =>
    {
        var t = store.TechList.FirstOrDefault(x => x.Id == id);
        if (t is null) return false;
        t.Disabled = true;
        store.SaveTechs();
        return true;
    });
    if (!ok) return Results.NotFound();
    auth.EndSessions(id);
    store.Audit(me.User, $"Turned off technician {id}. PCs still trust their keys until those keys are replaced on each PC.");
    return Results.Ok();
});

app.MapPost("/api/keys/{keyId}/remove", (string keyId, HttpContext ctx) =>
{
    if (Guard(ctx, out var me) is { } bad) return bad;
    var ok = store.Change(() =>
    {
        foreach (var t in store.TechList)
            if (t.Keys.RemoveAll(k => k.KeyId == keyId) > 0) { store.SaveTechs(); return true; }
        return false;
    });
    if (!ok) return Results.NotFound();
    store.Audit(me.User, $"Removed signing key {keyId}");
    return Results.Ok();
});

app.Map("/api/console/session/{sid}", async (HttpContext ctx, string sid) =>
{
    var tech = auth.Current(ctx);
    if (tech is null || !ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 401; return; }
    // Browsers send Origin with WebSockets: only this site's own pages may open a session.
    var origin = ctx.Request.Headers.Origin.ToString();
    if (origin.Length > 0 && !string.Equals(origin, $"{ctx.Request.Scheme}://{ctx.Request.Host}", StringComparison.OrdinalIgnoreCase)) { ctx.Response.StatusCode = 403; return; }
    using var ws = await ctx.WebSockets.AcceptWebSocketAsync();
    store.Audit(tech.User, $"Opened session {sid}");
    await live.BrowserSession(ws, sid, tech, ctx.RequestAborted);
    store.Audit(tech.User, $"Session {sid} ended");
});

app.MapGet("/api/alerts", (HttpContext ctx) =>
{
    if (Guard(ctx, out _) is { } bad) return bad;
    return Results.Ok(store.Devices.Where(d => !d.Retired).SelectMany(d => d.Alerts.Where(a => a.ClearedUtc is null).Select(a => new
    {
        deviceId = d.Id, d.Computer, client = store.Clients.FirstOrDefault(c => c.Id == d.ClientId)?.Name ?? "", a.Key, a.Level, a.Title, a.Detail, a.FirstSeenUtc, a.Acknowledged,
    })).OrderBy(a => a.Acknowledged).ThenByDescending(a => a.Level).ThenByDescending(a => a.FirstSeenUtc));
});

app.MapGet("/api/clients/{id}/report", (string id, string? month, HttpContext ctx) =>
{
    if (Guard(ctx, out _) is { } bad) return bad;
    var client = store.Clients.FirstOrDefault(c => c.Id == id);
    if (client is null) return Results.NotFound();
    var start = DateTime.TryParseExact((month ?? "") + "-01", "yyyy-MM-dd", null, System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, out var m)
        ? m : new DateTime(DateTime.UtcNow.Year, DateTime.UtcNow.Month, 1, 0, 0, 0, DateTimeKind.Utc).AddMonths(-1);
    var end = start.AddMonths(1);
    var months = store.Devices.Where(d => d.ClientId == id && d.EnrolledUtc < end).Select(d => new DeviceMonth
    {
        Computer = d.Computer + (d.Retired ? " (removed)" : ""), User = d.Latest?.LoggedOnUser ?? "", LastSeenUtc = d.LastSeenUtc, Latest = d.Latest,
        Alerts = d.Alerts.Where(a => a.FirstSeenUtc < end && (a.ClearedUtc is null || a.ClearedUtc >= start)).ToList(),
        Work = d.History.Where(h => h.FinishedUtc >= start && h.FinishedUtc < end).ToList(),
    }).ToList();
    // The report is one self-contained page with its own styles.
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'";
    return Results.Content(MonthlyReport.Html(client.Name, start, months, DateTime.UtcNow), "text/html; charset=utf-8");
});

app.MapGet("/api/audit", (HttpContext ctx) =>
{
    if (Guard(ctx, out _) is { } bad) return bad;
    return Results.Ok(store.AuditTail(300));
});

app.Run();

// A PC can only send so much: a rogue or broken one can't fill the server.
static void Limit(HealthReport r)
{
    r.Results = (r.Results ?? new()).Take(50).ToList();
    foreach (var x in r.Results) { x.Detail = Clip(x.Detail, 2000); x.Output = CommandResult.Trim(x.Output ?? ""); }
    r.Drives = (r.Drives ?? new()).Take(16).ToList();
    r.Volumes = (r.Volumes ?? new()).Take(26).ToList();
    r.Security = (r.Security ?? new()).Take(200).ToList();
    foreach (var s in r.Security) { s.Title = Clip(s.Title, 200); s.Detail = Clip(s.Detail, 1000); s.Id = Clip(s.Id, 300); }
    r.Notes = (r.Notes ?? new()).Take(50).Select(n => Clip(n, 300)).ToList();
    r.HelpRequest = Clip(r.HelpRequest, 1000);
    r.Antivirus ??= new(); r.Updates ??= new(); r.Backup ??= new(); r.Policy ??= new();
}

static string Clip(string? s, int n) => (s ?? "").Trim() is var t && t.Length > n ? t[..n] : (s ?? "").Trim();

public sealed record SetupRequest(string SetupToken, string User, string Name, string Password);
public sealed record LoginRequest(string User, string Password, string Code);
public sealed record NewTechRequest(string User, string Name, string Password);
public sealed record CodeRequest(int Days = 7, int Uses = 25);
public sealed record NoteRequest(string Note);
public sealed record ActionRequest(string Kind, Dictionary<string, string>? Args, string Reason = "", int Minutes = 30);
