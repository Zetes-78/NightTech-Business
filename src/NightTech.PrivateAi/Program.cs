using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using NightTech.Business.Core.PrivateAi;
using NightTech.PrivateAi;

// ---------------- Where things live ----------------

var dataDir = Cli.Option(args, "--data")
    ?? Environment.GetEnvironmentVariable("NTAI_DATA")
    ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Night Tech Private AI");
Directory.CreateDirectory(dataDir);
var settingsPath = Path.Combine(dataDir, "settings.json");
var settings = AiSettings.Load(settingsPath);
if (Cli.Option(args, "--port") is { } portText && int.TryParse(portText, out var portArg)) settings.Port = portArg;
var users = new UserStore(Path.Combine(dataDir, "users.json"));

// Command-line jobs for the setup tool: add a user, reset a password, show status. The password is read from standard input.
if (args.Length > 0 && !args[0].StartsWith("--", StringComparison.Ordinal))
    return await Cli.Run(args, users, settings, dataDir);

// A pattern can never run for long on hostile text (document readers use their own, shorter limits).
AppDomain.CurrentDomain.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", TimeSpan.FromSeconds(10));
var log = new ServerLog(Path.Combine(dataDir, "logs"));
var state = new AppState(settings, settingsPath, users, new Library(Path.Combine(dataDir, "library")), new ChatStore(Path.Combine(dataDir, "chats")), log, dataDir);

// ---------------- Web server ----------------

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
    WebRootPath = Path.Combine(AppContext.BaseDirectory, "wwwroot"),
});
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(k =>
{
    k.ListenAnyIP(settings.Port); // IPv4 and IPv6, falling back to IPv4 when IPv6 is off
    k.Limits.MaxRequestBodySize = (long)Math.Max(1, settings.MaxUploadMb) * 1024 * 1024;
    k.AddServerHeader = false;
});
builder.Services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = (long)Math.Max(1, settings.MaxUploadMb) * 1024 * 1024);
builder.Services.AddSingleton(state);
builder.Services.AddHostedService<OllamaKeeper>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(o =>
{
    o.Cookie.Name = "ntai";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Strict;
    o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    o.ExpireTimeSpan = TimeSpan.FromHours(12);
    o.SlidingExpiration = true;
    o.Events.OnRedirectToLogin = c => { c.Response.StatusCode = 401; return Task.CompletedTask; };
    o.Events.OnRedirectToAccessDenied = c => { c.Response.StatusCode = 403; return Task.CompletedTask; };
    // A changed password or a removed account ends that person's sign-ins everywhere.
    o.Events.OnValidatePrincipal = c =>
    {
        var u = users.Find(c.Principal?.Identity?.Name ?? "");
        if (u is null || u.Stamp != c.Principal!.FindFirstValue("stamp") || (u.IsAdmin ? "true" : "false") != c.Principal!.FindFirstValue("admin"))
            c.RejectPrincipal();
        return Task.CompletedTask;
    };
});
builder.Services.AddAuthorization(o => o.AddPolicy("admin", p => p.RequireClaim("admin", "true")));

var app = builder.Build();

app.Use(async (ctx, next) =>
{
    // Only computers on this home or office network.
    if (!NetworkGuard.IsLocal(ctx.Connection.RemoteIpAddress, OnLink.Prefixes))
    {
        ctx.Response.StatusCode = 403;
        await ctx.Response.WriteAsync("Private AI is only available on this network.");
        return;
    }
    // Only this computer's own names and addresses: stops a web page from reaching Private AI through a look-alike name (DNS rebinding).
    if (!OnLink.AllowedHost(ctx.Request.Host.Host))
    {
        ctx.Response.StatusCode = 400;
        await ctx.Response.WriteAsync("Open Private AI by this computer's name or address.");
        return;
    }
    var h = ctx.Response.Headers;
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "no-referrer";
    h["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    h["Cache-Control"] = "no-store";
    // Changes must come from this app's own page: a custom header can't be sent by another site without permission we never give.
    if (ctx.Request.Path.StartsWithSegments("/api") && !HttpMethods.IsGet(ctx.Request.Method) && !HttpMethods.IsHead(ctx.Request.Method))
    {
        var origin = ctx.Request.Headers.Origin.ToString();
        bool sameOrigin = origin.Length == 0 || Uri.TryCreate(origin, UriKind.Absolute, out var o) && string.Equals(o.Authority, ctx.Request.Host.Value, StringComparison.OrdinalIgnoreCase);
        if (ctx.Request.Headers["X-NTAI"] != "1" || !sameOrigin)
        {
            ctx.Response.StatusCode = 403;
            await ctx.Response.WriteAsync("Blocked: request did not come from the Private AI page.");
            return;
        }
    }
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

Api.Map(app);

log.Info($"Night Tech Private AI {AppState.Version} starting on port {settings.Port}. Data: {dataDir}");
try
{
    await app.RunAsync();
}
catch (IOException ex) when (ex.Message.Contains("address already in use", StringComparison.OrdinalIgnoreCase) || ex.InnerException is System.Net.Sockets.SocketException)
{
    log.Error($"Port {settings.Port} is already in use by another program. Change the port in settings.json.", ex);
    return 2;
}
return 0;
