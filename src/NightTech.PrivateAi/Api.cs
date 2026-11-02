using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using NightTech.Business.Core.PrivateAi;

namespace NightTech.PrivateAi;

public sealed record LoginRequest(string? Name, string? Password);
public sealed record SetupRequest(string? Company, string? Name, string? DisplayName, string? Password);
public sealed record ChatRequest(string? ChatId, string? Message, bool UseDocs);
public sealed record NewUserRequest(string? Name, string? DisplayName, string? Password, bool IsAdmin);
public sealed record PasswordRequest(string? Current, string? Password);
public sealed record AdminFlagRequest(bool IsAdmin);
public sealed record SettingsRequest(string? CompanyName, string? ChatModel, string? ExtraInstructions, int? ContextTokens);
public sealed record RenameRequest(string? Title);

public static class Api
{
    public const int MaxQuestionChars = 20_000;
    public const int MaxPassagesPerDocument = 6_000;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private static string Who(ClaimsPrincipal u) => u.Identity?.Name ?? "";
    private static IResult Problem(string message, int status = 400) => Results.Json(new { error = message }, statusCode: status);

    public static void Map(WebApplication app)
    {
        var api = app.MapGroup("/api");
        var signedIn = api.MapGroup("").RequireAuthorization();
        var admin = api.MapGroup("/admin").RequireAuthorization("admin");

        // ---------------- Signing in ----------------

        api.MapGet("/me", (HttpContext ctx, AppState s) =>
        {
            var u = ctx.User.Identity?.IsAuthenticated == true ? s.Users.Find(Who(ctx.User)) : null;
            if (u is null)
                return Results.Json(new
                {
                    signedIn = false,
                    company = s.Settings.CompanyName,
                    needsSetup = !s.Users.Any,
                    setupAllowed = !s.Users.Any && IPAddress.IsLoopback(Mapped(ctx.Connection.RemoteIpAddress)),
                    version = AppState.Version,
                });
            return Results.Json(new
            {
                signedIn = true,
                name = u.Name,
                displayName = u.DisplayName,
                isAdmin = u.IsAdmin,
                company = s.Settings.CompanyName,
                model = s.Settings.ChatModel,
                documents = s.Library.Documents.Count,
                version = AppState.Version,
            });
        });

        api.MapPost("/setup", async (HttpContext ctx, AppState s, SetupRequest r) =>
        {
            if (s.Users.Any) return Problem("Setup is already done. Sign in instead.", 409);
            if (!IPAddress.IsLoopback(Mapped(ctx.Connection.RemoteIpAddress)))
                return Problem("First-time setup has to be done on the AI computer itself.", 403);
            try
            {
                if (!string.IsNullOrWhiteSpace(r.Company)) { s.Settings.CompanyName = r.Company.Trim()[..Math.Min(80, r.Company.Trim().Length)]; s.SaveSettings(); }
                var u = s.Users.Add(r.Name?.Trim() ?? "", r.DisplayName ?? "", r.Password ?? "", true, DateTime.Now);
                await SignIn(ctx, u);
                s.Log.Info($"First-time setup done; administrator {u.Name} added.");
                return Results.Ok(new { ok = true });
            }
            catch (ArgumentException ex) { return Problem(ex.Message); }
        });

        api.MapPost("/login", async (HttpContext ctx, AppState s, LoginRequest r) =>
        {
            var name = (r.Name ?? "").Trim();
            var ipKey = "ip:" + Mapped(ctx.Connection.RemoteIpAddress);
            var now = DateTime.UtcNow;
            var wait = s.Limiter.Blocked("u:" + name.ToLowerInvariant(), now) ?? s.ComputerLimiter.Blocked(ipKey, now);
            if (wait is { } w) return Problem($"Too many wrong passwords. Try again in {Math.Max(1, (int)Math.Ceiling(w.TotalMinutes))} minute(s).", 429);
            var u = s.Users.Verify(name, r.Password ?? "");
            if (u is null)
            {
                s.Limiter.Failed("u:" + name.ToLowerInvariant(), now);
                s.ComputerLimiter.Failed(ipKey, now);
                s.Log.Warn($"Failed sign-in for '{Clip(name, 40)}' from {Mapped(ctx.Connection.RemoteIpAddress)}.");
                return Problem("That user name and password don't match.", 401);
            }
            s.Limiter.Succeeded("u:" + name.ToLowerInvariant());
            s.ComputerLimiter.Succeeded(ipKey);
            await SignIn(ctx, u);
            s.Log.Info($"{u.Name} signed in from {Mapped(ctx.Connection.RemoteIpAddress)}.");
            return Results.Ok(new { ok = true });
        });

        api.MapPost("/logout", async (HttpContext ctx) =>
        {
            await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Ok(new { ok = true });
        });

        signedIn.MapPost("/me/password", async (HttpContext ctx, AppState s, PasswordRequest r) =>
        {
            var name = Who(ctx.User);
            if (s.Users.Verify(name, r.Current ?? "") is null) return Problem("Your current password isn't right.", 401);
            try
            {
                s.Users.SetPassword(name, r.Password ?? "");
                await SignIn(ctx, s.Users.Find(name)!);
                return Results.Ok(new { ok = true });
            }
            catch (ArgumentException ex) { return Problem(ex.Message); }
        });

        // ---------------- Chats ----------------

        signedIn.MapGet("/chats", (HttpContext ctx, AppState s) => Results.Json(s.Chats.List(Who(ctx.User))));

        signedIn.MapGet("/chats/{id}", (string id, HttpContext ctx, AppState s) =>
            s.Chats.Get(Who(ctx.User), id) is { } c ? Results.Json(c) : Problem("Chat not found.", 404));

        signedIn.MapDelete("/chats/{id}", (string id, HttpContext ctx, AppState s) =>
            s.Chats.Delete(Who(ctx.User), id) ? Results.Ok(new { ok = true }) : Problem("Chat not found.", 404));

        signedIn.MapPost("/chats/{id}/title", (string id, HttpContext ctx, AppState s, RenameRequest r) =>
        {
            var c = s.Chats.Get(Who(ctx.User), id);
            if (c is null) return Problem("Chat not found.", 404);
            var t = (r.Title ?? "").Trim();
            if (t.Length is 0 or > 80) return Problem("Titles are 1 to 80 characters.");
            c.Title = t;
            s.Chats.Save(Who(ctx.User), c);
            return Results.Ok(new { ok = true });
        });

        signedIn.MapPost("/chat", (HttpContext ctx, AppState s, ChatRequest r) => Chat(ctx, s, r));

        // ---------------- Document library ----------------

        signedIn.MapGet("/docs", (AppState s) => Results.Json(s.Library.Documents));

        admin.MapPost("/docs", async (HttpContext ctx, AppState s) => await AddDocuments(ctx, s)).DisableAntiforgery();

        admin.MapDelete("/docs/{id}", (string id, HttpContext ctx, AppState s) =>
        {
            var d = s.Library.Documents.FirstOrDefault(x => x.Id == id);
            if (d is null || !s.Library.Remove(id)) return Problem("Document not found.", 404);
            s.Log.Info($"{Who(ctx.User)} removed document {d.FileName}.");
            return Results.Ok(new { ok = true });
        });

        // ---------------- Administration ----------------

        admin.MapGet("/users", (AppState s) => Results.Json(s.Users.All.Select(u => new { u.Name, u.DisplayName, u.IsAdmin, u.Created })));

        admin.MapPost("/users", (HttpContext ctx, AppState s, NewUserRequest r) =>
        {
            try
            {
                var u = s.Users.Add((r.Name ?? "").Trim(), r.DisplayName ?? "", r.Password ?? "", r.IsAdmin, DateTime.Now);
                s.Log.Info($"{Who(ctx.User)} added user {u.Name}{(u.IsAdmin ? " (administrator)" : "")}.");
                return Results.Ok(new { ok = true });
            }
            catch (ArgumentException ex) { return Problem(ex.Message); }
        });

        admin.MapPost("/users/{name}/password", (string name, HttpContext ctx, AppState s, PasswordRequest r) =>
        {
            try
            {
                s.Users.SetPassword(name, r.Password ?? "");
                s.Log.Info($"{Who(ctx.User)} reset the password for {name}.");
                return Results.Ok(new { ok = true });
            }
            catch (ArgumentException ex) { return Problem(ex.Message); }
        });

        admin.MapPost("/users/{name}/admin", (string name, HttpContext ctx, AppState s, AdminFlagRequest r) =>
        {
            try
            {
                s.Users.SetAdmin(name, r.IsAdmin);
                s.Log.Info($"{Who(ctx.User)} set administrator={r.IsAdmin} for {name}.");
                return Results.Ok(new { ok = true });
            }
            catch (ArgumentException ex) { return Problem(ex.Message); }
        });

        admin.MapDelete("/users/{name}", (string name, HttpContext ctx, AppState s) =>
        {
            if (string.Equals(name, Who(ctx.User), StringComparison.OrdinalIgnoreCase)) return Problem("You can't remove yourself.");
            try
            {
                s.Users.Remove(name);
                s.Chats.DeleteAll(name);
                s.Log.Info($"{Who(ctx.User)} removed user {name} and their chats.");
                return Results.Ok(new { ok = true });
            }
            catch (ArgumentException ex) { return Problem(ex.Message); }
        });

        admin.MapGet("/settings", async (AppState s, CancellationToken ct) =>
        {
            var version = await s.Ollama.VersionAsync(ct);
            List<InstalledModel> models = new();
            if (version is not null) { try { models = await s.Ollama.ModelsAsync(ct); } catch (HttpRequestException) { } }
            return Results.Json(new
            {
                s.Settings.CompanyName,
                s.Settings.ChatModel,
                s.Settings.SearchModel,
                s.Settings.ExtraInstructions,
                s.Settings.ContextTokens,
                s.Settings.Port,
                engine = version is null ? null : new { version },
                chatModelInstalled = OllamaClient.Has(models, s.Settings.ChatModel),
                searchModelInstalled = OllamaClient.Has(models, s.Settings.SearchModel),
                models = models.Where(m => !m.Name.Contains("embed", StringComparison.OrdinalIgnoreCase))
                    .Select(m => new { m.Name, sizeGb = Math.Round(m.Size / 1e9, 1), known = ModelCatalog.Find(m.Name.Replace(":latest", ""))?.Name }),
                documents = s.Library.Documents.Count,
                passages = s.Library.PassageCount,
                dataFolder = s.DataDir,
                version = AppState.Version,
            });
        });

        admin.MapPost("/settings", (HttpContext ctx, AppState s, SettingsRequest r) =>
        {
            if (r.CompanyName is { } c)
            {
                c = c.Trim();
                if (c.Length is 0 or > 80) return Problem("The name shown is 1 to 80 characters.");
                s.Settings.CompanyName = c;
            }
            if (r.ChatModel is { } m)
            {
                if (m.Length is 0 or > 100 || m.Any(ch => char.IsWhiteSpace(ch) || ch == '/' && m.Count(x => x == '/') > 2)) return Problem("That model name isn't valid.");
                s.Settings.ChatModel = m.EndsWith(":latest", StringComparison.Ordinal) ? m[..^7] : m;
            }
            if (r.ExtraInstructions is { } e)
            {
                if (e.Length > 4000) return Problem("Extra instructions are limited to 4,000 characters.");
                s.Settings.ExtraInstructions = e.Trim();
            }
            if (r.ContextTokens is { } t)
            {
                if (t is < 2048 or > 131072) return Problem("Conversation memory must be between 2,048 and 131,072.");
                s.Settings.ContextTokens = t;
            }
            s.SaveSettings();
            s.Log.Info($"{Who(ctx.User)} changed settings (model {s.Settings.ChatModel}).");
            return Results.Ok(new { ok = true });
        });
    }

    private static IPAddress Mapped(IPAddress? ip) => ip is null ? IPAddress.None : ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip;
    private static string Clip(string s, int n) => s.Length <= n ? s : s[..n];

    private static Task SignIn(HttpContext ctx, UserAccount u)
    {
        var id = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, u.Name),
            new Claim("display", u.DisplayName),
            new Claim("admin", u.IsAdmin ? "true" : "false"),
            new Claim("stamp", u.Stamp),
        }, CookieAuthenticationDefaults.AuthenticationScheme);
        return ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(id), new AuthenticationProperties { IsPersistent = true });
    }

    private static bool IsNomic(string model) => model.StartsWith("nomic-embed", StringComparison.OrdinalIgnoreCase);

    // ---------------- Chat: streamed answer ----------------

    private static async Task Chat(HttpContext ctx, AppState s, ChatRequest r)
    {
        var user = Who(ctx.User);
        var question = (r.Message ?? "").Trim();
        var res = ctx.Response;
        if (question.Length == 0 || question.Length > MaxQuestionChars)
        {
            res.StatusCode = 400;
            await res.WriteAsJsonAsync(new { error = $"Questions are 1 to {MaxQuestionChars:N0} characters." });
            return;
        }
        bool added;
        lock (s.Busy) added = s.Busy.Add(user);
        if (!added)
        {
            res.StatusCode = 409;
            await res.WriteAsJsonAsync(new { error = "Wait for the current answer to finish first." });
            return;
        }
        var abort = ctx.RequestAborted;
        bool slot = false;
        try
        {
            var conv = string.IsNullOrEmpty(r.ChatId) ? s.Chats.Create(user, r.UseDocs, DateTime.Now) : s.Chats.Get(user, r.ChatId);
            if (conv is null)
            {
                res.StatusCode = 404;
                await res.WriteAsJsonAsync(new { error = "Chat not found." });
                return;
            }
            res.ContentType = "application/x-ndjson; charset=utf-8";
            res.Headers["X-Accel-Buffering"] = "no";
            async Task Send(object o)
            {
                await res.WriteAsync(JsonSerializer.Serialize(o, Json) + "\n", abort);
                await res.Body.FlushAsync(abort);
            }

            slot = await s.Generating.WaitAsync(TimeSpan.FromMinutes(3), abort);
            if (!slot)
            {
                await Send(new { type = "error", message = "The AI is busy answering other people. Try again in a minute." });
                return;
            }

            // Documents: find the passages that match the question.
            var hits = new List<SearchHit>();
            bool useDocs = r.UseDocs && s.Library.Documents.Count > 0;
            if (useDocs)
            {
                try
                {
                    var q = IsNomic(s.Settings.SearchModel) ? "search_query: " + question : question;
                    var vec = (await s.Ollama.EmbedAsync(s.Settings.SearchModel, new[] { q }, abort))[0];
                    hits = s.Library.Search(vec, top: 5, minScore: 0.3);
                }
                catch (Exception ex) when (ex is OllamaException or HttpRequestException)
                {
                    s.Log.Error("Document search failed.", ex);
                    await Send(new { type = "notice", message = "Document search isn't available right now, so this answer doesn't use your documents." });
                    useDocs = false;
                }
            }
            var sources = hits.Select(h => new SourceRef { FileName = h.Document.FileName, Page = h.Page }).ToList();
            await Send(new { type = "meta", chatId = conv.Id, sources });

            var history = conv.Messages.Select(m => new ChatMessage(m.Role, m.Content)).ToList();
            var latest = new ChatMessage("user", useDocs ? PromptBuilder.WithExcerpts(question, hits) : question);
            var messages = PromptBuilder.Fit(PromptBuilder.System(s.Settings, DateTime.Now), history, latest, s.Settings.ContextTokens);

            var answer = new StringBuilder();
            bool stopped = false;
            string? failure = null;
            try
            {
                await foreach (var piece in s.Ollama.ChatAsync(s.Settings.ChatModel, messages, s.Settings.ContextTokens, abort))
                {
                    answer.Append(piece);
                    await Send(new { type = "text", text = piece });
                }
            }
            catch (OperationCanceledException) { stopped = true; }
            catch (OllamaException ex) { failure = ex.Message.Contains("not found", StringComparison.OrdinalIgnoreCase) ? $"The AI model \"{s.Settings.ChatModel}\" isn't installed. An administrator can pick an installed model in Settings." : "The AI engine reported a problem: " + ex.Message; }
            catch (HttpRequestException) { failure = "The AI engine isn't running. It usually restarts on its own within a minute; if not, restart this computer."; }

            if (failure is not null && answer.Length == 0)
            {
                s.Log.Error(failure);
                if (!abort.IsCancellationRequested) await Send(new { type = "error", message = failure });
                if (conv.Messages.Count == 0) s.Chats.Delete(user, conv.Id);
                return;
            }

            var now = DateTime.Now;
            if (conv.Messages.Count == 0) conv.Title = ChatStore.TitleFrom(question);
            conv.Messages.Add(new StoredMessage { Role = "user", Content = question, At = now });
            var text = answer.ToString();
            if (stopped || failure is not null) text += "\n\n_(Answer stopped before it finished.)_";
            conv.Messages.Add(new StoredMessage { Role = "assistant", Content = text, At = now, Sources = sources.Count > 0 ? sources : null });
            conv.Updated = now;
            conv.UseDocuments = r.UseDocs;
            s.Chats.Save(user, conv);
            if (!abort.IsCancellationRequested) await Send(new { type = "done", title = conv.Title });
        }
        catch (OperationCanceledException) { /* the person closed the page */ }
        finally
        {
            if (slot) s.Generating.Release();
            lock (s.Busy) s.Busy.Remove(user);
        }
    }

    // ---------------- Adding documents ----------------

    private static async Task<IResult> AddDocuments(HttpContext ctx, AppState s)
    {
        if (!ctx.Request.HasFormContentType) return Problem("Send the files as a form upload.");
        var form = await ctx.Request.ReadFormAsync(ctx.RequestAborted);
        if (form.Files.Count == 0) return Problem("Choose at least one file.");
        var results = new List<object>();
        await s.Indexing.WaitAsync(ctx.RequestAborted);
        try
        {
            foreach (var file in form.Files)
            {
                var name = Path.GetFileName(file.FileName);
                if (!TextExtractor.IsSupported(name)) { results.Add(new { fileName = name, ok = false, message = "This kind of file isn't supported." }); continue; }
                if (s.Library.Documents.Any(d => string.Equals(d.FileName, name, StringComparison.OrdinalIgnoreCase)))
                { results.Add(new { fileName = name, ok = false, message = "A document with this name is already in the library. Remove the old one first." }); continue; }
                byte[] data;
                using (var ms = new MemoryStream())
                {
                    await file.CopyToAsync(ms, ctx.RequestAborted);
                    data = ms.ToArray();
                }
                var ex = TextExtractor.Extract(name, data);
                if (ex.Problem is not null) { results.Add(new { fileName = name, ok = false, message = ex.Problem }); continue; }
                var chunks = Chunker.Split(ex.Parts);
                if (chunks.Count > MaxPassagesPerDocument)
                { results.Add(new { fileName = name, ok = false, message = "This document is too long for the library. Split it into smaller files." }); continue; }
                try
                {
                    var prefix = IsNomic(s.Settings.SearchModel) ? "search_document: " : "";
                    var vectors = await s.Ollama.EmbedAsync(s.Settings.SearchModel, chunks.Select(c => prefix + name + "\n" + c.Text).ToList(), ctx.RequestAborted);
                    var doc = s.Library.Add(name, data.Length, ex.Parts.Count, chunks, vectors, Who(ctx.User), DateTime.Now);
                    s.Log.Info($"{Who(ctx.User)} added document {name} ({chunks.Count} passages).");
                    results.Add(new { fileName = name, ok = true, passages = doc.Passages, message = $"Added: {doc.Passages} passages." });
                }
                catch (Exception e) when (e is OllamaException or HttpRequestException)
                {
                    s.Log.Error($"Couldn't index {name}.", e);
                    var msg = e.Message.Contains("not found", StringComparison.OrdinalIgnoreCase)
                        ? $"The document search model ({s.Settings.SearchModel}) isn't installed. Run Night Tech AI Setup again to add it."
                        : "The AI engine couldn't read this document right now. Try again in a minute.";
                    results.Add(new { fileName = name, ok = false, message = msg });
                }
            }
        }
        finally { s.Indexing.Release(); }
        return Results.Json(new { results });
    }
}
