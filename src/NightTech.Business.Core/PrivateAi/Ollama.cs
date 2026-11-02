using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NightTech.Business.Core.PrivateAi;

public sealed record ChatMessage(string Role, string Content);

public sealed record InstalledModel(string Name, long Size, DateTime Modified);

public sealed record PullProgress(string Status, long Total, long Completed)
{
    public double Percent => Total > 0 ? 100.0 * Completed / Total : 0;
}

/// <summary>Talks to Ollama, the engine that runs the AI model on this computer. It listens only on this computer (127.0.0.1).</summary>
public sealed class OllamaClient
{
    public const string DefaultUrl = "http://127.0.0.1:11434";
    private readonly HttpClient _http;

    public OllamaClient(string? baseUrl = null, HttpMessageHandler? handler = null)
    {
        _http = handler is null ? new HttpClient() : new HttpClient(handler);
        _http.BaseAddress = new Uri((baseUrl ?? DefaultUrl).TrimEnd('/') + "/");
        _http.Timeout = Timeout.InfiniteTimeSpan; // long answers and big downloads; callers pass a cancellation token
    }

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>Ollama's version, or null if it isn't running.</summary>
    public async Task<string?> VersionAsync(CancellationToken ct = default)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(3));
            using var doc = JsonDocument.Parse(await _http.GetStringAsync("api/version", cts.Token));
            return doc.RootElement.TryGetProperty("version", out var v) ? v.GetString() : "unknown";
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException) { return null; }
    }

    public async Task<List<InstalledModel>> ModelsAsync(CancellationToken ct = default)
    {
        using var doc = JsonDocument.Parse(await _http.GetStringAsync("api/tags", ct));
        var list = new List<InstalledModel>();
        if (doc.RootElement.TryGetProperty("models", out var models))
            foreach (var m in models.EnumerateArray())
                list.Add(new InstalledModel(
                    m.GetProperty("name").GetString() ?? "",
                    m.TryGetProperty("size", out var s) ? s.GetInt64() : 0,
                    m.TryGetProperty("modified_at", out var d) && d.TryGetDateTime(out var dt) ? dt : default));
        return list;
    }

    /// <summary>True when the model (for example "gemma4:12b" or "phi4") is installed.</summary>
    public static bool Has(IEnumerable<InstalledModel> installed, string tag)
    {
        var want = tag.Contains(':') ? tag : tag + ":latest";
        return installed.Any(m => string.Equals(m.Name, want, StringComparison.OrdinalIgnoreCase) || string.Equals(m.Name, tag, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Streams the answer, a piece at a time.</summary>
    public async IAsyncEnumerable<string> ChatAsync(string model, IEnumerable<ChatMessage> messages, int contextTokens,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var body = new
        {
            model,
            messages = messages.Select(m => new { role = m.Role, content = m.Content }),
            stream = true,
            options = new { num_ctx = contextTokens },
            keep_alive = "30m",
        };
        using var req = new HttpRequestMessage(HttpMethod.Post, "api/chat") { Content = JsonContent.Create(body, options: Json) };
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode) throw new OllamaException(await ErrorText(resp, ct));
        using var reader = new StreamReader(await resp.Content.ReadAsStreamAsync(ct), Encoding.UTF8);
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (line.Length == 0) continue;
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var err)) throw new OllamaException(err.GetString() ?? "The AI engine reported an error.");
            if (root.TryGetProperty("message", out var msg) && msg.TryGetProperty("content", out var c) && c.GetString() is { Length: > 0 } piece)
                yield return piece;
            if (root.TryGetProperty("done", out var done) && done.GetBoolean()) yield break;
        }
    }

    /// <summary>Search vectors for each text (the document library's "meaning" numbers).</summary>
    public async Task<List<float[]>> EmbedAsync(string model, IReadOnlyList<string> texts, CancellationToken ct = default)
    {
        var result = new List<float[]>(texts.Count);
        for (int i = 0; i < texts.Count; i += 32)
        {
            var batch = texts.Skip(i).Take(32).ToList();
            using var resp = await _http.PostAsJsonAsync("api/embed", new { model, input = batch, keep_alive = "10m" }, Json, ct);
            if (!resp.IsSuccessStatusCode) throw new OllamaException(await ErrorText(resp, ct));
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
            foreach (var e in doc.RootElement.GetProperty("embeddings").EnumerateArray())
                result.Add(e.EnumerateArray().Select(x => x.GetSingle()).ToArray());
        }
        if (result.Count != texts.Count) throw new OllamaException("The document search model returned the wrong number of results.");
        return result;
    }

    /// <summary>Downloads a model, reporting progress.</summary>
    public async Task PullAsync(string model, IProgress<PullProgress>? progress, CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "api/pull") { Content = JsonContent.Create(new { model, stream = true }, options: Json) };
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode) throw new OllamaException(await ErrorText(resp, ct));
        using var reader = new StreamReader(await resp.Content.ReadAsStreamAsync(ct), Encoding.UTF8);
        string last = "";
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (line.Length == 0) continue;
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.TryGetProperty("error", out var err)) throw new OllamaException(err.GetString() ?? "Download failed.");
            last = root.TryGetProperty("status", out var st) ? st.GetString() ?? "" : last;
            long total = root.TryGetProperty("total", out var t) ? t.GetInt64() : 0;
            long done = root.TryGetProperty("completed", out var c) ? c.GetInt64() : 0;
            progress?.Report(new PullProgress(last, total, done));
        }
        if (!string.Equals(last, "success", StringComparison.OrdinalIgnoreCase))
            throw new OllamaException("The download didn't finish. Check the internet connection and try again.");
    }

    private static async Task<string> ErrorText(HttpResponseMessage resp, CancellationToken ct)
    {
        var body = await resp.Content.ReadAsStringAsync(ct);
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("error", out var e)) return e.GetString() ?? body;
        }
        catch (JsonException) { }
        return $"The AI engine answered {(int)resp.StatusCode}: {body}";
    }
}

public sealed class OllamaException : Exception
{
    public OllamaException(string message) : base(message) { }
}
