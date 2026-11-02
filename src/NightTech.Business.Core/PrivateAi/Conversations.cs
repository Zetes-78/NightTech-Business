using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NightTech.Business.Core.PrivateAi;

/// <summary>Settings for one private AI install. Saved as settings.json in the data folder.</summary>
public sealed class AiSettings
{
    public string CompanyName { get; set; } = "Private AI";
    public int Port { get; set; } = 8080;
    public string ChatModel { get; set; } = "gemma4:12b";
    public string SearchModel { get; set; } = ModelCatalog.DocumentSearch.Tag;
    public string OllamaUrl { get; set; } = OllamaClient.DefaultUrl;
    /// <summary>Where ollama.exe is, so Private AI can start it when nobody is signed in to Windows.</summary>
    public string OllamaExe { get; set; } = "";
    /// <summary>Where the models are stored (shared by Ollama and Private AI).</summary>
    public string ModelsFolder { get; set; } = "";
    public int ContextTokens { get; set; } = 8192;
    public int MaxUploadMb { get; set; } = 50;
    public string ExtraInstructions { get; set; } = "";
    public string InstalledBy { get; set; } = "Night Tech Solutions";
    public string Ticket { get; set; } = "";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public static AiSettings Load(string path)
    {
        if (!File.Exists(path)) return new AiSettings();
        return JsonSerializer.Deserialize<AiSettings>(File.ReadAllText(path), Json) ?? new AiSettings();
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Json));
        File.Move(tmp, path, true);
    }
}

/// <summary>Builds what the AI is given: who it is, the conversation, and (when used) excerpts from the documents.</summary>
public static class PromptBuilder
{
    public static string System(AiSettings s, DateTime now)
    {
        var sb = new StringBuilder();
        sb.Append($"You are the private AI assistant for {s.CompanyName}. ");
        sb.Append($"Today is {now.ToString("dddd, MMMM d, yyyy", CultureInfo.InvariantCulture)}. ");
        sb.Append("You run entirely on a computer the user owns, with no internet access, so you can't look things up online and don't know recent news. ");
        sb.Append("Be helpful, clear and concise. Use plain English. If you're not sure of something, say so instead of guessing. ");
        sb.Append("Remind the user to double-check facts, numbers, and anything legal, medical or financial before relying on them.");
        if (!string.IsNullOrWhiteSpace(s.ExtraInstructions)) sb.Append("\n\n").Append(s.ExtraInstructions.Trim());
        return sb.ToString();
    }

    /// <summary>The question, with numbered excerpts from the documents to answer from.</summary>
    public static string WithExcerpts(string question, IReadOnlyList<SearchHit> hits)
    {
        if (hits.Count == 0)
            return question + "\n\n(The document library was searched, but nothing relevant was found. If the question is about the organization's own documents, say that you couldn't find it in the documents.)";
        var sb = new StringBuilder("Answer using these excerpts from the organization's documents. Cite them like [1] or [2]. ");
        sb.Append("If the excerpts don't contain the answer, say so plainly and don't make one up.\n\n");
        for (int i = 0; i < hits.Count; i++)
        {
            var h = hits[i];
            sb.Append($"[{i + 1}] {h.Document.FileName}{(h.Page > 0 ? $", page {h.Page}" : "")}:\n{h.Text}\n\n");
        }
        sb.Append("Question: ").Append(question);
        return sb.ToString();
    }

    /// <summary>Keeps the newest messages that fit, so long chats don't overflow the model's memory. About 4 characters per token.</summary>
    public static List<ChatMessage> Fit(string system, IReadOnlyList<ChatMessage> history, ChatMessage latest, int contextTokens)
    {
        int budget = (int)(contextTokens * 4 * 0.75) - system.Length - latest.Content.Length;
        var kept = new List<ChatMessage>();
        for (int i = history.Count - 1; i >= 0 && budget > 0; i--)
        {
            budget -= history[i].Content.Length;
            if (budget < 0) break;
            kept.Insert(0, history[i]);
        }
        // Never start with an answer that's missing its question.
        while (kept.Count > 0 && kept[0].Role != "user") kept.RemoveAt(0);
        var all = new List<ChatMessage> { new("system", system) };
        all.AddRange(kept);
        all.Add(latest);
        return all;
    }
}

public sealed class SourceRef
{
    public string FileName { get; set; } = "";
    public int Page { get; set; }
}

public sealed class StoredMessage
{
    public string Role { get; set; } = "";
    public string Content { get; set; } = "";
    public DateTime At { get; set; }
    public List<SourceRef>? Sources { get; set; }
}

public sealed class Conversation
{
    public string Id { get; set; } = "";
    public string Title { get; set; } = "New chat";
    public DateTime Created { get; set; }
    public DateTime Updated { get; set; }
    public bool UseDocuments { get; set; }
    public List<StoredMessage> Messages { get; set; } = new();
}

public sealed record ConversationSummary(string Id, string Title, DateTime Updated);

/// <summary>Each person's chats, kept private to them: one folder per user, one file per chat.</summary>
public sealed class ChatStore
{
    private readonly string _root;
    private readonly object _gate = new();
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = false, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public ChatStore(string root) { _root = root; Directory.CreateDirectory(root); }

    private string Folder(string user) => Path.Combine(_root, SafeKey(user));

    /// <summary>User names are already restricted, but never trust a path piece.</summary>
    public static string SafeKey(string s)
    {
        var clean = new string((s ?? "").ToLowerInvariant().Where(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or '_').ToArray()).Trim('.');
        return clean.Length == 0 ? "_" : clean;
    }

    private static bool ValidId(string id) => id.Length is > 0 and <= 40 && id.All(char.IsAsciiLetterOrDigit);

    public List<ConversationSummary> List(string user)
    {
        lock (_gate)
        {
            var dir = Folder(user);
            if (!Directory.Exists(dir)) return new();
            var list = new List<ConversationSummary>();
            foreach (var f in Directory.EnumerateFiles(dir, "*.json"))
            {
                var c = Read(f);
                if (c is not null) list.Add(new ConversationSummary(c.Id, c.Title, c.Updated));
            }
            return list.OrderByDescending(c => c.Updated).ToList();
        }
    }

    public Conversation? Get(string user, string id)
    {
        if (!ValidId(id)) return null;
        lock (_gate) return Read(Path.Combine(Folder(user), id + ".json"));
    }

    public Conversation Create(string user, bool useDocs, DateTime now)
    {
        var c = new Conversation { Id = Guid.NewGuid().ToString("N")[..16], Created = now, Updated = now, UseDocuments = useDocs };
        Save(user, c);
        return c;
    }

    public void Save(string user, Conversation c)
    {
        if (!ValidId(c.Id)) throw new ArgumentException("Bad chat id.");
        lock (_gate)
        {
            var dir = Folder(user);
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, c.Id + ".json");
            var tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(c, Json));
            File.Move(tmp, path, true);
        }
    }

    public bool Delete(string user, string id)
    {
        if (!ValidId(id)) return false;
        lock (_gate)
        {
            var path = Path.Combine(Folder(user), id + ".json");
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }
    }

    public void DeleteAll(string user)
    {
        lock (_gate)
        {
            var dir = Folder(user);
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    private static Conversation? Read(string path)
    {
        try { return File.Exists(path) ? JsonSerializer.Deserialize<Conversation>(File.ReadAllText(path), Json) : null; }
        catch (Exception ex) when (ex is JsonException or IOException) { return null; }
    }

    /// <summary>A short title from the first question.</summary>
    public static string TitleFrom(string question)
    {
        var t = string.Join(' ', question.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return t.Length <= 48 ? t : t[..45].TrimEnd() + "...";
    }
}
