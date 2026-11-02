namespace NightTech.Business.Core.PrivateAi;

/// <summary>An AI model we install. Sizes are the download size of the model as Ollama publishes it.</summary>
public sealed record AiModel(
    string Tag,            // what Ollama calls it, e.g. "gemma4:12b"
    string Name,           // what we call it on screen
    string MadeBy,
    bool UsCompany,
    double DownloadGb,
    string BestFor,
    bool Embedding = false,
    int Preference = 0);   // higher wins when several fit: quality for everyday office work

/// <summary>The models offered on the website's Private AI page, in order from smallest to largest.</summary>
public static class ModelCatalog
{
    public static readonly IReadOnlyList<AiModel> ChatModels = new[]
    {
        new AiModel("qwen3.5:4b",    "Qwen 3.5 (4B)",       "Alibaba",    false, 3.4,  "Quick writing help on a single laptop", Preference: 1),
        new AiModel("llama3.1:8b",   "Llama 3.1 (8B)",      "Meta",       true,  4.9,  "Everyday writing and questions", Preference: 2),
        new AiModel("qwen3.5:9b",    "Qwen 3.5 (9B)",       "Alibaba",    false, 6.6,  "Everyday writing, reads images, many languages", Preference: 3),
        new AiModel("gemma4:12b",    "Gemma 4 (12B)",       "Google",     true,  8.0,  "Our pick for most offices: writing, summaries, reading photos of documents", Preference: 5),
        new AiModel("phi4",          "Phi-4 (14B)",         "Microsoft",  true,  9.1,  "Careful, step-by-step answers and math", Preference: 4),
        new AiModel("gpt-oss:20b",   "gpt-oss (20B)",       "OpenAI",     true,  14,   "Stronger reasoning and longer documents", Preference: 6),
        new AiModel("mistral-small", "Mistral Small (24B)", "Mistral AI", false, 14,   "Strong all-rounder for a busy office", Preference: 7),
        new AiModel("gemma4:26b",    "Gemma 4 (26B)",       "Google",     true,  18,   "Best writing quality for a small team", Preference: 8),
        new AiModel("llama3.3:70b",  "Llama 3.3 (70B)",     "Meta",       true,  43,   "The most capable here, for heavier use", Preference: 9),
    };

    /// <summary>Turns documents into searchable numbers for the document library. Small and fast on any computer.</summary>
    public static readonly AiModel DocumentSearch =
        new("nomic-embed-text", "Nomic Embed (document search)", "Nomic AI", true, 0.3, "Finding the right pages in your documents", Embedding: true);

    public static AiModel? Find(string tag) =>
        ChatModels.FirstOrDefault(m => string.Equals(m.Tag, tag, StringComparison.OrdinalIgnoreCase))
        ?? (string.Equals(tag, DocumentSearch.Tag, StringComparison.OrdinalIgnoreCase) ? DocumentSearch : null);

    /// <summary>Memory a model needs to run: its weights plus room for the conversation.</summary>
    public static double RunGb(AiModel m) => m.DownloadGb * 1.1 + 0.5;
}
