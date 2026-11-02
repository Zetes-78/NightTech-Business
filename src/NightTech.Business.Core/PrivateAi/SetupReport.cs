using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NightTech.Business.Core.PrivateAi;

public enum StepResult { Pending, Running, Done, Skipped, Warning, Failed }

public sealed class SetupStep
{
    public string Name { get; set; } = "";
    public StepResult Result { get; set; }
    public string Detail { get; set; } = "";
}

/// <summary>What Night Tech AI Setup did on a computer. The JSON goes on the Hub ticket; the text copy goes to the customer.</summary>
public sealed class AiSetupReport
{
    public string Tool { get; set; } = "Night Tech AI Setup";
    public string ToolVersion { get; set; } = "";
    public string Kind { get; set; } = "private-ai-setup";
    public string Ticket { get; set; } = "";
    public string Technician { get; set; } = "";
    public string Customer { get; set; } = "";
    public DateTime Started { get; set; }
    public DateTime Finished { get; set; }
    public HardwareProfile? Hardware { get; set; }
    public string RunsOn { get; set; } = "";
    public string Model { get; set; } = "";
    public string ModelName { get; set; } = "";
    public string SearchModel { get; set; } = "";
    public string EngineVersion { get; set; } = "";
    public string ServerVersion { get; set; } = "";
    public int Port { get; set; }
    public List<string> Addresses { get; set; } = new();
    public string AdminUser { get; set; } = "";
    public string NetworkProfile { get; set; } = "";
    public List<SetupStep> Steps { get; set; } = new();
    public bool Success => Steps.Count > 0 && Steps.All(s => s.Result is StepResult.Done or StepResult.Skipped or StepResult.Warning);

    public List<string> Notes { get; set; } = new()
    {
        "The AI runs on this computer. Questions, chats and documents stay on it and are not sent to an AI company.",
        "Private AI is reachable only from this home or office network, and everyone signs in with their own account.",
        "Any AI can be confidently wrong. Check facts, numbers and anything legal, medical or financial before relying on them.",
        "Back up the folder C:\\ProgramData\\Night Tech Private AI with the rest of your files. It holds accounts, chats and the document library.",
    };

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        Converters = { new JsonStringEnumConverter() },
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);
    public static AiSetupReport? FromJson(string s) => JsonSerializer.Deserialize<AiSetupReport>(s.TrimStart('\uFEFF'), Json);

    public string ToText()
    {
        var s = new StringBuilder();
        s.AppendLine($"{Brand.Company}: Private AI setup report");
        s.AppendLine(new string('=', 60));
        void Row(string k, string? v) { if (!string.IsNullOrWhiteSpace(v)) s.AppendLine($"  {k,-18} {v}"); }
        Row("For", Customer);
        Row("Ticket", Ticket);
        Row("Technician", Technician);
        Row("Date", Finished.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
        Row("Result", Success ? "Private AI is installed and running." : "Setup did not finish. See the steps below.");
        s.AppendLine();
        if (Hardware is { } h)
        {
            s.AppendLine("THIS COMPUTER");
            Row("Name", h.ComputerName);
            Row("Processor", $"{h.Cpu} ({h.CpuCores} cores)");
            Row("Memory", $"{h.RamGb:0.#} GB");
            foreach (var g in h.Gpus) Row("Graphics", $"{g.Name}{(g.MemoryGb > 0 ? $" ({g.MemoryGb:0.#} GB)" : "")}");
            Row("Free disk", $"{h.FreeDiskGb:0} GB");
            Row("Windows", h.Windows);
            s.AppendLine();
        }
        s.AppendLine("PRIVATE AI");
        Row("AI model", string.IsNullOrEmpty(ModelName) ? Model : $"{ModelName} ({Model})");
        Row("Runs on", RunsOn);
        Row("Document search", SearchModel);
        Row("Open it at", string.Join("  or  ", Addresses));
        Row("Administrator", AdminUser);
        Row("Network type", NetworkProfile);
        Row("AI engine", EngineVersion);
        Row("Private AI", ServerVersion);
        s.AppendLine();
        s.AppendLine("STEPS");
        foreach (var st in Steps)
            s.AppendLine($"  [{Mark(st.Result)}] {st.Name}{(st.Detail.Length > 0 ? ": " + st.Detail : "")}");
        s.AppendLine();
        s.AppendLine("GOOD TO KNOW");
        foreach (var n in Notes) s.AppendLine("  - " + n);
        s.AppendLine();
        s.AppendLine($"{Brand.Company} · {Brand.Phone} · {Brand.Website}");
        return s.ToString();
    }

    private static string Mark(StepResult r) => r switch
    {
        StepResult.Done => "OK",
        StepResult.Skipped => "--",
        StepResult.Warning => "!!",
        StepResult.Failed => "XX",
        _ => "  ",
    };

    public (string Json, string Text) Save(string folder)
    {
        Directory.CreateDirectory(folder);
        var stamp = Started.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var safe = string.Concat((string.IsNullOrWhiteSpace(Ticket) ? Hardware?.ComputerName ?? "pc" : Ticket).Select(c => char.IsLetterOrDigit(c) || c == '-' ? c : '_'));
        var json = Path.Combine(folder, $"private-ai-setup-{safe}-{stamp}.json");
        var text = Path.ChangeExtension(json, ".txt");
        var bom = new UTF8Encoding(true);
        File.WriteAllText(json, ToJson(), bom);
        File.WriteAllText(text, ToText(), bom);
        return (json, text);
    }
}
