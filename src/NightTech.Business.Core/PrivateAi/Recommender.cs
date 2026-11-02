namespace NightTech.Business.Core.PrivateAi;

public sealed record GpuInfo(string Name, double MemoryGb, string Vendor)
{
    /// <summary>Ollama runs models on NVIDIA and recent AMD cards. Intel graphics and small cards fall back to the processor.</summary>
    public bool Usable => MemoryGb >= 6 && (Vendor is "NVIDIA" or "AMD");
}

/// <summary>What the computer has, as the setup tool reads it.</summary>
public sealed record HardwareProfile(
    string ComputerName,
    string Cpu,
    int CpuCores,
    double RamGb,
    IReadOnlyList<GpuInfo> Gpus,
    double FreeDiskGb,
    string Windows)
{
    public GpuInfo? BestGpu => Gpus.Where(g => g.Usable).OrderByDescending(g => g.MemoryGb).FirstOrDefault();
}

public enum RunMode { GraphicsCard, Processor, NotSuitable }

public sealed record Recommendation(
    RunMode Mode,
    AiModel? Pick,
    IReadOnlyList<AiModel> AlsoFits,
    IReadOnlyList<string> Notes,
    string Summary);

/// <summary>Picks the model that fits a computer. Errs small: a model that answers quickly beats a bigger one that crawls.</summary>
public static class Recommender
{
    public const double MinRamGb = 8;

    public static Recommendation For(HardwareProfile hw, bool usCompaniesOnly = false, bool forTeam = false)
    {
        var notes = new List<string>();
        var models = ModelCatalog.ChatModels.Where(m => !usCompaniesOnly || m.UsCompany).ToList();
        var gpu = hw.BestGpu;
        double budget;
        RunMode mode;

        if (gpu is not null)
        {
            mode = RunMode.GraphicsCard;
            budget = gpu.MemoryGb;
            notes.Add($"Runs on the graphics card ({gpu.Name}, {gpu.MemoryGb:0.#} GB).");
            if (hw.RamGb < 16) notes.Add($"Only {hw.RamGb:0.#} GB of memory. 16 GB or more is recommended alongside the graphics card.");
        }
        else
        {
            mode = RunMode.Processor;
            // Leave room for Windows and the user's programs; on the processor, big models are too slow to be useful.
            budget = Math.Min(hw.RamGb - 6, 12);
            var weak = hw.Gpus.FirstOrDefault(g => g.MemoryGb > 0);
            notes.Add(weak is null
                ? "No suitable graphics card found, so it runs on the processor. Answers will be slower."
                : $"The graphics card ({weak.Name}) can't run AI models well, so it runs on the processor. Answers will be slower.");
            if (forTeam) notes.Add("For a team, a computer with a graphics card (12 GB or more) is strongly recommended.");
        }

        if (hw.RamGb < MinRamGb || budget < ModelCatalog.RunGb(models[0]))
            return new Recommendation(RunMode.NotSuitable, null, Array.Empty<AiModel>(),
                notes.Append($"This computer has {hw.RamGb:0.#} GB of memory. Private AI needs at least {MinRamGb} GB, and 16 GB or more is recommended.").ToList(),
                "This computer can't run a private AI well. Recommend an upgrade or a dedicated AI computer.");

        var fits = models.Where(m => ModelCatalog.RunGb(m) <= budget).ToList();
        if (mode == RunMode.Processor) fits = fits.Where(m => m.DownloadGb <= 7).ToList(); // up to about 9B on a processor
        if (fits.Count == 0) fits.Add(models[0]);

        // Room on the disk for the model, the document search model and some headroom.
        var room = fits.Where(m => m.DownloadGb + ModelCatalog.DocumentSearch.DownloadGb + 5 <= hw.FreeDiskGb).ToList();
        if (room.Count == 0)
        {
            notes.Add($"Only {hw.FreeDiskGb:0} GB free on the drive. Free up space before installing.");
            room = fits.OrderBy(m => m.DownloadGb).Take(1).ToList();
        }

        var pick = room.MaxBy(m => m.Preference)!;
        var also = room.Where(m => m != pick).OrderByDescending(m => m.Preference).Take(3).ToList();
        if (hw.FreeDiskGb < 50) notes.Add($"{hw.FreeDiskGb:0} GB free on the drive. Keep at least 50 GB free for models and documents.");
        var speed = mode == RunMode.GraphicsCard ? "answers quickly" : "works, but answers will take a little while";
        return new Recommendation(mode, pick, also, notes, $"Recommended: {pick.Name} by {pick.MadeBy}. On this computer it {speed}.");
    }
}
