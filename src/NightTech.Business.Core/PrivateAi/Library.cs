using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NightTech.Business.Core.PrivateAi;

/// <summary>A passage of a document, small enough to hand to the AI as background.</summary>
public sealed record Chunk(int Page, string Text);

public static class Chunker
{
    /// <summary>Splits text into passages of about <paramref name="size"/> characters, breaking at paragraphs and sentences, with a little overlap.</summary>
    public static List<Chunk> Split(IEnumerable<TextPart> parts, int size = 1200, int overlap = 200)
    {
        var chunks = new List<Chunk>();
        foreach (var part in parts)
        {
            var text = part.Text;
            int start = 0;
            while (start < text.Length)
            {
                int end = Math.Min(text.Length, start + size);
                if (end < text.Length)
                {
                    int cut = Best(text, start + size / 2, end);
                    if (cut > start) end = cut;
                }
                var piece = text[start..end].Trim();
                if (piece.Length > 0) chunks.Add(new Chunk(part.Page, piece));
                if (end >= text.Length) break;
                int next = end - overlap;
                // Start the overlap at a word boundary.
                while (next > start && next < end && !char.IsWhiteSpace(text[next - 1])) next++;
                start = Math.Max(next, start + 1);
            }
        }
        return chunks;
    }

    private static int Best(string t, int from, int to)
    {
        foreach (var sep in new[] { "\n\n", "\n", ". ", "? ", "! ", "; ", ", ", " " })
        {
            int i = t.LastIndexOf(sep, to - 1, to - from, StringComparison.Ordinal);
            if (i >= from) return i + sep.Length;
        }
        return to;
    }
}

public sealed class LibraryDocument
{
    public string Id { get; set; } = "";
    public string FileName { get; set; } = "";
    public long Bytes { get; set; }
    public int Pages { get; set; }
    public int Passages { get; set; }
    public DateTime Added { get; set; }
    public string AddedBy { get; set; } = "";
}

public sealed record SearchHit(LibraryDocument Document, int Page, string Text, double Score);

/// <summary>
/// The document library: each document's passages and their search vectors, kept on this computer.
/// Stored as library.json (document list) and one .vec file per document.
/// </summary>
public sealed class Library
{
    private sealed class Entry
    {
        public required LibraryDocument Doc;
        public required List<Chunk> Chunks;
        public required List<float[]> Vectors;
    }

    private readonly string _folder;
    private readonly object _gate = new();
    private readonly Dictionary<string, Entry> _entries = new();
    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    public Library(string folder)
    {
        _folder = folder;
        Directory.CreateDirectory(folder);
        Load();
    }

    public IReadOnlyList<LibraryDocument> Documents
    {
        get { lock (_gate) return _entries.Values.Select(e => e.Doc).OrderBy(d => d.FileName, StringComparer.OrdinalIgnoreCase).ToList(); }
    }

    public int PassageCount { get { lock (_gate) return _entries.Values.Sum(e => e.Chunks.Count); } }

    public LibraryDocument Add(string fileName, long bytes, int pages, List<Chunk> chunks, List<float[]> vectors, string addedBy, DateTime now)
    {
        if (chunks.Count != vectors.Count) throw new ArgumentException("Every passage needs a vector.");
        var doc = new LibraryDocument
        {
            Id = Guid.NewGuid().ToString("N")[..12],
            FileName = Path.GetFileName(fileName),
            Bytes = bytes,
            Pages = pages,
            Passages = chunks.Count,
            Added = now,
            AddedBy = addedBy,
        };
        var entry = new Entry { Doc = doc, Chunks = chunks, Vectors = vectors.Select(Normalize).ToList() };
        lock (_gate)
        {
            WriteVectors(doc.Id, entry);
            _entries[doc.Id] = entry;
            SaveIndex();
        }
        return doc;
    }

    public bool Remove(string id)
    {
        lock (_gate)
        {
            if (!_entries.Remove(id)) return false;
            try { File.Delete(VecPath(id)); } catch (IOException) { }
            SaveIndex();
            return true;
        }
    }

    /// <summary>The passages closest in meaning to the question.</summary>
    public List<SearchHit> Search(float[] query, int top = 5, double minScore = 0.35)
    {
        var q = Normalize(query);
        var hits = new List<SearchHit>();
        lock (_gate)
        {
            foreach (var e in _entries.Values)
                for (int i = 0; i < e.Vectors.Count; i++)
                {
                    if (e.Vectors[i].Length != q.Length) continue;
                    double s = Dot(q, e.Vectors[i]);
                    if (s >= minScore) hits.Add(new SearchHit(e.Doc, e.Chunks[i].Page, e.Chunks[i].Text, s));
                }
        }
        return hits.OrderByDescending(h => h.Score).Take(top).ToList();
    }

    private static double Dot(float[] a, float[] b)
    {
        double s = 0;
        for (int i = 0; i < a.Length; i++) s += a[i] * b[i];
        return s;
    }

    private static float[] Normalize(float[] v)
    {
        double n = Math.Sqrt(v.Sum(x => (double)x * x));
        if (n == 0) return v.ToArray();
        return v.Select(x => (float)(x / n)).ToArray();
    }

    // ---------------- Storage ----------------

    private string IndexPath => Path.Combine(_folder, "library.json");
    private string VecPath(string id) => Path.Combine(_folder, id + ".vec");

    private void SaveIndex()
    {
        var tmp = IndexPath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_entries.Values.Select(e => e.Doc).ToList(), Json));
        File.Move(tmp, IndexPath, true);
    }

    /// <summary>Per document: passage count, then for each passage its page, text and vector.</summary>
    private void WriteVectors(string id, Entry e)
    {
        var tmp = VecPath(id) + ".tmp";
        using (var w = new BinaryWriter(File.Create(tmp), Encoding.UTF8))
        {
            w.Write(0x4E544149); // "NTAI"
            w.Write(1);
            w.Write(e.Chunks.Count);
            for (int i = 0; i < e.Chunks.Count; i++)
            {
                w.Write(e.Chunks[i].Page);
                w.Write(e.Chunks[i].Text);
                w.Write(e.Vectors[i].Length);
                foreach (var f in e.Vectors[i]) w.Write(f);
            }
        }
        File.Move(tmp, VecPath(id), true);
    }

    private void Load()
    {
        if (!File.Exists(IndexPath)) return;
        List<LibraryDocument>? docs;
        try { docs = JsonSerializer.Deserialize<List<LibraryDocument>>(File.ReadAllText(IndexPath), Json); }
        catch (JsonException) { return; }
        foreach (var d in docs ?? new())
        {
            try
            {
                using var r = new BinaryReader(File.OpenRead(VecPath(d.Id)), Encoding.UTF8);
                if (r.ReadInt32() != 0x4E544149 || r.ReadInt32() != 1) continue;
                int n = r.ReadInt32();
                var chunks = new List<Chunk>(n);
                var vecs = new List<float[]>(n);
                for (int i = 0; i < n; i++)
                {
                    int page = r.ReadInt32();
                    var text = r.ReadString();
                    int len = r.ReadInt32();
                    if (len is < 0 or > 65536) throw new InvalidDataException();
                    var v = new float[len];
                    for (int j = 0; j < len; j++) v[j] = r.ReadSingle();
                    chunks.Add(new Chunk(page, text));
                    vecs.Add(v);
                }
                _entries[d.Id] = new Entry { Doc = d, Chunks = chunks, Vectors = vecs };
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or EndOfStreamException) { /* a missing or damaged file is skipped */ }
        }
    }
}
