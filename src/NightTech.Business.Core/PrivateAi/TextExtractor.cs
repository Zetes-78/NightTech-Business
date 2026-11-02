using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Linq;

namespace NightTech.Business.Core.PrivateAi;

/// <summary>One page (or section) of text taken from a document. Page is 0 when the format has no pages.</summary>
public sealed record TextPart(int Page, string Text);

public sealed class ExtractResult
{
    public List<TextPart> Parts { get; } = new();
    public string? Problem { get; set; }
    public int Characters => Parts.Sum(p => p.Text.Length);
}

/// <summary>Reads the text out of documents for the document library. Our own readers; no outside libraries.</summary>
public static class TextExtractor
{
    public static readonly string[] Supported = { ".txt", ".md", ".csv", ".log", ".html", ".htm", ".docx", ".xlsx", ".pptx", ".pdf" };

    public static bool IsSupported(string fileName) =>
        Supported.Contains(Path.GetExtension(fileName).ToLowerInvariant());

    /// <summary>Most text a document may contribute (about 2,500 pages).</summary>
    public const int MaxChars = 5_000_000;
    /// <summary>Most XML an Office file may expand to, across all its parts (stops "zip bomb" files).</summary>
    public const long MaxOfficeXmlChars = 150_000_000;

    /// <summary>
    /// Reads a document on its own thread with a large stack and a time limit, so a damaged or hostile file can't
    /// crash or freeze the program that called it.
    /// </summary>
    public static ExtractResult Extract(string fileName, byte[] data, TimeSpan? timeLimit = null)
    {
        ExtractResult? result = null;
        var t = new Thread(() => result = ExtractNow(fileName, data), 256 * 1024 * 1024) { IsBackground = true, Name = "Document reader" };
        t.Start();
        if (!t.Join(timeLimit ?? TimeSpan.FromMinutes(3)))
            return new ExtractResult { Problem = "This document took too long to read. Save it in another format (for example Word or PDF) and try again." };
        return result ?? new ExtractResult { Problem = "This document couldn't be read." };
    }

    private static ExtractResult ExtractNow(string fileName, byte[] data)
    {
        var r = new ExtractResult();
        try
        {
            switch (Path.GetExtension(fileName).ToLowerInvariant())
            {
                case ".txt": case ".md": case ".csv": case ".log":
                    r.Parts.Add(new TextPart(0, DecodeText(data))); break;
                case ".html": case ".htm":
                    r.Parts.Add(new TextPart(0, Html(DecodeText(data)))); break;
                case ".docx": Docx(data, r); break;
                case ".xlsx": Xlsx(data, r); break;
                case ".pptx": Pptx(data, r); break;
                case ".pdf": PdfText.Extract(data, r); break;
                default: r.Problem = "This kind of file isn't supported. Use PDF, Word, Excel, PowerPoint, text or web pages."; break;
            }
        }
        catch (TooBigException)
        {
            r.Parts.Clear();
            r.Problem = "This document is too large or expands to too much data to add. Split it into smaller files.";
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            r.Parts.Clear();
            r.Problem = "The file looks damaged or isn't really a " + Path.GetExtension(fileName) + " file.";
        }
        for (int i = 0; i < r.Parts.Count; i++) r.Parts[i] = r.Parts[i] with { Text = Tidy(r.Parts[i].Text) };
        r.Parts.RemoveAll(p => p.Text.Length == 0);
        if (r.Problem is null && r.Characters == 0)
            r.Problem = "No text was found. If it's a scanned document, it needs to be typed text (or run through text recognition) first.";
        return r;
    }

    public static string DecodeText(byte[] data)
    {
        if (data.Length >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) return Encoding.UTF8.GetString(data, 3, data.Length - 3);
        if (data.Length >= 2 && data[0] == 0xFF && data[1] == 0xFE) return Encoding.Unicode.GetString(data, 2, data.Length - 2);
        if (data.Length >= 2 && data[0] == 0xFE && data[1] == 0xFF) return Encoding.BigEndianUnicode.GetString(data, 2, data.Length - 2);
        try { return new UTF8Encoding(false, true).GetString(data); }
        catch (DecoderFallbackException) { return Encoding.Latin1.GetString(data); }
    }

    private static string Tidy(string s)
    {
        s = s.Replace("\r\n", "\n").Replace('\r', '\n').Replace(' ', ' ');
        s = Regex.Replace(s, @"[ \t\f\v]+", " ");
        s = Regex.Replace(s, @" *\n *", "\n");
        s = Regex.Replace(s, @"\n{3,}", "\n\n");
        return s.Trim();
    }

    private static readonly HashSet<string> SkipContent = new(StringComparer.OrdinalIgnoreCase) { "script", "style", "noscript", "svg", "head", "template" };
    private static readonly HashSet<string> LineBreak = new(StringComparer.OrdinalIgnoreCase)
        { "br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "table", "ul", "ol", "header", "footer", "blockquote", "pre" };

    /// <summary>Text of a web page. One forward pass, so any input takes time in proportion to its size.</summary>
    public static string Html(string html)
    {
        var sb = new StringBuilder(Math.Min(html.Length, MaxChars));
        int i = 0, n = html.Length;
        while (i < n && sb.Length < MaxChars)
        {
            int lt = html.IndexOf('<', i);
            if (lt < 0) { sb.Append(html, i, n - i); break; }
            sb.Append(html, i, lt - i);
            if (string.CompareOrdinal(html, lt, "<!--", 0, 4) == 0)
            {
                int end = html.IndexOf("-->", lt + 4, StringComparison.Ordinal);
                i = end < 0 ? n : end + 3;
                continue;
            }
            int gt = html.IndexOf('>', lt + 1);
            if (gt < 0) { i = n; break; }
            // Tag name
            int k = lt + 1;
            bool closing = k < gt && html[k] == '/';
            if (closing) k++;
            int nameStart = k;
            while (k < gt && (char.IsLetterOrDigit(html[k]) || html[k] == '-')) k++;
            var name = html[nameStart..k];
            i = gt + 1;
            if (!closing && SkipContent.Contains(name))
            {
                int end = html.IndexOf("</" + name, i, StringComparison.OrdinalIgnoreCase);
                if (end < 0) { i = n; break; }
                int endGt = html.IndexOf('>', end);
                i = endGt < 0 ? n : endGt + 1;
                continue;
            }
            if (name.Equals("td", StringComparison.OrdinalIgnoreCase) || name.Equals("th", StringComparison.OrdinalIgnoreCase)) { if (!closing) sb.Append(" | "); }
            else if (LineBreak.Contains(name)) { if (sb.Length > 0 && sb[^1] != '\n') sb.Append('\n'); }
            else sb.Append(' ');
        }
        return WebUtility.HtmlDecode(sb.ToString());
    }

    // ---------------- Office files (zip of XML) ----------------
    // Read with a forward-only XmlReader (no document tree, no recursion), with limits on how much XML may be read.

    internal sealed class TooBigException : Exception { }

    private sealed class Budget
    {
        public long XmlChars;
        public int Text;
    }

    private static XmlReader? Reader(ZipArchive z, string path, Budget b)
    {
        var e = z.GetEntry(path);
        if (e is null) return null;
        if (e.Length > MaxOfficeXmlChars) throw new TooBigException();
        b.XmlChars += e.Length;
        if (b.XmlChars > MaxOfficeXmlChars) throw new TooBigException();
        return XmlReader.Create(e.Open(), new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxOfficeXmlChars,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true,
            CloseInput = true,
        });
    }

    private static void Add(StringBuilder sb, string s, Budget b)
    {
        sb.Append(s);
        b.Text += s.Length;
        if (b.Text > MaxChars) throw new TooBigException();
    }

    /// <summary>Paragraph text: elements named <paramref name="text"/> inside <paramref name="para"/>, a line per paragraph.</summary>
    private static string Paragraphs(XmlReader x, string para, string text, Budget b, bool wordExtras)
    {
        var sb = new StringBuilder();
        using (x)
        {
            // ReadElementContentAsString already moves to the next node, so only call Read() when it didn't.
            bool more = x.Read();
            while (more)
            {
                if (x.NodeType == XmlNodeType.Element && x.LocalName == text && !x.IsEmptyElement)
                {
                    Add(sb, x.ReadElementContentAsString(), b);
                    more = !x.EOF;
                    continue;
                }
                if (x.NodeType == XmlNodeType.Element && wordExtras)
                {
                    if (x.LocalName == "tab") Add(sb, "\t", b);
                    else if (x.LocalName is "br" or "cr") Add(sb, "\n", b);
                }
                else if (x.NodeType == XmlNodeType.EndElement && x.LocalName == para) Add(sb, "\n", b);
                more = x.Read();
            }
        }
        return sb.ToString();
    }

    private static void Docx(byte[] data, ExtractResult r)
    {
        using var z = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read);
        var b = new Budget();
        var x = Reader(z, "word/document.xml", b) ?? throw new InvalidDataException("No document body.");
        r.Parts.Add(new TextPart(0, Paragraphs(x, "p", "t", b, wordExtras: true)));
    }

    private static void Pptx(byte[] data, ExtractResult r)
    {
        using var z = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read);
        var b = new Budget();
        var slides = z.Entries
            .Select(e => Regex.Match(e.FullName, @"^ppt/slides/slide(\d{1,5})\.xml$"))
            .Where(m => m.Success)
            .Select(m => (Number: int.Parse(m.Groups[1].Value), Path: m.Value))
            .OrderBy(s => s.Number);
        foreach (var (number, path) in slides)
        {
            var x = Reader(z, path, b);
            if (x is not null) r.Parts.Add(new TextPart(number, Paragraphs(x, "p", "t", b, wordExtras: false)));
        }
    }

    private static void Xlsx(byte[] data, ExtractResult r)
    {
        using var z = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read);
        var b = new Budget();

        // Shared strings: one per <si>, joining its <t> pieces.
        var shared = new List<string>();
        var ss = Reader(z, "xl/sharedStrings.xml", b);
        if (ss is not null)
            using (ss)
            {
                StringBuilder? cur = null;
                bool more = ss.Read();
                while (more)
                {
                    if (ss.NodeType == XmlNodeType.Element && ss.LocalName == "t" && cur is not null && !ss.IsEmptyElement)
                    {
                        cur.Append(ss.ReadElementContentAsString());
                        more = !ss.EOF;
                        continue;
                    }
                    if (ss.NodeType == XmlNodeType.Element && ss.LocalName == "si")
                    {
                        if (ss.IsEmptyElement) shared.Add("");
                        else cur = new StringBuilder();
                    }
                    else if (ss.NodeType == XmlNodeType.EndElement && ss.LocalName == "si" && cur is not null)
                    {
                        shared.Add(cur.ToString());
                        b.Text += cur.Length;
                        if (b.Text > MaxChars) throw new TooBigException();
                        cur = null;
                    }
                    more = ss.Read();
                }
            }

        // Sheet names and files, in workbook order.
        var targets = new Dictionary<string, string>();
        var rels = Reader(z, "xl/_rels/workbook.xml.rels", b);
        if (rels is not null)
            using (rels)
                while (rels.Read())
                    if (rels.NodeType == XmlNodeType.Element && rels.LocalName == "Relationship" && rels.GetAttribute("Id") is { } id && rels.GetAttribute("Target") is { } tg)
                        targets.TryAdd(id, tg);
        var names = new List<(string Name, string Path)>();
        var wb = Reader(z, "xl/workbook.xml", b);
        if (wb is not null)
            using (wb)
                while (wb.Read())
                    if (wb.NodeType == XmlNodeType.Element && wb.LocalName == "sheet"
                        && wb.GetAttribute("id", "http://schemas.openxmlformats.org/officeDocument/2006/relationships") is { } rid
                        && targets.TryGetValue(rid, out var t))
                        names.Add((wb.GetAttribute("name") ?? "Sheet", t.StartsWith('/') ? t.TrimStart('/') : "xl/" + t));
        if (names.Count == 0)
            names = z.Entries.Where(e => e.FullName.StartsWith("xl/worksheets/sheet", StringComparison.Ordinal))
                .Select(e => (Path.GetFileNameWithoutExtension(e.Name), e.FullName)).ToList();

        int page = 0;
        foreach (var (name, path) in names.DistinctBy(n => n.Path))
        {
            var x = Reader(z, path, b);
            if (x is null) continue;
            var sb = new StringBuilder($"Sheet: {name}\n");
            using (x)
            {
                var cells = new List<string>();
                string type = "";
                bool more = x.Read();
                while (more)
                {
                    if (x.NodeType == XmlNodeType.Element && x.LocalName is "v" or "t" && !x.IsEmptyElement)
                    {
                        var v = x.ReadElementContentAsString();
                        if (type == "s" && int.TryParse(v, out var i) && i >= 0 && i < shared.Count) v = shared[i];
                        cells.Add(v);
                        more = !x.EOF;
                        continue;
                    }
                    if (x.NodeType == XmlNodeType.Element && x.LocalName == "row") cells.Clear();
                    else if (x.NodeType == XmlNodeType.Element && x.LocalName == "c") type = x.GetAttribute("t") ?? "";
                    else if (x.NodeType == XmlNodeType.EndElement && x.LocalName == "row" && cells.Any(c => c.Length > 0))
                        Add(sb, string.Join(" | ", cells) + "\n", b);
                    more = x.Read();
                }
            }
            r.Parts.Add(new TextPart(++page, sb.ToString()));
        }
    }
}
