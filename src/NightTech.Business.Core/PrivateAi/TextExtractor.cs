using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

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

    public static ExtractResult Extract(string fileName, byte[] data)
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
        catch (Exception ex) when (ex is InvalidDataException or XmlException or IOException or FormatException)
        {
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

    public static string Html(string html)
    {
        html = Regex.Replace(html, @"<(script|style|noscript|svg|head)\b[\s\S]*?</\1\s*>", " ", RegexOptions.IgnoreCase);
        html = Regex.Replace(html, @"<!--[\s\S]*?-->", " ");
        html = Regex.Replace(html, @"<(br|/p|/div|/li|/tr|/h[1-6]|/section|/article|/table)\b[^>]*>", "\n", RegexOptions.IgnoreCase);
        html = Regex.Replace(html, @"<(td|th)\b[^>]*>", " | ", RegexOptions.IgnoreCase);
        html = Regex.Replace(html, @"<[^>]+>", " ");
        return WebUtility.HtmlDecode(html);
    }

    // ---------------- Office files (zip of XML) ----------------

    private static XmlDocument? Xml(ZipArchive z, string path)
    {
        var e = z.GetEntry(path);
        if (e is null) return null;
        if (e.Length > 200L * 1024 * 1024) throw new InvalidDataException("Part too large.");
        var doc = new XmlDocument { XmlResolver = null };
        using var s = e.Open();
        using var reader = XmlReader.Create(s, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
        doc.Load(reader);
        return doc;
    }

    private static void Docx(byte[] data, ExtractResult r)
    {
        using var z = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read);
        var doc = Xml(z, "word/document.xml") ?? throw new InvalidDataException("No document body.");
        var sb = new StringBuilder();
        foreach (XmlNode p in doc.GetElementsByTagName("w:p"))
        {
            foreach (XmlNode n in p.SelectNodes(".//*")!)
            {
                if (n.Name == "w:t") sb.Append(n.InnerText);
                else if (n.Name == "w:tab") sb.Append('\t');
                else if (n.Name is "w:br" or "w:cr") sb.Append('\n');
            }
            sb.Append('\n');
        }
        r.Parts.Add(new TextPart(0, sb.ToString()));
    }

    private static void Xlsx(byte[] data, ExtractResult r)
    {
        using var z = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read);
        var shared = new List<string>();
        var ss = Xml(z, "xl/sharedStrings.xml");
        if (ss is not null)
            foreach (XmlNode si in ss.GetElementsByTagName("si"))
                shared.Add(string.Concat(si.SelectNodes(".//*[local-name()='t']")!.Cast<XmlNode>().Select(t => t.InnerText)));

        // Sheet names, in workbook order.
        var names = new List<(string Name, string Path)>();
        var wb = Xml(z, "xl/workbook.xml");
        var rels = Xml(z, "xl/_rels/workbook.xml.rels");
        if (wb is not null && rels is not null)
        {
            var targets = rels.GetElementsByTagName("Relationship").Cast<XmlElement>()
                .ToDictionary(e => e.GetAttribute("Id"), e => e.GetAttribute("Target"));
            foreach (XmlElement s in wb.GetElementsByTagName("sheet"))
            {
                var id = s.GetAttribute("id", "http://schemas.openxmlformats.org/officeDocument/2006/relationships");
                if (targets.TryGetValue(id, out var t))
                    names.Add((s.GetAttribute("name"), t.StartsWith('/') ? t.TrimStart('/') : "xl/" + t));
            }
        }
        if (names.Count == 0)
            names = z.Entries.Where(e => e.FullName.StartsWith("xl/worksheets/sheet", StringComparison.Ordinal))
                .Select(e => (Path.GetFileNameWithoutExtension(e.Name), e.FullName)).ToList();

        int page = 0;
        foreach (var (name, path) in names)
        {
            var sheet = Xml(z, path);
            if (sheet is null) continue;
            var sb = new StringBuilder($"Sheet: {name}\n");
            int rows = 0;
            foreach (XmlNode row in sheet.GetElementsByTagName("row"))
            {
                var cells = new List<string>();
                foreach (XmlElement c in row.ChildNodes.OfType<XmlElement>().Where(e => e.LocalName == "c"))
                {
                    var type = c.GetAttribute("t");
                    var v = c.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.LocalName == "v")?.InnerText ?? "";
                    if (type == "s" && int.TryParse(v, out var i) && i >= 0 && i < shared.Count) v = shared[i];
                    else if (type == "inlineStr") v = c.InnerText;
                    cells.Add(v);
                }
                if (cells.Any(x => x.Length > 0)) { sb.Append(string.Join(" | ", cells)).Append('\n'); rows++; }
                if (rows >= 20000) { sb.Append("(more rows not included)\n"); break; }
            }
            r.Parts.Add(new TextPart(++page, sb.ToString()));
        }
    }

    private static void Pptx(byte[] data, ExtractResult r)
    {
        using var z = new ZipArchive(new MemoryStream(data), ZipArchiveMode.Read);
        var slides = z.Entries
            .Select(e => Regex.Match(e.FullName, @"^ppt/slides/slide(\d+)\.xml$"))
            .Where(m => m.Success)
            .Select(m => (Number: int.Parse(m.Groups[1].Value), Path: m.Value))
            .OrderBy(s => s.Number);
        foreach (var (number, path) in slides)
        {
            var doc = Xml(z, path);
            if (doc is null) continue;
            var sb = new StringBuilder();
            foreach (XmlNode p in doc.GetElementsByTagName("a:p"))
            {
                foreach (XmlNode t in p.SelectNodes(".//*[local-name()='t']")!) sb.Append(t.InnerText);
                sb.Append('\n');
            }
            r.Parts.Add(new TextPart(number, sb.ToString()));
        }
    }
}
