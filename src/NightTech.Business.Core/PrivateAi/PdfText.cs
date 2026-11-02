using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Text.RegularExpressions;

namespace NightTech.Business.Core.PrivateAi;

/// <summary>
/// Reads the text of a PDF, page by page: objects (including compressed object streams), the page tree, content
/// streams, fonts and their ToUnicode maps, and form XObjects. Scanned pages (pictures of text) have no text to read.
/// </summary>
internal static class PdfText
{
    private const int MaxStreamBytes = 24 * 1024 * 1024;
    /// <summary>Most data all of one PDF's streams may expand to, so a small file can't fill the memory.</summary>
    private const long MaxDecodedBytes = 96L * 1024 * 1024;
    private const int MaxChars = TextExtractor.MaxChars;
    private static readonly TimeSpan RegexLimit = TimeSpan.FromSeconds(5);

    // ---------------- Values ----------------

    internal sealed record Name(string Value);
    internal sealed record Ref(int Number);
    internal sealed class Dict : Dictionary<string, object> { }

    private sealed class Obj
    {
        public object? Value;
        public int RawStart = -1, RawLength;   // the stream's bytes, in the original file (never copied)
        public byte[]? Decoded;
        public bool DecodeTried;
    }

    private sealed class Doc
    {
        public readonly Dictionary<int, Obj> Objects = new();
        public required byte[] Data;
        public long DecodedBytes;
        public object? Resolve(object? v, int depth = 0)
        {
            while (v is Ref r && depth++ < 32) v = Objects.TryGetValue(r.Number, out var o) ? o.Value : null;
            return v;
        }
        public Dict? D(object? v) => Resolve(v) as Dict;
        public byte[]? Stream(object? v)
        {
            if (v is not Ref r || !Objects.TryGetValue(r.Number, out var o)) return null;
            if (!o.DecodeTried) { o.DecodeTried = true; o.Decoded = Decode(this, o); }
            return o.Decoded;
        }
    }

    public static void Extract(byte[] data, ExtractResult result)
    {
        var doc = Load(data);
        if (doc.Objects.Values.Any(o => o.Value is Dict d && d.ContainsKey("Encrypt")) || Regex.IsMatch(Latin1(data, Math.Max(0, data.Length - 4096), Math.Min(4096, data.Length)), @"/Encrypt\s", RegexOptions.None, RegexLimit))
        {
            result.Problem = "This PDF is password-protected or encrypted. Save an unprotected copy and add that instead.";
            return;
        }
        var pages = Pages(doc);
        int total = 0, n = 0;
        foreach (var page in pages)
        {
            n++;
            var sb = new StringBuilder();
            var res = Inherited(doc, page, "Resources");
            foreach (var content in Contents(doc, page))
                Run(doc, content, doc.D(res), sb, 0);
            var text = sb.ToString();
            total += text.Length;
            result.Parts.Add(new TextPart(n, text));
            if (total > MaxChars) break;
        }
        var all = string.Concat(result.Parts.Select(p => p.Text));
        if (all.Trim().Length > 0 && Readable(all) < 0.75)
        {
            result.Parts.Clear();
            result.Problem = "This PDF's text uses fonts that can't be read. Open it, save or export it as a Word document, and add that instead.";
        }
    }

    private static double Readable(string s)
    {
        int good = 0, total = 0;
        foreach (var c in s)
        {
            if (char.IsWhiteSpace(c)) continue;
            total++;
            if (char.IsLetterOrDigit(c) || char.IsPunctuation(c) || char.IsSymbol(c) && c < 0x2400) good++;
        }
        return total == 0 ? 1 : (double)good / total;
    }

    private static string Latin1(byte[] b, int start, int len) => Encoding.Latin1.GetString(b, start, len);

    // ---------------- Objects ----------------

    private static readonly Regex ObjStart = new(@"(\d{1,9})\s+(\d{1,5})\s+obj\b", RegexOptions.Compiled, TimeSpan.FromSeconds(30));

    private static Doc Load(byte[] data)
    {
        var doc = new Doc { Data = data };
        var text = Encoding.Latin1.GetString(data);
        foreach (Match m in ObjStart.Matches(text))
        {
            if (!int.TryParse(m.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var num)) continue;
            int pos = m.Index + m.Length;
            try
            {
                var p = new Parser(data, pos);
                var value = p.Value();
                var o = new Obj { Value = value };
                p.SkipSpace();
                if (value is Dict d && p.Matches("stream"))
                {
                    int s = p.Pos + 6;
                    if (s < data.Length && data[s] == '\r') s++;
                    if (s < data.Length && data[s] == '\n') s++;
                    int len = -1;
                    if (d.TryGetValue("Length", out var l) && l is double dl && dl >= 0 && s + (long)dl <= data.Length) len = (int)dl;
                    if (len < 0 || !EndstreamNear(data, s + len))
                    {
                        int e = text.IndexOf("endstream", s, StringComparison.Ordinal);
                        if (e < 0) continue;
                        len = e - s;
                        if (len > 0 && data[s + len - 1] == '\n') len--;
                        if (len > 0 && data[s + len - 1] == '\r') len--;
                    }
                    o.RawStart = s;
                    o.RawLength = len;
                }
                doc.Objects[num] = o; // later objects replace earlier ones (incremental updates)
            }
            catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or ArgumentException or OverflowException) { /* skip a damaged object */ }
        }

        // Objects packed inside compressed object streams.
        foreach (var o in doc.Objects.Values.ToList())
        {
            if (o.Value is not Dict d || !IsName(d, "Type", "ObjStm")) continue;
            var bytes = Decode(doc, o);
            if (bytes is null || d.GetValueOrDefault("N") is not double count || d.GetValueOrDefault("First") is not double first) continue;
            try
            {
                var hp = new Parser(bytes, 0);
                var heads = new List<(int Num, int Off)>();
                for (int i = 0; i < (int)count; i++)
                {
                    if (hp.Value() is not double on || hp.Value() is not double off) break;
                    heads.Add(((int)on, (int)off));
                }
                foreach (var (num, off) in heads)
                {
                    long at = (long)first + off;
                    if (at < 0 || at >= bytes.Length || doc.Objects.ContainsKey(num)) continue;
                    doc.Objects[num] = new Obj { Value = new Parser(bytes, (int)at).Value() };
                }
            }
            catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or ArgumentException or OverflowException) { }
        }
        return doc;
    }

    private static bool EndstreamNear(byte[] data, int at)
    {
        for (int i = at; i < Math.Min(data.Length - 9, at + 4); i++)
            if (data[i] == 'e' && Encoding.Latin1.GetString(data, i, 9) == "endstream") return true;
        return false;
    }

    private static bool IsName(Dict d, string key, string name) => d.TryGetValue(key, out var v) && v is Name n && n.Value == name;

    private static byte[]? Decode(Doc doc, Obj o)
    {
        if (o.RawStart < 0 || o.Value is not Dict d) return null;
        var filter = doc.Resolve(d.GetValueOrDefault("Filter"));
        var filters = filter switch
        {
            null => new List<string>(),
            Name n => new List<string> { n.Value },
            List<object> l => l.Select(x => (doc.Resolve(x) as Name)?.Value ?? "").ToList(),
            _ => new List<string> { "?" },
        };
        byte[]? bytes = null;
        foreach (var f in filters)
        {
            var input = bytes is null ? new ArraySegment<byte>(doc.Data, o.RawStart, o.RawLength) : new ArraySegment<byte>(bytes);
            if (f is "FlateDecode" or "Fl") bytes = Inflate(input, doc);
            else if (f is "ASCII85Decode" or "A85") bytes = Ascii85(input.ToArray());
            else if (f is "ASCIIHexDecode" or "AHx") bytes = AsciiHex(input.ToArray());
            else return null; // images and other encodings hold no text
            if (bytes is null) return null;
        }
        bytes ??= new ArraySegment<byte>(doc.Data, o.RawStart, o.RawLength).ToArray();
        doc.DecodedBytes += bytes.Length;
        if (doc.DecodedBytes > MaxDecodedBytes) throw new TextExtractor.TooBigException();
        return bytes;
    }

    internal static byte[]? Ascii85(byte[] input)
    {
        var o = new MemoryStream();
        uint tuple = 0;
        int count = 0;
        int i = 0;
        if (input.Length >= 2 && input[0] == '<' && input[1] == '~') i = 2;
        for (; i < input.Length; i++)
        {
            byte c = input[i];
            if (c == '~') break;
            if (c is 0 or 9 or 10 or 12 or 13 or 32) continue;
            if (c == 'z' && count == 0) { o.Write(new byte[4]); continue; }
            if (c < '!' || c > 'u') return null;
            tuple = tuple * 85 + (uint)(c - '!');
            if (++count == 5)
            {
                o.WriteByte((byte)(tuple >> 24)); o.WriteByte((byte)(tuple >> 16)); o.WriteByte((byte)(tuple >> 8)); o.WriteByte((byte)tuple);
                tuple = 0; count = 0;
            }
            if (o.Length > MaxStreamBytes) return null;
        }
        if (count > 1)
        {
            for (int k = count; k < 5; k++) tuple = tuple * 85 + 84;
            for (int k = 0; k < count - 1; k++) o.WriteByte((byte)(tuple >> (24 - 8 * k)));
        }
        return o.ToArray();
    }

    private static byte[]? AsciiHex(byte[] input)
    {
        var digits = new StringBuilder();
        foreach (var b in input)
        {
            if (b == '>') break;
            if (Uri.IsHexDigit((char)b)) digits.Append((char)b);
        }
        if (digits.Length % 2 == 1) digits.Append('0');
        return Convert.FromHexString(digits.ToString());
    }

    private static byte[]? Inflate(ArraySegment<byte> input, Doc? doc)
    {
        long room = doc is null ? MaxStreamBytes : Math.Min(MaxStreamBytes, MaxDecodedBytes - doc.DecodedBytes);
        foreach (var skip in new[] { 0, 2 })
        {
            if (input.Count <= skip) return null;
            try
            {
                using var src = new MemoryStream(input.Array!, input.Offset + skip, input.Count - skip);
                using Stream z = skip == 0 ? new ZLibStream(src, CompressionMode.Decompress) : new DeflateStream(src, CompressionMode.Decompress);
                using var dst = new MemoryStream();
                var buf = new byte[81920];
                int n;
                while ((n = z.Read(buf, 0, buf.Length)) > 0)
                {
                    dst.Write(buf, 0, n);
                    if (dst.Length > room) throw new TextExtractor.TooBigException();
                }
                return dst.ToArray();
            }
            catch (InvalidDataException) { }
        }
        return null;
    }

    // ---------------- Pages ----------------

    private static List<Dict> Pages(Doc doc)
    {
        var catalog = doc.Objects.Values.Select(o => o.Value).OfType<Dict>().LastOrDefault(d => IsName(d, "Type", "Catalog"));
        var pages = new List<Dict>();
        var seen = new HashSet<Dict>(ReferenceEqualityComparer.Instance);
        void Walk(object? node, int depth)
        {
            var d = doc.D(node);
            if (d is null || depth > 64 || !seen.Add(d)) return;
            if (IsName(d, "Type", "Page") || !d.ContainsKey("Kids") && d.ContainsKey("Contents")) { pages.Add(d); return; }
            if (doc.Resolve(d.GetValueOrDefault("Kids")) is List<object> kids)
                foreach (var k in kids)
                {
                    if (doc.D(k) is { } kd) ParentOf[kd] = d;
                    Walk(k, depth + 1);
                }
        }
        ParentOf.Clear();
        if (catalog is not null) Walk(catalog.GetValueOrDefault("Pages"), 0);
        if (pages.Count == 0)
            pages = doc.Objects.OrderBy(kv => kv.Key).Select(kv => kv.Value.Value).OfType<Dict>().Where(d => IsName(d, "Type", "Page")).ToList();
        return pages;
    }

    [ThreadStatic] private static Dictionary<Dict, Dict>? _parentOf;
    private static Dictionary<Dict, Dict> ParentOf => _parentOf ??= new Dictionary<Dict, Dict>(ReferenceEqualityComparer.Instance);

    private static object? Inherited(Doc doc, Dict page, string key)
    {
        var d = page;
        for (int i = 0; i < 64 && d is not null; i++)
        {
            if (d.TryGetValue(key, out var v)) return v;
            d = d.TryGetValue("Parent", out var p) ? doc.D(p) : (ParentOf.TryGetValue(d, out var pd) ? pd : null);
        }
        return null;
    }

    private static IEnumerable<byte[]> Contents(Doc doc, Dict page)
    {
        var c = page.GetValueOrDefault("Contents");
        var list = doc.Resolve(c) is List<object> l ? l : new List<object?> { c }!;
        // Several content streams on one page are one stream split in pieces: join them.
        var joined = new MemoryStream();
        var seen = new HashSet<int>();
        foreach (var part in list)
        {
            if (part is Ref pr && !seen.Add(pr.Number)) continue; // the same stream listed again adds nothing
            var s = doc.Stream(part);
            if (s is null) continue;
            joined.Write(s);
            joined.WriteByte((byte)'\n');
        }
        if (joined.Length > 0) yield return joined.ToArray();
    }

    // ---------------- Fonts ----------------

    private sealed class Font
    {
        public bool TwoByte;
        public Dictionary<int, string>? Map;
        public Dictionary<int, double>? Widths;
        public double DefaultWidth = 500;

        /// <summary>The text, and how wide it is in thousandths of the font size.</summary>
        public string Decode(byte[] b, out double width)
        {
            var sb = new StringBuilder();
            width = 0;
            if (TwoByte)
            {
                for (int i = 0; i + 1 < b.Length; i += 2)
                {
                    int code = b[i] << 8 | b[i + 1];
                    width += W(code);
                    if (Map is not null && Map.TryGetValue(code, out var s)) sb.Append(s);
                }
            }
            else
            {
                foreach (var x in b)
                {
                    width += W(x);
                    if (Map is not null && Map.TryGetValue(x, out var s)) sb.Append(s);
                    else sb.Append(WinAnsi(x));
                }
            }
            return sb.ToString();
        }

        private double W(int code) => Widths is not null && Widths.TryGetValue(code, out var w) && w > 0 ? w : DefaultWidth;
    }

    private static readonly string Cp1252High = "€\u0081‚ƒ„…†‡ˆ‰Š‹Œ\u008DŽ\u008F\u0090‘’“”•–—˜™š›œ\u009DžŸ";
    private static char WinAnsi(byte b) => b is >= 0x80 and <= 0x9F ? Cp1252High[b - 0x80] : (char)b;

    private static Font LoadFont(Doc doc, object? fontRef)
    {
        var f = new Font();
        var d = doc.D(fontRef);
        if (d is null) return f;
        f.TwoByte = IsName(d, "Subtype", "Type0");
        var tu = doc.Stream(d.GetValueOrDefault("ToUnicode"));
        if (tu is not null) f.Map = CMap(tu, out var codeBytes) is { Count: > 0 } map ? map : null;
        try
        {
            if (f.TwoByte)
            {
                f.DefaultWidth = 1000;
                var desc = doc.Resolve(d.GetValueOrDefault("DescendantFonts")) is List<object> dl && dl.Count > 0 ? doc.D(dl[0]) : null;
                if (desc is not null)
                {
                    if (doc.Resolve(desc.GetValueOrDefault("DW")) is double dw) f.DefaultWidth = dw;
                    if (doc.Resolve(desc.GetValueOrDefault("W")) is List<object> w) f.Widths = CidWidths(doc, w);
                }
            }
            else if (doc.Resolve(d.GetValueOrDefault("Widths")) is List<object> widths && doc.Resolve(d.GetValueOrDefault("FirstChar")) is double first)
            {
                f.Widths = new Dictionary<int, double>();
                for (int i = 0; i < widths.Count; i++)
                    if (doc.Resolve(widths[i]) is double wv) f.Widths[(int)first + i] = wv;
                var nonZero = f.Widths.Values.Where(v => v > 0).ToList();
                if (nonZero.Count > 0) f.DefaultWidth = nonZero.Average();
            }
        }
        catch (Exception ex) when (ex is InvalidCastException or ArgumentException) { }
        return f;
    }

    /// <summary>CID font widths: "c [w1 w2 ...]" and "cFirst cLast w" entries.</summary>
    private static Dictionary<int, double> CidWidths(Doc doc, List<object> w)
    {
        var map = new Dictionary<int, double>();
        for (int i = 0; i < w.Count;)
        {
            if (doc.Resolve(w[i]) is not double c) break;
            var next = i + 1 < w.Count ? doc.Resolve(w[i + 1]) : null;
            if (next is List<object> arr)
            {
                for (int k = 0; k < arr.Count && map.Count < 200_000; k++)
                    if (doc.Resolve(arr[k]) is double wv) map[(int)c + k] = wv;
                i += 2;
            }
            else if (next is double last && i + 2 < w.Count && doc.Resolve(w[i + 2]) is double wv2)
            {
                for (int k = (int)c; k <= (int)last && map.Count < 200_000; k++) map[k] = wv2;
                i += 3;
            }
            else break;
        }
        return map;
    }

    /// <summary>Reads bfchar and bfrange entries of a ToUnicode CMap.</summary>
    internal static Dictionary<int, string> CMap(byte[] data, out int codeBytes)
    {
        var map = new Dictionary<int, string>();
        codeBytes = 1;
        var s = Encoding.Latin1.GetString(data);
        var cs = Regex.Match(s, @"begincodespacerange\s*<([0-9A-Fa-f]+)>", RegexOptions.None, RegexLimit);
        if (cs.Success) codeBytes = Math.Max(1, cs.Groups[1].Value.Length / 2);
        foreach (Match block in Regex.Matches(s, @"beginbfchar([\s\S]*?)endbfchar", RegexOptions.None, RegexLimit))
            foreach (Match m in Regex.Matches(block.Groups[1].Value, @"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>", RegexOptions.None, RegexLimit))
                map[Hex(m.Groups[1].Value)] = Utf16(m.Groups[2].Value);
        foreach (Match block in Regex.Matches(s, @"beginbfrange([\s\S]*?)endbfrange", RegexOptions.None, RegexLimit))
            foreach (Match m in Regex.Matches(block.Groups[1].Value, @"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]*>|\[[^\]]*\])", RegexOptions.None, RegexLimit))
            {
                int lo = Hex(m.Groups[1].Value), hi = Hex(m.Groups[2].Value);
                if (hi < lo || hi - lo > 65535) continue;
                var dst = m.Groups[3].Value;
                if (dst.StartsWith('['))
                {
                    var items = Regex.Matches(dst, @"<([0-9A-Fa-f]*)>", RegexOptions.None, RegexLimit).Select(x => x.Groups[1].Value).ToList();
                    for (int i = 0; i < items.Count && lo + i <= hi; i++) map[lo + i] = Utf16(items[i]);
                }
                else
                {
                    var start = Utf16(dst.Trim('<', '>'));
                    if (start.Length == 0) continue;
                    for (int c = lo; c <= hi; c++)
                    {
                        var chars = start.ToCharArray();
                        chars[^1] = (char)(chars[^1] + (c - lo));
                        map[c] = new string(chars);
                    }
                }
            }
        return map;
    }

    private static int Hex(string h) => h.Length == 0 ? 0 : int.Parse(h.Length > 8 ? h[^8..] : h, NumberStyles.HexNumber, CultureInfo.InvariantCulture);

    private static string Utf16(string hex)
    {
        if (hex.Length % 2 == 1) hex += "0";
        var bytes = Convert.FromHexString(hex);
        if (bytes.Length == 1) return ((char)bytes[0]).ToString();
        return Encoding.BigEndianUnicode.GetString(bytes, 0, bytes.Length / 2 * 2);
    }

    // ---------------- Content streams ----------------

    /// <summary>
    /// Where text lands on the page decides where spaces and line breaks go: a gap wider than a fraction of the font size
    /// is a space, and a different line is a line break. Widths come from the font, so letters placed one by one
    /// (common in PDFs from web browsers) join back into words.
    /// </summary>
    private sealed class TextState
    {
        public double FontSize = 12, Sx = 1, Sy = 1;      // font size and the text matrix scale
        public double LineX, LineY, X, Y;                 // start of the current line, and where the next text goes
        public double Leading;
        public bool HasPrev, ForceBreak;
        public double PrevEnd, PrevY;
    }

    private static void Run(Doc doc, byte[] content, Dict? resources, StringBuilder sb, int depth)
    {
        if (depth > 6) return;
        var fonts = new Dictionary<string, Font>();
        var fontDict = doc.D(resources?.GetValueOrDefault("Font"));
        Font current = new();
        var t = new TextState();
        var operands = new List<object>();
        var p = new Parser(content, 0);

        void Show(byte[] bytes)
        {
            var text = current.Decode(bytes, out var w);
            double em = Math.Abs(t.FontSize * t.Sx);
            if (t.HasPrev)
            {
                if (t.ForceBreak || Math.Abs(t.Y - t.PrevY) > Math.Max(0.5, Math.Abs(t.FontSize * t.Sy) * 0.5)) sb.Append('\n');
                else if (t.X - t.PrevEnd > em * 0.15 || t.PrevEnd - t.X > em * 2) sb.Append(' ');
            }
            sb.Append(text);
            t.X += w / 1000.0 * t.FontSize * t.Sx;
            t.HasPrev = true; t.ForceBreak = false;
            t.PrevEnd = t.X; t.PrevY = t.Y;
        }

        void MoveLine(double tx, double ty)
        {
            t.LineX += tx * t.Sx; t.LineY += ty * t.Sy;
            t.X = t.LineX; t.Y = t.LineY;
        }

        while (true)
        {
            object? tok;
            try { tok = p.Token(); }
            catch (Exception ex) when (ex is FormatException or IndexOutOfRangeException or ArgumentException) { break; }
            if (tok is null) break;
            if (tok is not Op op) { operands.Add(tok); if (operands.Count > 64) operands.RemoveAt(0); continue; }
            double N(int fromEnd) => operands.Count >= fromEnd && operands[^fromEnd] is double d ? d : 0;
            switch (op.Name)
            {
                case "Tf":
                    if (operands.Count >= 2 && operands[^2] is Name fn)
                    {
                        if (!fonts.TryGetValue(fn.Value, out var f))
                            fonts[fn.Value] = f = LoadFont(doc, fontDict?.GetValueOrDefault(fn.Value));
                        current = f;
                        t.FontSize = N(1) == 0 ? 1 : N(1);
                    }
                    break;
                case "TL": t.Leading = N(1); break;
                case "Tm":
                    if (operands.Count >= 6)
                    {
                        t.Sx = N(6) == 0 ? 1 : N(6); t.Sy = N(3) == 0 ? 1 : N(3);
                        t.LineX = t.X = N(2); t.LineY = t.Y = N(1);
                    }
                    break;
                case "Td": MoveLine(N(2), N(1)); break;
                case "TD": t.Leading = -N(1); MoveLine(N(2), N(1)); break;
                case "T*": MoveLine(0, -t.Leading); t.ForceBreak = true; break;
                case "Tj":
                    if (operands.Count >= 1 && operands[^1] is byte[] s1) Show(s1);
                    break;
                case "'": case "\"":
                    MoveLine(0, -t.Leading); t.ForceBreak = true;
                    if (operands.Count >= 1 && operands[^1] is byte[] s2) Show(s2);
                    break;
                case "TJ":
                    if (operands.Count >= 1 && operands[^1] is List<object> arr)
                        foreach (var a in arr)
                        {
                            if (a is byte[] s3) Show(s3);
                            else if (a is double gap) t.X -= gap / 1000.0 * t.FontSize * t.Sx;
                        }
                    break;
                case "BT": t.Sx = t.Sy = 1; t.LineX = t.LineY = t.X = t.Y = 0; break;
                case "Do":
                    if (operands.Count >= 1 && operands[^1] is Name xn)
                    {
                        var xobjs = doc.D(resources?.GetValueOrDefault("XObject"));
                        var xref = xobjs?.GetValueOrDefault(xn.Value);
                        if (doc.D(xref) is { } xd && IsName(xd, "Subtype", "Form") && doc.Stream(xref) is { } xs)
                        {
                            sb.Append('\n');
                            Run(doc, xs, doc.D(xd.GetValueOrDefault("Resources")) ?? resources, sb, depth + 1);
                            sb.Append('\n');
                            t.HasPrev = false;
                        }
                    }
                    break;
            }
            operands.Clear();
            if (sb.Length > MaxChars) break;
        }
    }



    // ---------------- Parser ----------------

    internal sealed record Op(string Name);
    internal sealed class Null { public static readonly Null Instance = new(); }

    internal sealed class Parser
    {
        private readonly byte[] _b;
        private int _depth;
        private const int MaxDepth = 100;
        public int Pos;
        public Parser(byte[] b, int pos) { _b = b; Pos = pos; }

        private static bool IsWs(byte c) => c is 0 or 9 or 10 or 12 or 13 or 32;
        private static bool IsDelim(byte c) => c is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';

        public void SkipSpace()
        {
            while (Pos < _b.Length)
            {
                if (IsWs(_b[Pos])) Pos++;
                else if (_b[Pos] == '%') { while (Pos < _b.Length && _b[Pos] != '\n' && _b[Pos] != '\r') Pos++; }
                else break;
            }
        }

        public bool Matches(string word)
        {
            if (Pos + word.Length > _b.Length) return false;
            for (int i = 0; i < word.Length; i++) if (_b[Pos + i] != word[i]) return false;
            return true;
        }

        /// <summary>A whole value (dictionary, array, number, reference, string or name).</summary>
        public object? Value()
        {
            var t = Token();
            if (t is double a)
            {
                // "12 0 R" is a reference.
                int save = Pos;
                var t2 = Token();
                if (t2 is double)
                {
                    var t3 = Token();
                    if (t3 is Op { Name: "R" }) return new Ref((int)a);
                }
                Pos = save;
                return a;
            }
            return t;
        }

        /// <summary>The next token: values, plus operators (as Op) in content streams. Null at the end.</summary>
        public object? Token()
        {
            SkipSpace();
            if (Pos >= _b.Length) return null;
            byte c = _b[Pos];
            if (c == '/')
            {
                int s = ++Pos;
                while (Pos < _b.Length && !IsWs(_b[Pos]) && !IsDelim(_b[Pos])) Pos++;
                return new Name(DecodeName(Encoding.Latin1.GetString(_b, s, Pos - s)));
            }
            if (c == '<' && Pos + 1 < _b.Length && _b[Pos + 1] == '<')
            {
                Pos += 2;
                if (++_depth > MaxDepth) throw new FormatException("Nested too deeply.");
                try
                {
                    var d = new Dict();
                    while (true)
                    {
                        SkipSpace();
                        if (Pos >= _b.Length) throw new FormatException("Unclosed dictionary.");
                        if (_b[Pos] == '>' && Pos + 1 < _b.Length && _b[Pos + 1] == '>') { Pos += 2; return d; }
                        var k = Token();
                        if (k is not Name key) { if (k is null) throw new FormatException(); continue; }
                        d[key.Value] = Value()!;
                    }
                }
                finally { _depth--; }
            }
            if (c == '<') return HexString();
            if (c == '(') return LiteralString();
            if (c == '[')
            {
                Pos++;
                if (++_depth > MaxDepth) throw new FormatException("Nested too deeply.");
                try
                {
                    var list = new List<object>();
                    while (true)
                    {
                        SkipSpace();
                        if (Pos >= _b.Length) throw new FormatException("Unclosed array.");
                        if (_b[Pos] == ']') { Pos++; return list; }
                        var v = Value();
                        if (v is Op o && o.Name == "R") continue;
                        if (v is not null) list.Add(v);
                        if (list.Count > 1_000_000) throw new FormatException("Array too large.");
                    }
                }
                finally { _depth--; }
            }
            if (c == ']' || c == '>' || c == ')' || c == '{' || c == '}') { Pos++; return new Op(((char)c).ToString()); }
            if (c is >= (byte)'0' and <= (byte)'9' || c is (byte)'-' or (byte)'+' or (byte)'.')
            {
                int s = Pos++;
                while (Pos < _b.Length && (_b[Pos] is >= (byte)'0' and <= (byte)'9' || _b[Pos] == '.')) Pos++;
                var str = Encoding.Latin1.GetString(_b, s, Pos - s);
                return double.TryParse(str, NumberStyles.Float, CultureInfo.InvariantCulture, out var num) ? num : 0.0;
            }
            int st = Pos;
            while (Pos < _b.Length && !IsWs(_b[Pos]) && !IsDelim(_b[Pos])) Pos++;
            if (Pos == st) Pos++;
            var word = Encoding.Latin1.GetString(_b, st, Pos - st);
            if (word == "BI") { SkipInlineImage(); return new Op("EI"); }
            return word switch { "true" => true, "false" => false, "null" => Null.Instance, _ => new Op(word) };
        }

        private void SkipInlineImage()
        {
            // Inline image data is binary; skip to " EI" followed by whitespace.
            while (Pos + 3 < _b.Length)
            {
                if (IsWs(_b[Pos]) && _b[Pos + 1] == 'E' && _b[Pos + 2] == 'I' && (Pos + 3 >= _b.Length || IsWs(_b[Pos + 3]))) { Pos += 3; return; }
                Pos++;
            }
            Pos = _b.Length;
        }

        private static string DecodeName(string s) =>
            s.Contains('#') ? Regex.Replace(s, "#([0-9A-Fa-f]{2})", m => ((char)Convert.ToByte(m.Groups[1].Value, 16)).ToString()) : s;

        private byte[] HexString()
        {
            Pos++;
            var digits = new StringBuilder();
            while (Pos < _b.Length && _b[Pos] != '>')
            {
                var ch = (char)_b[Pos++];
                if (Uri.IsHexDigit(ch)) digits.Append(ch);
            }
            Pos++;
            if (digits.Length % 2 == 1) digits.Append('0');
            return Convert.FromHexString(digits.ToString());
        }

        private byte[] LiteralString()
        {
            Pos++;
            var o = new List<byte>();
            int depth = 1;
            while (Pos < _b.Length)
            {
                byte c = _b[Pos++];
                if (c == '\\' && Pos < _b.Length)
                {
                    byte e = _b[Pos++];
                    switch (e)
                    {
                        case (byte)'n': o.Add(10); break;
                        case (byte)'r': o.Add(13); break;
                        case (byte)'t': o.Add(9); break;
                        case (byte)'b': o.Add(8); break;
                        case (byte)'f': o.Add(12); break;
                        case (byte)'\r': if (Pos < _b.Length && _b[Pos] == '\n') Pos++; break;
                        case (byte)'\n': break;
                        default:
                            if (e is >= (byte)'0' and <= (byte)'7')
                            {
                                int v = e - '0';
                                for (int i = 0; i < 2 && Pos < _b.Length && _b[Pos] is >= (byte)'0' and <= (byte)'7'; i++) v = v * 8 + (_b[Pos++] - '0');
                                o.Add((byte)v);
                            }
                            else o.Add(e);
                            break;
                    }
                }
                else if (c == '(') { depth++; o.Add(c); }
                else if (c == ')') { if (--depth == 0) break; o.Add(c); }
                else o.Add(c);
            }
            return o.ToArray();
        }
    }
}
