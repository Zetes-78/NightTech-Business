using System.IO.Compression;
using System.Net;
using System.Text;
using NightTech.Business.Core.PrivateAi;

namespace NightTech.Business.Tests;

public class PrivateAiTests
{
    private static string Temp() => Path.Combine(Path.GetTempPath(), "ntai-" + Guid.NewGuid().ToString("N"));
    private static readonly DateTime Now = new(2026, 11, 2, 9, 0, 0);

    // ---------------- Recommender ----------------

    private static HardwareProfile Pc(double ram, double vram = 0, string vendor = "NVIDIA", double disk = 500) =>
        new("PC", "Intel Core i7", 8, ram, vram > 0 ? new[] { new GpuInfo("Card", vram, vendor) } : Array.Empty<GpuInfo>(), disk, "Windows 11");

    [Fact]
    public void Graphics_card_size_decides_the_model()
    {
        Assert.Equal("gemma4:12b", Recommender.For(Pc(32, 12)).Pick!.Tag);
        Assert.Equal("gemma4:26b", Recommender.For(Pc(64, 24)).Pick!.Tag);
        Assert.Equal("qwen3.5:9b", Recommender.For(Pc(16, 8)).Pick!.Tag);
        Assert.Equal(RunMode.GraphicsCard, Recommender.For(Pc(32, 12)).Mode);
    }

    [Fact]
    public void Without_a_usable_card_it_runs_a_small_model_on_the_processor()
    {
        var r = Recommender.For(Pc(16));
        Assert.Equal(RunMode.Processor, r.Mode);
        Assert.True(r.Pick!.DownloadGb <= 7);
        var intel = Recommender.For(Pc(16, 2, "Intel"));
        Assert.Equal(RunMode.Processor, intel.Mode);
        Assert.Contains(intel.Notes, n => n.Contains("can't run AI models well"));
    }

    [Fact]
    public void Too_little_memory_is_not_suitable()
    {
        var r = Recommender.For(Pc(4));
        Assert.Equal(RunMode.NotSuitable, r.Mode);
        Assert.Null(r.Pick);
    }

    [Fact]
    public void Us_only_and_disk_space_are_respected()
    {
        Assert.All(new[] { Recommender.For(Pc(16, 8), usCompaniesOnly: true).Pick! }, m => Assert.True(m.UsCompany));
        var tight = Recommender.For(Pc(64, 24, disk: 15));
        Assert.True(tight.Pick!.DownloadGb + 5 <= 15 || tight.Notes.Any(n => n.Contains("Free up space")));
    }

    // ---------------- Documents ----------------

    private static byte[] Zip(params (string Name, string Text)[] entries)
    {
        using var ms = new MemoryStream();
        using (var z = new ZipArchive(ms, ZipArchiveMode.Create, true))
            foreach (var (n, t) in entries)
            {
                using var w = new StreamWriter(z.CreateEntry(n).Open());
                w.Write(t);
            }
        return ms.ToArray();
    }

    [Fact]
    public void Reads_word_excel_and_powerpoint()
    {
        var docx = Zip(("word/document.xml",
            "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>" +
            "<w:p><w:r><w:t>Vacation is 10 days.</w:t></w:r></w:p><w:p><w:r><w:t xml:space=\"preserve\">After </w:t></w:r><w:r><w:t>two years, 15.</w:t></w:r></w:p></w:body></w:document>"));
        var d = TextExtractor.Extract("h.docx", docx);
        Assert.Null(d.Problem);
        Assert.Equal("Vacation is 10 days.\nAfter two years, 15.", d.Parts.Single().Text);

        var xlsx = Zip(
            ("xl/workbook.xml", "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"Prices\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>"),
            ("xl/_rels/workbook.xml.rels", "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Target=\"worksheets/sheet1.xml\"/></Relationships>"),
            ("xl/sharedStrings.xml", "<sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><si><t>Drain cleaning</t></si></sst>"),
            ("xl/worksheets/sheet1.xml", "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData><row><c t=\"s\"><v>0</v></c><c><v>149</v></c></row></sheetData></worksheet>"));
        Assert.Equal("Sheet: Prices\nDrain cleaning | 149", TextExtractor.Extract("p.xlsx", xlsx).Parts.Single().Text);

        var pptx = Zip(
            ("ppt/slides/slide2.xml", "<p:sld xmlns:p=\"p\" xmlns:a=\"a\"><a:p><a:r><a:t>Second</a:t></a:r></a:p></p:sld>"),
            ("ppt/slides/slide1.xml", "<p:sld xmlns:p=\"p\" xmlns:a=\"a\"><a:p><a:r><a:t>First</a:t></a:r></a:p></p:sld>"));
        var p = TextExtractor.Extract("d.pptx", pptx);
        Assert.Equal(new[] { "First", "Second" }, p.Parts.Select(x => x.Text));
        Assert.Equal(new[] { 1, 2 }, p.Parts.Select(x => x.Page));
    }

    [Fact]
    public void Office_files_with_outside_references_are_not_followed()
    {
        var evil = Zip(("word/document.xml", "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///c:/windows/win.ini\">]><w:document xmlns:w=\"w\"><w:p><w:t>&e;</w:t></w:p></w:document>"));
        var r = TextExtractor.Extract("evil.docx", evil);
        Assert.NotNull(r.Problem);
        Assert.Empty(r.Parts);
    }

    [Fact]
    public void Reads_web_pages_and_text_files()
    {
        var html = Encoding.UTF8.GetBytes("<html><head><title>x</title><script>alert(1)</script></head><body><h1>Hours</h1><p>Open 7&ndash;3 &amp; weekends</p></body></html>");
        Assert.Equal("Hours\nOpen 7–3 & weekends", TextExtractor.Extract("a.html", html).Parts.Single().Text);
        var utf16 = new byte[] { 0xFF, 0xFE }.Concat(Encoding.Unicode.GetBytes("Café")).ToArray();
        Assert.Equal("Café", TextExtractor.Extract("a.txt", utf16).Parts.Single().Text);
        Assert.NotNull(TextExtractor.Extract("a.exe", new byte[10]).Problem);
        Assert.False(TextExtractor.IsSupported("photo.jpg"));
    }

    [Theory]
    [InlineData("chrome-handbook.pdf")]
    [InlineData("lo-handbook.pdf")]
    [InlineData("rl-handbook.pdf")]
    [InlineData("latex-handbook.pdf")]
    public void Reads_pdfs_from_different_programs(string file)
    {
        var r = TextExtractor.Extract(file, File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Samples", file)));
        Assert.Null(r.Problem);
        Assert.Equal(2, r.Parts.Count);
        var all = string.Join(" ", r.Parts.Select(p => p.Text)).Replace('\n', ' ');
        Assert.Contains("Vacation policy: New full-time employees get 10 paid vacation days", all);
        Assert.Contains("Thanksgiving", r.Parts[1].Text);
        Assert.Equal(1, r.Parts[0].Page);
    }

    [Fact]
    public void Hand_made_pdf_with_a_compressed_stream_and_unicode_map()
    {
        // A Type0 font with 2-byte codes mapped through a ToUnicode CMap, in a Flate-compressed stream.
        static byte[] Deflate(string s)
        {
            using var ms = new MemoryStream();
            using (var z = new ZLibStream(ms, CompressionLevel.Optimal, true)) z.Write(Encoding.Latin1.GetBytes(s));
            return ms.ToArray();
        }
        var cmap = "begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n2 beginbfchar\n<0001> <0048>\n<0002> <0069>\nendbfchar\n1 beginbfrange\n<0010> <0012> <0041>\nendbfrange\nendcmap";
        var content = Deflate("BT /F1 12 Tf 72 720 Td <00010002> Tj 0 -20 Td [<0010> -50 <00110012>] TJ ET");
        var ms = new MemoryStream();
        void W(string s) => ms.Write(Encoding.Latin1.GetBytes(s));
        W("%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n");
        W("2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 5 0 R >> >> >> endobj\n");
        W("3 0 obj << /Type /Page /Parent 2 0 R /Contents 4 0 R >> endobj\n");
        W($"4 0 obj << /Length {content.Length} /Filter /FlateDecode >> stream\n"); ms.Write(content); W("\nendstream endobj\n");
        W("5 0 obj << /Type /Font /Subtype /Type0 /ToUnicode 6 0 R >> endobj\n");
        W($"6 0 obj << /Length {cmap.Length} >> stream\n{cmap}\nendstream endobj\ntrailer << /Root 1 0 R >>\n%%EOF");
        var r = TextExtractor.Extract("x.pdf", ms.ToArray());
        Assert.Null(r.Problem);
        Assert.Equal("Hi\nABC", r.Parts.Single().Text);
    }

    [Fact]
    public void Ascii85_decodes()
    {
        var bytes = PdfText.Ascii85(Encoding.ASCII.GetBytes("<~87cURD]j7BEbo7~>"));
        Assert.Equal("Hello world", Encoding.ASCII.GetString(bytes!));
    }

    [Fact]
    public void Damaged_or_encrypted_pdfs_explain_themselves()
    {
        Assert.NotNull(TextExtractor.Extract("x.pdf", Encoding.ASCII.GetBytes("%PDF-1.4 garbage")).Problem);
        var enc = Encoding.ASCII.GetBytes("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R /Encrypt 9 0 R >>\n%%EOF");
        Assert.Contains("password", TextExtractor.Extract("x.pdf", enc).Problem);
    }

    // ---------------- Library ----------------

    [Fact]
    public void Chunker_splits_on_sentences_with_overlap_and_keeps_pages()
    {
        var text = string.Join(" ", Enumerable.Range(1, 200).Select(i => $"Sentence number {i} is here."));
        var chunks = Chunker.Split(new[] { new TextPart(3, text) }, size: 400, overlap: 80);
        Assert.True(chunks.Count > 5);
        Assert.All(chunks, c => Assert.True(c.Text.Length <= 400));
        Assert.All(chunks, c => Assert.Equal(3, c.Page));
        Assert.All(chunks.Take(chunks.Count - 1), c => Assert.EndsWith(".", c.Text));
        Assert.Contains("Sentence number 200 is here.", chunks[^1].Text);
    }

    [Fact]
    public void Library_finds_the_closest_passage_and_survives_a_restart()
    {
        var dir = Temp();
        try
        {
            var lib = new Library(dir);
            var doc = lib.Add("Handbook.pdf", 1000, 2,
                new() { new Chunk(1, "vacation days"), new Chunk(2, "holiday closings") },
                new() { new[] { 1f, 0f, 0f }, new[] { 0f, 1f, 0f } }, "jason", Now);
            var hit = lib.Search(new[] { 0.9f, 0.1f, 0f }).First();
            Assert.Equal("vacation days", hit.Text);
            Assert.Equal(1, hit.Page);
            Assert.Empty(lib.Search(new[] { 0f, 0f, 1f }));

            var again = new Library(dir);
            Assert.Equal("Handbook.pdf", again.Documents.Single().FileName);
            Assert.Equal(2, again.PassageCount);
            Assert.Equal("holiday closings", again.Search(new[] { 0f, 1f, 0f }).First().Text);
            Assert.True(again.Remove(doc.Id));
            Assert.Empty(new Library(dir).Documents);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // ---------------- Accounts and network ----------------

    [Fact]
    public void Passwords_are_hashed_and_checked()
    {
        var dir = Temp();
        try
        {
            var path = Path.Combine(dir, "users.json");
            var users = new UserStore(path);
            users.Add("jason", "Jason", "correct horse", false, Now);
            Assert.True(users.Find("jason")!.IsAdmin); // the first person is always an administrator
            Assert.NotNull(users.Verify("JASON", "correct horse"));
            Assert.Null(users.Verify("jason", "wrong password"));
            Assert.Null(users.Verify("nobody", "correct horse"));
            Assert.DoesNotContain("correct horse", File.ReadAllText(path));
            Assert.Throws<ArgumentException>(() => users.Add("jason", "", "another one", false, Now));
            Assert.Throws<ArgumentException>(() => users.Add("carin", "", "short", false, Now));
            Assert.Throws<ArgumentException>(() => users.Add("../x", "", "long enough", false, Now));
            Assert.Throws<ArgumentException>(() => users.Remove("jason")); // last admin
            var stamp = users.Find("jason")!.Stamp;
            users.SetPassword("jason", "new password!");
            Assert.NotEqual(stamp, new UserStore(path).Find("jason")!.Stamp);
            Assert.NotNull(new UserStore(path).Verify("jason", "new password!"));
            // A change made by another program (the setup tool) is picked up.
            var other = new UserStore(path);
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(-5));
            other.SetPassword("jason", "changed elsewhere");
            Assert.NotNull(users.Verify("jason", "changed elsewhere"));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    [Fact]
    public void Sign_in_limiter_locks_after_five_failures()
    {
        var l = new SignInLimiter();
        for (int i = 0; i < 4; i++) l.Failed("jason", Now);
        Assert.Null(l.Blocked("jason", Now));
        l.Failed("jason", Now);
        Assert.NotNull(l.Blocked("jason", Now));
        Assert.Null(l.Blocked("jason", Now + SignInLimiter.Lockout + TimeSpan.FromSeconds(1)));
    }

    [Theory]
    [InlineData("127.0.0.1", true)]
    [InlineData("192.168.1.20", true)]
    [InlineData("10.4.5.6", true)]
    [InlineData("172.16.0.9", true)]
    [InlineData("172.32.0.9", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("::1", true)]
    [InlineData("fe80::1", true)]
    [InlineData("fd12::5", true)]
    [InlineData("2001:4860::8888", false)]
    [InlineData("::ffff:192.168.0.5", true)]
    [InlineData("::ffff:1.2.3.4", false)]
    public void Only_the_local_network_is_allowed(string ip, bool local) =>
        Assert.Equal(local, NetworkGuard.IsLocal(IPAddress.Parse(ip)));

    // ---------------- Prompts and chats ----------------

    [Fact]
    public void Long_chats_keep_the_newest_messages_that_fit()
    {
        var history = Enumerable.Range(0, 40).Select(i => new ChatMessage(i % 2 == 0 ? "user" : "assistant", new string('x', 1000))).ToList();
        var fitted = PromptBuilder.Fit("system", history, new ChatMessage("user", "latest"), 4096);
        Assert.Equal("system", fitted[0].Role);
        Assert.Equal("latest", fitted[^1].Content);
        Assert.True(fitted.Count < history.Count);
        Assert.Equal("user", fitted[1].Role);
    }

    [Fact]
    public void Excerpts_are_numbered_with_their_source()
    {
        var doc = new LibraryDocument { FileName = "Handbook.pdf" };
        var text = PromptBuilder.WithExcerpts("How many days?", new[] { new SearchHit(doc, 12, "10 days", 0.9) });
        Assert.Contains("[1] Handbook.pdf, page 12:\n10 days", text);
        Assert.EndsWith("Question: How many days?", text);
        Assert.Contains("couldn't find", PromptBuilder.WithExcerpts("x", Array.Empty<SearchHit>()));
        Assert.Contains("Acme", PromptBuilder.System(new AiSettings { CompanyName = "Acme" }, Now));
    }

    [Fact]
    public void Chats_are_private_per_user_and_ids_are_checked()
    {
        var dir = Temp();
        try
        {
            var store = new ChatStore(dir);
            var c = store.Create("jason", true, Now);
            c.Title = "Vacation";
            c.Messages.Add(new StoredMessage { Role = "user", Content = "hi", At = Now });
            store.Save("jason", c);
            Assert.Equal("Vacation", store.List("jason").Single().Title);
            Assert.Empty(store.List("carin"));
            Assert.Null(store.Get("carin", c.Id));
            Assert.Null(store.Get("jason", "../users"));
            Assert.False(store.Delete("jason", "..\\x"));
            Assert.True(store.Delete("jason", c.Id));
            Assert.Equal("_", ChatStore.SafeKey(".."));
            Assert.Equal("What is our vacation policy for new employees...", ChatStore.TitleFrom("What is our vacation policy for new employees in their first year?"));
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    // ---------------- Ollama client ----------------

    private sealed class FakeOllama : HttpMessageHandler
    {
        public readonly List<(string Path, string Body)> Requests = new();
        public Func<string, string, (HttpStatusCode, string)> Reply = (_, _) => (HttpStatusCode.OK, "{}");
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage r, CancellationToken ct)
        {
            var body = r.Content is null ? "" : await r.Content.ReadAsStringAsync(ct);
            Requests.Add((r.RequestUri!.AbsolutePath, body));
            var (code, text) = Reply(r.RequestUri.AbsolutePath, body);
            return new HttpResponseMessage(code) { Content = new StringContent(text) };
        }
    }

    [Fact]
    public async Task Chat_streams_pieces_and_reports_errors()
    {
        var fake = new FakeOllama
        {
            Reply = (path, _) => (HttpStatusCode.OK,
                "{\"message\":{\"role\":\"assistant\",\"content\":\"Hel\"},\"done\":false}\n" +
                "{\"message\":{\"role\":\"assistant\",\"content\":\"lo\"},\"done\":false}\n" +
                "{\"done\":true}\n"),
        };
        var client = new OllamaClient(handler: fake);
        var pieces = new List<string>();
        await foreach (var p in client.ChatAsync("gemma4:12b", new[] { new ChatMessage("user", "hi") }, 8192)) pieces.Add(p);
        Assert.Equal("Hello", string.Concat(pieces));
        Assert.Contains("\"num_ctx\":8192", fake.Requests[0].Body);
        Assert.Contains("\"stream\":true", fake.Requests[0].Body);

        fake.Reply = (_, _) => (HttpStatusCode.NotFound, "{\"error\":\"model 'x' not found\"}");
        var ex = await Assert.ThrowsAsync<OllamaException>(async () => { await foreach (var _ in client.ChatAsync("x", new[] { new ChatMessage("user", "hi") }, 2048)) { } });
        Assert.Contains("not found", ex.Message);
    }

    [Fact]
    public async Task Embed_pull_and_models()
    {
        var fake = new FakeOllama
        {
            Reply = (path, body) => path switch
            {
                "/api/embed" => (HttpStatusCode.OK, "{\"embeddings\":[[0.1,0.2],[0.3,0.4]]}"),
                "/api/tags" => (HttpStatusCode.OK, "{\"models\":[{\"name\":\"phi4:latest\",\"size\":9100000000,\"modified_at\":\"2026-10-01T00:00:00Z\"}]}"),
                "/api/pull" => (HttpStatusCode.OK, "{\"status\":\"pulling\",\"total\":100,\"completed\":50}\n{\"status\":\"success\"}\n"),
                _ => (HttpStatusCode.OK, "{\"version\":\"0.12.0\"}"),
            },
        };
        var client = new OllamaClient(handler: fake);
        var vecs = await client.EmbedAsync("nomic-embed-text", new[] { "a", "b" });
        Assert.Equal(0.4f, vecs[1][1]);
        var models = await client.ModelsAsync();
        Assert.True(OllamaClient.Has(models, "phi4"));
        Assert.False(OllamaClient.Has(models, "gemma4:12b"));
        var seen = new List<PullProgress>();
        await client.PullAsync("phi4", new Progress<PullProgress>(seen.Add));
        Assert.Equal("0.12.0", await client.VersionAsync());

        fake.Reply = (_, _) => (HttpStatusCode.OK, "{\"status\":\"pulling\"}\n");
        await Assert.ThrowsAsync<OllamaException>(() => client.PullAsync("phi4", null));
    }

    // ---------------- Setup report ----------------

    [Fact]
    public void Setup_report_round_trips_and_never_holds_a_password()
    {
        var r = new AiSetupReport
        {
            Ticket = "NT-0042", Customer = "Acme Plumbing", Started = Now, Finished = Now,
            Hardware = new HardwareProfile("OFFICE-PC", "Intel Core i7", 8, 32, new[] { new GpuInfo("RTX 4070", 12, "NVIDIA") }, 400, "Windows 11"),
            Model = "gemma4:12b", ModelName = "Gemma 4 (12B) by Google", AdminUser = "owner", Port = 8080,
            Addresses = new() { "http://office-pc:8080" },
            Steps = new() { new SetupStep { Name = "Install", Result = StepResult.Done }, new SetupStep { Name = "Firewall", Result = StepResult.Warning, Detail = "Public network" } },
        };
        Assert.True(r.Success);
        var dir = Temp();
        try
        {
            var (json, text) = r.Save(dir);
            var back = AiSetupReport.FromJson(File.ReadAllText(json))!;
            Assert.Equal("private-ai-setup", back.Kind);
            Assert.Equal(12, back.Hardware!.Gpus[0].MemoryGb);
            Assert.Equal(StepResult.Warning, back.Steps[1].Result);
            Assert.Contains("NT-0042", Path.GetFileName(json));
            var t = File.ReadAllText(text);
            Assert.Contains("Private AI is installed and running.", t);
            Assert.Contains("[!!] Firewall: Public network", t);
            Assert.DoesNotContain("password", File.ReadAllText(json).ToLowerInvariant());
            r.Steps[0].Result = StepResult.Failed;
            Assert.False(r.Success);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }
}
