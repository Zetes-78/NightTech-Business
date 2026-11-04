using System.Drawing.Imaging;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using NightTech.Business.Core.Sentinel;
using BrandInfo = NightTech.Business.Core.Brand;

namespace NightTech.Sentinel.Agent;

/// <summary>
/// The remote desktop helper. Runs in the session at the screen (started by the service), captures the screen in
/// tiles, sends only the tiles that changed, and plays back the tech's mouse and keyboard. It shows a banner the whole
/// time, with a Disconnect button the person at the PC can press to end the session.
/// Messages to the service: 1 = JSON control, 2 = tile (x, y, w, h as 16-bit numbers, then JPEG bytes).
/// </summary>
public static class DesktopHelper
{
    private const int Tile = 128;
    private static volatile bool _running = true;
    private static volatile bool _fullRefresh = true;
    private static Stream? _pipe;

    public static int Run(string pipeName)
    {
        var tech = Environment.GetCommandLineArgs().Skip(3).FirstOrDefault() ?? "A technician";
        try
        {
            var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            pipe.Connect(10000);
            _pipe = pipe;
        }
        catch (Exception e) when (e is TimeoutException or IOException) { return 1; }

        var capture = new Thread(CaptureLoop) { IsBackground = true, Name = "capture" };
        var input = new Thread(InputLoop) { IsBackground = true, Name = "input" };
        capture.Start();
        input.Start();

        Application.EnableVisualStyles();
        using var banner = new Banner(tech);
        banner.Disconnect += () => { Send(LiveLink.Control(new { t = "end", d = "The person at the PC disconnected." })); _running = false; };
        var timer = new System.Windows.Forms.Timer { Interval = 500 };
        timer.Tick += (_, _) => { if (!_running) banner.Close(); };
        timer.Start();
        Application.Run(banner);
        _running = false;
        capture.Join(2000);
        return 0;
    }

    private static void Send(byte[] m)
    {
        try { if (_pipe is not null) PipeFrames.Write(_pipe, m, CancellationToken.None).GetAwaiter().GetResult(); }
        catch (Exception e) when (e is IOException or ObjectDisposedException) { _running = false; }
    }

    // ---------------- Screen ----------------

    private static void CaptureLoop()
    {
        byte[]? previous = null;
        Rectangle last = Rectangle.Empty;
        var jpeg = ImageCodecInfo.GetImageEncoders().First(c => c.FormatID == ImageFormat.Jpeg.Guid);
        using var quality = new EncoderParameters(1) { Param = { [0] = new EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 55L) } };
        while (_running)
        {
            var started = Environment.TickCount64;
            try
            {
                Desktop.FollowInput();
                var screen = SystemInformation.VirtualScreen;
                if (screen != last)
                {
                    last = screen;
                    previous = null;
                    Send(LiveLink.Control(new { t = "screen", w = screen.Width, h = screen.Height, x = screen.X, y = screen.Y }));
                }
                using var bmp = new Bitmap(screen.Width, screen.Height, PixelFormat.Format32bppRgb);
                using (var g = Graphics.FromImage(bmp))
                    g.CopyFromScreen(screen.X, screen.Y, 0, 0, screen.Size, CopyPixelOperation.SourceCopy);
                var data = bmp.LockBits(new Rectangle(0, 0, bmp.Width, bmp.Height), ImageLockMode.ReadOnly, PixelFormat.Format32bppRgb);
                int stride = data.Stride;
                var pixels = new byte[stride * bmp.Height];
                Marshal.Copy(data.Scan0, pixels, 0, pixels.Length);
                bmp.UnlockBits(data);
                bool full = _fullRefresh || previous is null || previous.Length != pixels.Length;
                _fullRefresh = false;
                for (int ty = 0; ty < bmp.Height; ty += Tile)
                    for (int tx = 0; tx < bmp.Width; tx += Tile)
                    {
                        int w = Math.Min(Tile, bmp.Width - tx), h = Math.Min(Tile, bmp.Height - ty);
                        if (!full && Same(previous!, pixels, stride, tx, ty, w, h)) continue;
                        using var tile = bmp.Clone(new Rectangle(tx, ty, w, h), PixelFormat.Format24bppRgb);
                        using var ms = new MemoryStream();
                        ms.WriteByte(2);
                        foreach (var v in new[] { tx, ty, w, h }) ms.Write(BitConverter.GetBytes((ushort)v));
                        tile.Save(ms, jpeg, quality);
                        Send(ms.ToArray());
                    }
                previous = pixels;
            }
            catch (Exception e) when (e is System.ComponentModel.Win32Exception or ArgumentException or ExternalException)
            {
                // The desktop is switching (sign-in screen, UAC): try again shortly.
                previous = null;
            }
            int elapsed = (int)(Environment.TickCount64 - started);
            Thread.Sleep(Math.Max(30, 125 - elapsed));   // about 8 frames a second at most
        }
    }

    private static bool Same(byte[] a, byte[] b, int stride, int x, int y, int w, int h)
    {
        for (int row = y; row < y + h; row++)
        {
            int off = row * stride + x * 4;
            if (!a.AsSpan(off, w * 4).SequenceEqual(b.AsSpan(off, w * 4))) return false;
        }
        return true;
    }

    // ---------------- Mouse and keyboard ----------------

    private sealed class InputMsg
    {
        public string T { get; set; } = "";
        public int X { get; set; }
        public int Y { get; set; }
        public int B { get; set; }
        public int Delta { get; set; }
        public int Code { get; set; }
        public bool Ext { get; set; }
        public bool Up { get; set; }
        public string D { get; set; } = "";
    }

    private static void InputLoop()
    {
        while (_running)
        {
            byte[]? m;
            try { m = PipeFrames.Read(_pipe!, CancellationToken.None).GetAwaiter().GetResult(); }
            catch (Exception e) when (e is IOException or ObjectDisposedException) { m = null; }
            if (m is null) { _running = false; return; }
            if (m.Length < 2 || m[0] != 1) continue;
            InputMsg? i;
            try { i = JsonSerializer.Deserialize<InputMsg>(m.AsSpan(1), SignedCommand.Json); } catch (JsonException) { continue; }
            if (i is null) continue;
            Desktop.FollowInput();
            var screen = SystemInformation.VirtualScreen;
            switch (i.T)
            {
                case "end": _running = false; return;
                case "refresh": _fullRefresh = true; break;
                case "move": Mouse(screen, i.X, i.Y, 0x0001); break;
                case "down": Mouse(screen, i.X, i.Y, i.B switch { 2 => 0x0008, 1 => 0x0020, _ => 0x0002 }); break;
                case "up": Mouse(screen, i.X, i.Y, i.B switch { 2 => 0x0010, 1 => 0x0040, _ => 0x0004 }); break;
                case "wheel": Wheel(i.Delta); break;
                case "key": Key(i.Code, i.Ext, i.Up); break;
                case "text": foreach (var ch in i.D.Take(1000)) Unicode(ch); break;
            }
        }
    }

    private static void Mouse(Rectangle screen, int x, int y, uint flags)
    {
        x = Math.Clamp(x, 0, screen.Width - 1);
        y = Math.Clamp(y, 0, screen.Height - 1);
        var inp = new INPUT { type = 0 };
        inp.u.mi = new MOUSEINPUT
        {
            dx = (int)(x * 65535L / Math.Max(1, screen.Width - 1)),
            dy = (int)(y * 65535L / Math.Max(1, screen.Height - 1)),
            dwFlags = flags | 0x0001 | 0x8000 | 0x4000,   // MOVE | ABSOLUTE | VIRTUALDESK
        };
        SendInput(1, new[] { inp }, Marshal.SizeOf<INPUT>());
    }

    private static void Wheel(int delta)
    {
        var inp = new INPUT { type = 0 };
        inp.u.mi = new MOUSEINPUT { mouseData = (uint)Math.Clamp(delta, -1200, 1200), dwFlags = 0x0800 };
        SendInput(1, new[] { inp }, Marshal.SizeOf<INPUT>());
    }

    private static void Key(int scanCode, bool extended, bool up)
    {
        if (scanCode is <= 0 or > 0xFF) return;
        var inp = new INPUT { type = 1 };
        inp.u.ki = new KEYBDINPUT { wScan = (ushort)scanCode, dwFlags = 0x0008 | (extended ? 0x0001u : 0) | (up ? 0x0002u : 0) };   // SCANCODE
        SendInput(1, new[] { inp }, Marshal.SizeOf<INPUT>());
    }

    private static void Unicode(char ch)
    {
        var down = new INPUT { type = 1 };
        down.u.ki = new KEYBDINPUT { wScan = ch, dwFlags = 0x0004 };   // UNICODE
        var upInp = new INPUT { type = 1 };
        upInp.u.ki = new KEYBDINPUT { wScan = ch, dwFlags = 0x0004 | 0x0002 };
        SendInput(2, new[] { down, upInp }, Marshal.SizeOf<INPUT>());
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT { public uint type; public InputUnion u; }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT { public int dx, dy; public uint mouseData, dwFlags, time; public IntPtr dwExtraInfo; }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT { public ushort wVk, wScan; public uint dwFlags, time; public IntPtr dwExtraInfo; }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint count, INPUT[] inputs, int size);

    /// <summary>Keeps a thread on whichever desktop has the screen (normal, sign-in screen or UAC prompt).</summary>
    private static class Desktop
    {
        public static void FollowInput()
        {
            var d = OpenInputDesktop(0, false, 0x10000000);   // GENERIC_ALL
            if (d == IntPtr.Zero) return;
            if (!SetThreadDesktop(d)) CloseDesktop(d);
        }

        [DllImport("user32.dll", SetLastError = true)] private static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
        [DllImport("user32.dll", SetLastError = true)] private static extern bool SetThreadDesktop(IntPtr desktop);
        [DllImport("user32.dll")] private static extern bool CloseDesktop(IntPtr desktop);
    }

    /// <summary>The bar across the top of the screen while Night Tech is connected.</summary>
    private sealed class Banner : Form
    {
        public event Action? Disconnect;

        public Banner(string tech)
        {
            FormBorderStyle = FormBorderStyle.None;
            TopMost = true;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.Manual;
            BackColor = ColorTranslator.FromHtml(BrandInfo.Navy);
            ForeColor = Color.White;
            Font = new Font("Segoe UI", 10f);
            Size = new Size(560, 40);
            var area = Screen.PrimaryScreen?.WorkingArea ?? new Rectangle(0, 0, 1024, 768);
            Location = new Point(area.Left + (area.Width - Width) / 2, area.Top);
            var label = new Label
            {
                Text = $"{tech} from {BrandInfo.Company} is connected and can see this screen.",
                AutoSize = false, TextAlign = ContentAlignment.MiddleLeft, Dock = DockStyle.Fill, Padding = new Padding(12, 0, 0, 0),
            };
            var button = new Button
            {
                Text = "Disconnect", Dock = DockStyle.Right, Width = 110, FlatStyle = FlatStyle.Flat,
                BackColor = ColorTranslator.FromHtml(BrandInfo.Orange), ForeColor = Color.FromArgb(26, 32, 44),
            };
            button.FlatAppearance.BorderSize = 0;
            button.Click += (_, _) => { Disconnect?.Invoke(); Close(); };
            Controls.Add(label);
            Controls.Add(button);
        }

        // Stays on top without taking focus from what the person (or tech) is doing.
        protected override bool ShowWithoutActivation => true;

        protected override CreateParams CreateParams
        {
            get
            {
                var cp = base.CreateParams;
                cp.ExStyle |= 0x00000080 | 0x08000000;   // TOOLWINDOW | NOACTIVATE
                return cp;
            }
        }
    }
}
