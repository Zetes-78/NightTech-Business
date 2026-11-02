using System.Text;

namespace NightTech.Business.Core.Logging;

/// <summary>
/// Simple thread-safe daily log file: %LOCALAPPDATA%\Night Tech\&lt;tool&gt;\logs\yyyy-MM-dd.log.
/// Logging never throws; a tool must keep working even if the log can't be written.
/// </summary>
public sealed class AppLog
{
    private readonly object _gate = new();
    private readonly string _folder;

    public AppLog(string toolName, string? folderOverride = null)
    {
        _folder = folderOverride ?? Path.Combine(Brand.AppDataFolder(toolName), "logs");
        try { Directory.CreateDirectory(_folder); } catch { /* ignore */ }
    }

    public string Folder => _folder;

    public event Action<string>? LineWritten;

    public void Info(string message) => Write("INFO", message);
    public void Warn(string message) => Write("WARN", message);
    public void Error(string message, Exception? ex = null) =>
        Write("ERROR", ex is null ? message : message + " | " + ex.GetType().Name + ": " + ex.Message);

    private void Write(string level, string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {message}";
        lock (_gate)
        {
            try
            {
                File.AppendAllText(Path.Combine(_folder, DateTime.Now.ToString("yyyy-MM-dd") + ".log"),
                    line + Environment.NewLine, Encoding.UTF8);
            }
            catch { /* never fail because of logging */ }
        }
        try { LineWritten?.Invoke(line); } catch { /* ignore listener errors */ }
    }
}
