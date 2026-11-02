using System.Windows;
using System.Windows.Threading;
using NightTech.Business.Core;
using NightTech.Business.Core.Logging;

namespace NightTech.SecurityCheckup;

public partial class App : Application
{
    /// <summary>Run from the Night Tech USB kit (a "portable.txt" next to the program): reports and logs stay on the stick.</summary>
    public static bool Portable { get; } = File.Exists(Path.Combine(AppContext.BaseDirectory, "portable.txt"));

    public static string ReportsFolder { get; } = Portable
        ? Path.Combine(AppContext.BaseDirectory, "Reports")
        : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Night Tech Security Checkup", "Reports");

    public static AppLog Log { get; } = new("Security Checkup", Portable ? Path.Combine(AppContext.BaseDirectory, "Logs") : null);

    public static string ToolVersion { get; } =
        typeof(App).Assembly.GetName().Version is { } v ? $"{v.Major}.{v.Minor}.{v.Build}" : "0.0.0";

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnUnhandled;
        Log.Info($"{Brand.Company} Security Checkup {ToolVersion} started on {Environment.MachineName}" + (Portable ? " (portable)." : "."));
        base.OnStartup(e);
    }

    private void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        Log.Error("Unexpected error.", e.Exception);
        MessageBox.Show("Something unexpected went wrong:\n\n" + e.Exception.Message + "\n\nDetails are in the log folder:\n" + Log.Folder,
            "Night Tech Security Checkup", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
