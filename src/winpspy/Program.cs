using System.Diagnostics.Eventing.Reader;
using System.Security.Principal;
using Winpspy.Collectors;
using Winpspy.Core;

namespace Winpspy;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        Options options;
        try { options = Options.Parse(args); }
        catch (ArgumentException ex) { Console.Error.WriteLine(ex.Message + " Use --help for usage."); return 2; }
        if (options.Help) { Console.WriteLine(Options.Usage); return 0; }
        if (!OperatingSystem.IsWindows()) { Console.Error.WriteLine("winpspy requires Windows."); return 2; }
        if (options.Check) return Check(options);
        if (!IsElevated()) { Console.Error.WriteLine("Monitoring requires an elevated terminal. Open PowerShell or Windows Terminal as administrator, then run winpspy again. Use --check to inspect capabilities."); return 3; }
        if (options.Paths.Count == 0)
            options.Paths.AddRange(DriveInfo.GetDrives().Where(x => x.DriveType == DriveType.Fixed && x.IsReady).Select(x => x.RootDirectory.FullName));
        if (options.Paths.Count == 0 && options.Events.Contains(Category.File)) { Console.Error.WriteLine("No local fixed drives found. Supply --path."); return 2; }
        foreach (string path in options.Paths)
            if (!Directory.Exists(path)) { Console.Error.WriteLine("Collection directory does not exist or is inaccessible: " + path); return 2; }
        Console.Error.WriteLine("winpspy 2.0 | activity colors, no threat classification | Ctrl+C to stop");
        Console.Error.WriteLine("File roots: " + string.Join(", ", options.Paths.Select(TimelineFormatter.Escape)));
        Console.Error.WriteLine("Collection: " + string.Join(", ", options.Events) + ". Other filters affect console only.");
        using var stop = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; stop.Cancel(); };
        Console.CancelKeyPress += handler;
        EventPipeline? pipeline = null;
        EtwCollector? etw = null;
        ProcessEnricher? enricher = null;
        EventLogs? logs = null;
        PipeCollector? pipes = null;
        Task? snapshot = null;
        int result = 0;
        try
        {
            pipeline = new(options, e => WriteConsole(e, options));
            enricher = new(pipeline); enricher.Start();
            etw = new(options,pipeline,enricher); etw.Start();
            logs = new(options,pipeline); logs.Start();
            if (options.Events.Contains(Category.Pipe)) { pipes = new(pipeline); pipes.Start(); }
            snapshot = enricher.Snapshot();
            pipeline.Report("session","ready","Live collectors started. Startup snapshot and enrichment run concurrently.");
            if (options.Duration is { } duration) stop.CancelAfter(duration);
            while (!stop.IsCancellationRequested)
            {
                var delay = Task.Delay(5000, stop.Token);
                var finished = await Task.WhenAny(delay, pipeline.Failure, etw.Failure);
                if (finished == pipeline.Failure || finished == etw.Failure) { result = 1; break; }
                if (!stop.IsCancellationRequested) { etw.ReportLosses(); enricher.Report(); }
            }
        }
        catch (Exception ex) { Console.Error.WriteLine("Collection failed: " + TimelineFormatter.Escape(ex.Message)); result = 1; }
        finally
        {
            // Stop producers, finish pending metadata, then drain correlation and evidence queues.
            logs?.Dispose();
            if (pipes != null) await pipes.DisposeAsync();
            if (etw != null) await etw.DisposeAsync();
            if (snapshot != null)
            {
                try { await snapshot.WaitAsync(TimeSpan.FromSeconds(6)); }
                catch (TimeoutException) { pipeline?.Report("process-snapshot","degraded","Snapshot deadline exceeded; baseline may be incomplete."); }
            }
            if (enricher != null) await enricher.DisposeAsync();
            if (pipeline != null)
            {
                await pipeline.DisposeAsync();
                if (pipeline.Error is { } error) { Console.Error.WriteLine("Output failed: " + TimelineFormatter.Escape(error.Message)); result = 1; }
            }
            Console.CancelKeyPress -= handler;
        }
        return result;
    }
    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
    private static int Check(Options options)
    {
        Console.WriteLine($"winpspy 2.0 | {Environment.OSVersion} | {System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}");
        Console.WriteLine("Elevation: " + (IsElevated() ? "administrator" : "not elevated; monitoring requires administrator"));
        foreach (string name in new[] { "Microsoft-Windows-Kernel-Process", "Microsoft-Windows-Kernel-File", "Microsoft-Windows-Kernel-Registry", "Microsoft-Windows-DNS-Client" })
        {
            try { using var provider = new ProviderMetadata(name); Console.WriteLine($"Provider: {name} registered"); }
            catch (EventLogException ex) { Console.WriteLine($"Provider: {name} unavailable ({TimelineFormatter.Escape(ex.Message)})"); }
        }
        foreach (var channel in EventLogs.Channels(options))
        {
            try
            {
                using var configuration = new EventLogConfiguration(channel.Name);
                Console.WriteLine($"Log: {channel.Name} {(configuration.IsEnabled ? "enabled" : "disabled")}");
            }
            catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException) { Console.WriteLine($"Log: {channel.Name} unavailable ({TimelineFormatter.Escape(ex.Message)})"); }
        }
        foreach (var policy in EventLogs.PowerShellPolicy()) Console.WriteLine(policy.Name + ": " + policy.Message);
        Console.WriteLine("Security event coverage depends on existing audit policy. ETW session availability is verified when capture starts.");
        Console.WriteLine("No collection started and no logging settings were changed.");
        return 0;
    }
    private static void WriteConsole(ActivityEvent e, Options options)
    {
        bool color = !options.NoColor && !Console.IsOutputRedirected;
        foreach (var line in TimelineFormatter.Lines(e))
        {
            if (color) Console.ForegroundColor = line.Color;
            try { Console.WriteLine(line.Text); }
            finally { if (color) Console.ResetColor(); }
        }
    }
}
