using System.Diagnostics.Eventing.Reader;
using Microsoft.Win32;
using Winpspy.Core;

namespace Winpspy.Collectors;

internal sealed class EventLogs(Options options, EventPipeline pipeline) : IDisposable
{
    private readonly List<EventLogWatcher> watchers = [];
    internal static IEnumerable<(string Name, string Query)> Channels(Options o)
    {
        if (o.Events.Contains(Category.PowerShell))
        {
            yield return ("Microsoft-Windows-PowerShell/Operational", "*[System[(EventID=4104)]]");
            yield return ("PowerShellCore/Operational", "*[System[(EventID=4104)]]");
        }
        if (o.Events.Contains(Category.Task))
            yield return ("Microsoft-Windows-TaskScheduler/Operational", "*[System[(EventID=100 or EventID=101 or EventID=102 or EventID=106 or EventID=129 or EventID=140 or EventID=141 or EventID=142 or EventID=200 or EventID=201 or EventID=203)]]");
        if (o.Events.Contains(Category.Service))
            yield return ("System", "*[System[Provider[@Name='Service Control Manager'] and (EventID=7031 or EventID=7034 or EventID=7036 or EventID=7040 or EventID=7045)]]");
        var security = new List<int>();
        if (o.Events.Contains(Category.Task)) security.AddRange([4698,4699,4700,4701,4702]);
        if (o.Events.Contains(Category.Service)) security.Add(4697);
        if (security.Count > 0)
            yield return ("Security", "*[System[" + string.Join(" or ", security.Select(x => "EventID=" + x)) + "]]");
    }
    public void Start()
    {
        foreach (var channel in Channels(options))
        {
            EventLogWatcher? watcher = null;
            try
            {
                using var configuration = new EventLogConfiguration(channel.Name);
                if (!configuration.IsEnabled) { pipeline.Report(channel.Name,"unavailable","Log is disabled. No settings were changed."); continue; }
                watcher = new(new EventLogQuery(channel.Name, PathType.LogName, channel.Query), null, readExistingEvents: false);
                string name = channel.Name;
                watcher.EventRecordWritten += (_, args) =>
                {
                    if (args.EventException != null) { pipeline.Report(name,"degraded",args.EventException.Message); return; }
                    using var record = args.EventRecord;
                    if (record == null) return;
                    try
                    {
                        pipeline.Publish(new CaptureItem(record.TimeCreated?.ToUniversalTime() ?? DateTimeOffset.UtcNow, LogXml: record.ToXml()));
                    }
                    catch (EventLogException ex) { pipeline.Report(name,"degraded",ex.Message); }
                };
                watcher.Enabled = true;
                watchers.Add(watcher);
                pipeline.Report(name,"active","Subscribed to future events; coverage depends on existing logging/audit configuration.");
            }
            catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                watcher?.Dispose(); pipeline.Report(channel.Name,"unavailable",ex.Message);
            }
        }
        if (options.Events.Contains(Category.PowerShell))
        {
            foreach (var status in PowerShellPolicy()) pipeline.Report(status.Name, status.Enabled ? "active" : "degraded", status.Message);
        }
    }
    internal static IEnumerable<(string Name, bool Enabled, string Message)> PowerShellPolicy()
    {
        foreach (var engine in new[] { ("Windows PowerShell", "Windows\\PowerShell"), ("PowerShell Core", "PowerShellCore") })
        {
            string path = $"SOFTWARE\\Policies\\Microsoft\\{engine.Item2}\\ScriptBlockLogging";
            object? machine = Registry.GetValue("HKEY_LOCAL_MACHINE\\" + path,"EnableScriptBlockLogging",null);
            object? user = Registry.GetValue("HKEY_CURRENT_USER\\" + path,"EnableScriptBlockLogging",null);
            bool enabled = machine is int m ? m == 1 : user is int u && u == 1;
            yield return (engine.Item1, enabled, enabled
                ? "Script-block logging policy detected. Other users/sessions and protected logging may have different coverage."
                : "Script-block logging policy not detected for this machine/current user. Coverage is not guaranteed; per-user or PowerShell configuration may differ. No settings were changed.");
        }
    }
    public void Dispose()
    {
        foreach (var watcher in watchers) watcher.Dispose();
        watchers.Clear();
    }
}
