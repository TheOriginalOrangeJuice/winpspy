using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Channels;
using Microsoft.Win32.SafeHandles;
using Winpspy.Core;
using ActivityEvent = Winpspy.Core.ActivityEvent;

namespace Winpspy.Collectors;

internal sealed class ProcessEnricher(EventPipeline pipeline) : IAsyncDisposable
{
    private readonly Channel<ProcessIdentity> requests = Channel.CreateBounded<ProcessIdentity>(2048);
    private Task[] workers = [];
    private long unavailable, dropped;
    public void Start() => workers = [Task.Run(Work), Task.Run(Work)];
    public void Request(ProcessIdentity identity)
    {
        if (identity.Pid != Environment.ProcessId && !requests.Writer.TryWrite(identity)) Interlocked.Increment(ref dropped);
    }
    private async Task Work()
    {
        await foreach (var requested in requests.Reader.ReadAllAsync())
        {
            string? image = null, sid = null, user = null;
            string status = "available";
            try
            {
                // Verify and query the same handle; reopening by PID permits a reuse race.
                using var handle = OpenProcess(0x1000, false, requested.Pid);
                if (handle.IsInvalid || !GetProcessTimes(handle,out long creation,out _,out _,out _)) status = "access-denied-or-exited";
                else if (Math.Abs((DateTimeOffset.FromFileTime(creation) - requested.StartedUtc).TotalMilliseconds) > 20) status = "process-exited-or-reused";
                else
                {
                    var path = new System.Text.StringBuilder(32768);
                    int size = path.Capacity;
                    if (handle.IsInvalid) status = "access-denied";
                    else
                    {
                        if (QueryFullProcessImageName(handle, 0, path, ref size)) image = path.ToString();
                        if (OpenProcessToken(handle, 8, out var token))
                        {
                            using (token)
                            using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
                            {
                                sid = identity.User?.Value;
                                try { user = identity.Name; } catch (IdentityNotMappedException) { }
                            }
                        }
                        if (image == null || sid == null) status = "partial";
                    }
                }
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or UnauthorizedAccessException)
            { status = "unavailable-or-exited"; }
            if (status != "available") Interlocked.Increment(ref unavailable);
            pipeline.Publish(new ActivityEvent(DateTimeOffset.UtcNow, Category.Process, "process.enriched", new("winpspy.process-query"),
                new(Process: new(StartedUtc: requested.StartedUtc, Image: image, User: user, UserSid: sid, Enrichment: status)), requested.Pid));
        }
    }
    public Task Snapshot() => Task.Run(() =>
    {
        try
        {
            using var search = new ManagementObjectSearcher("root\\cimv2", "SELECT ProcessId,ParentProcessId,CreationDate,ExecutablePath,CommandLine,SessionId,Name FROM Win32_Process",
                new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(5), ReturnImmediately = false });
            using var results = search.Get();
            var snapshot = new List<(int Pid, ProcessActivity Data)>();
            foreach (ManagementObject row in results)
            {
                using (row)
                {
                    int pid = Convert.ToInt32(row["ProcessId"]);
                    if (row["CreationDate"] is not string created || pid == Environment.ProcessId) continue;
                    DateTimeOffset start = ManagementDateTimeConverter.ToDateTime(created).ToUniversalTime();
                    var data = new ProcessActivity(start, Convert.ToInt32(row["ParentProcessId"]),
                        row["ExecutablePath"] as string ?? row["Name"] as string, row["CommandLine"] as string, Convert.ToInt32(row["SessionId"]));
                    snapshot.Add((pid,data));
                }
            }
            foreach (var entry in snapshot.OrderBy(x => x.Data.StartedUtc))
            {
                pipeline.Publish(new ActivityEvent(DateTimeOffset.UtcNow, Category.Process, "process.snapshot", new("Win32_Process"), new(Process: entry.Data), entry.Pid));
                Request(new(entry.Pid,entry.Data.StartedUtc!.Value));
            }
            pipeline.Report("process-snapshot", "active", "Startup snapshot complete. Live capture was enabled before enumeration.");
        }
        catch (Exception ex) when (ex is ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
        { pipeline.Report("process-snapshot", "degraded", ex.Message); }
    });
    public void Report() => pipeline.Report("enrichment", "active", "Cumulative asynchronous process enrichment counts.",
        new Dictionary<string,long> { ["unavailableOrPartial"] = Interlocked.Read(ref unavailable), ["queueDrops"] = Interlocked.Read(ref dropped) });
    public async ValueTask DisposeAsync()
    {
        requests.Writer.TryComplete();
        try { await Task.WhenAll(workers).WaitAsync(TimeSpan.FromSeconds(5)); }
        catch (TimeoutException) { pipeline.Report("enrichment", "degraded", "Enrichment shutdown deadline exceeded; remaining metadata is unavailable."); }
        Report();
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(SafeProcessHandle process, uint flags, System.Text.StringBuilder name, ref int size);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(SafeProcessHandle process, uint access, out SafeAccessTokenHandle token);
}
