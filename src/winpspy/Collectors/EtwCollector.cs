using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Winpspy.Core;

namespace Winpspy.Collectors;

internal sealed class EtwCollector(Options options, EventPipeline pipeline, ProcessEnricher enricher) : IAsyncDisposable
{
    internal static readonly Guid FileProvider = new("edd08927-9cc4-4e65-b970-c2560fb5c289");
    internal static readonly Guid DnsProvider = new("1c95126e-7eea-49a9-a3fe-a378b03ddb4d");
    internal static readonly Guid RegistryProvider = new("70eb4f03-c1de-4f73-a051-33d13d5413bd");
    private readonly DevicePaths paths = new();
    private readonly List<(TraceEventSession Session, Task Pump, string Name)> sessions = [];
    private readonly TaskCompletionSource fatal = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int stopping;
    private long decodeErrors;
    private readonly RegistryCorrelator registryNames = new();
    public Task Failure => fatal.Task;
    private static DateTimeOffset Time(TraceEvent e) => e.TimeStamp.ToUniversalTime();
    private static EventSource Source(TraceEvent e) => new(e.ProviderName, (int)e.ID, e.Version, Opcode:(int)e.Opcode);
    private TraceEventSession Create(string name) => new($"winpspy-{Environment.ProcessId}-{Guid.NewGuid():N}-{name}", TraceEventSessionOptions.Create | TraceEventSessionOptions.NoRestartOnCreate)
        { StopOnDispose = true, BufferSizeMB = 32 };

    public void Start()
    {
        var kernel = Create("kernel");
        try
        {
            var flags = KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread;
            if (options.Events.Contains(Category.Network)) flags |= KernelTraceEventParser.Keywords.NetworkTCPIP;
            try { kernel.EnableKernelProvider(flags); }
            catch when ((flags & KernelTraceEventParser.Keywords.NetworkTCPIP) != 0)
            {
                kernel.Dispose(); kernel = Create("kernel");
                kernel.EnableKernelProvider(KernelTraceEventParser.Keywords.Process | KernelTraceEventParser.Keywords.Thread);
                pipeline.Report("network", "unavailable", "Optional kernel network flags could not be enabled; process collection remains active.");
            }
            var parser = kernel.Source.Kernel;
            parser.ProcessStart += e => Guard(() => Process(e, false));
            parser.ProcessStop += e => Guard(() => Process(e, true));
            parser.ThreadStart += e => Thread(e, true, false);
            parser.ThreadStop += e => Thread(e, false, false);
            parser.ThreadDCStart += e => Thread(e, true, true);
            RegisterNetwork(parser);
            Pump(kernel, "kernel", true);
        }
        catch { kernel.Dispose(); throw; }

        if (options.Events.Contains(Category.File))
        {
            var file = Create("file");
            try
            {
                file.Source.Dynamic.All += e => { if (e.ProviderGuid == FileProvider) Guard(() => File(e)); };
                // CreateNewFile (0x1000) duplicates successful Create completion records.
                // The completion's disposition distinguishes created, opened, and overwritten.
                ulong keywords = 0x10 | 0x20 | 0x40 | 0x80 | 0x200 | 0x400 | 0x800;
                if (options.Verbose) keywords |= 0x100;
                file.EnableProvider(FileProvider, TraceEventLevel.Verbose, keywords);
                Pump(file, "file", true);
            }
            catch { file.Dispose(); throw; }
        }
        if (options.Events.Contains(Category.Dns))
        {
            var dns = Create("dns");
            try
            {
                dns.Source.Dynamic.All += e => { if (e.ProviderGuid == DnsProvider && (int)e.ID == 3008) Guard(() => Dns(e)); };
                dns.EnableProvider(DnsProvider, TraceEventLevel.Verbose);
                Pump(dns, "dns", false);
            }
            catch (Exception ex) { dns.Dispose(); pipeline.Report("dns", "unavailable", ex.Message); }
        }
        if (options.Events.Contains(Category.Registry))
        {
            var registry = Create("registry");
            try
            {
                registry.Source.Dynamic.All += e => { if (e.ProviderGuid == RegistryProvider) Guard(() => Registry(e)); };
                // Opens/closes maintain object names even when they are not displayed.
                ulong keywords = 1 | 4 | 64 | 256 | 512 | 4096 | 8192 | 16384;
                if (options.Verbose) keywords |= 32768 | 1024;
                registry.EnableProvider(RegistryProvider, TraceEventLevel.Verbose, keywords);
                Pump(registry,"registry",false);
            }
            catch (Exception ex) { registry.Dispose(); pipeline.Report("registry","unavailable",ex.Message); }
        }
    }
    private void Pump(TraceEventSession session, string name, bool core)
    {
        var pump = Task.Factory.StartNew(() =>
        {
            try { session.Source.Process(); }
            catch (Exception ex)
            {
                if (Volatile.Read(ref stopping) == 0) pipeline.Report(name, "failed", ex.Message);
            }
            finally
            {
                if (Volatile.Read(ref stopping) == 0)
                {
                    pipeline.Report(name, "failed", "ETW consumer ended unexpectedly.");
                    if (core) fatal.TrySetResult();
                }
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        sessions.Add((session, pump, name));
        pipeline.Report(name, "active", $"ETW session {session.SessionName}");
    }
    private void Guard(Action action)
    {
        try { action(); }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IndexOutOfRangeException or OverflowException)
        {
            if (Interlocked.Increment(ref decodeErrors) == 1) pipeline.Report("etw-decoder", "degraded", "Unsupported or malformed event payload: " + ex.Message);
        }
    }
    private void Process(ProcessTraceData e, bool stop)
    {
        DateTimeOffset at = Time(e);
        int pid = e.ProcessID;
        var data = new ProcessActivity(stop ? null : at, e.ParentID, paths.Resolve(e.ImageFileName),
            e.CommandLine, e.SessionID, stop ? e.ExitStatus : null);
        pipeline.Publish(new ActivityEvent(at, Category.Process, stop ? "process.stop" : "process.start", Source(e), new(Process: data), pid));
        if (!stop) enricher.Request(new(pid, at));
    }
    private void Thread(ThreadTraceData e, bool start, bool snapshot) =>
        pipeline.Publish(new CaptureItem(Time(e), Thread: new(Time(e), e.ThreadID, e.ProcessID, start, snapshot)));
    private static object? Payload(TraceEvent e, string key) => e.PayloadNames.Contains(key) ? e.PayloadByName(key) : null;
    private static ulong U64(TraceEvent e, string key) => Payload(e,key) switch
    {
        int value => unchecked((uint)value), long value => unchecked((ulong)value),
        null => 0, object value => Convert.ToUInt64(value)
    };
    private static string? Text(TraceEvent e, string key) => Payload(e,key)?.ToString();
    private void File(TraceEvent e)
    {
        int id = (int)e.ID;
        if (id is not (10 or 11 or 12 or 14 or 15 or 16 or 17 or 18 or 19 or 24 or 26 or 27 or 28 or 29 or 30 or 31 or 33)) return;
        if (e.Version > 1) { Interlocked.Increment(ref decodeErrors); return; }
        ulong thread = U64(e, "IssuingThreadId");
        if (thread == 0) thread = U64(e, "ThreadId");
        // File events are often logged on a worker thread. Never use the header PID as the actor.
        var file = new NativeFileEvent(Time(e), id, Source(e), U64(e,"Irp"), U64(e,"FileObject"), U64(e,"FileKey"),
            thread > 0 && thread <= int.MaxValue ? (int)thread : null,
            paths.Resolve(Text(e,"FileName") ?? Text(e,"FilePath")),
            id == 24 && Payload(e,"Status") != null ? unchecked((uint)U64(e,"Status")) : null,
            U64(e,"ExtraInformation"), Payload(e,"IOSize") != null ? (long)U64(e,"IOSize") : null,
            Payload(e,"ByteOffset") != null ? unchecked((long)U64(e,"ByteOffset")) : null,
            CreateDisposition: Payload(e,"CreateOptions") != null ? (int)((U64(e,"CreateOptions") >> 24) & 0xff) : null);
        pipeline.Publish(new CaptureItem(file.TimestampUtc, File: file));
    }
    private void Dns(TraceEvent e)
    {
        pipeline.Publish(new ActivityEvent(Time(e), Category.Dns, "dns.query", Source(e),
            new(Network: new(Query: Text(e,"QueryName"), Answers: Text(e,"QueryResults"), Status: Payload(e,"QueryStatus") == null ? null : (uint)U64(e,"QueryStatus"))), e.ProcessID >= 0 ? e.ProcessID : null));
    }
    private void Registry(TraceEvent e)
    {
        if (e.Version != 0) { Interlocked.Increment(ref decodeErrors); return; }
        int id = (int)e.ID;
        uint? status = Payload(e,"Status") == null ? null : (uint)U64(e,"Status");
        var details = registryNames.Resolve(new(id,U64(e,"KeyObject"),U64(e,"BaseObject"),
            Text(e,"BaseName"),Text(e,"RelativeName"),Text(e,"KeyName"),Text(e,"ValueName"),status));
        if (e.ProcessID == Environment.ProcessId) return;
        string? operation = id switch
        {
            1 when U64(e,"Disposition") == 2 && U64(e,"Status") == 0 => "open",
            1 => "create", 2 => "open", 3 => "delete", 4 => "query", 5 => "setValue",
            6 => "deleteValue", 7 => "queryValue", 11 => "setInformation", 15 => "security", _ => null
        };
        if (operation == null || (!options.Verbose && operation is "open" or "query" or "queryValue")) return;
        pipeline.Publish(new ActivityEvent(Time(e), Category.Registry, "registry." + operation, Source(e),
            new(Registry: details), e.ProcessID >= 0 ? e.ProcessID : null, e.ThreadID));
    }
    private void RegisterNetwork(KernelTraceEventParser p)
    {
        if (!options.Events.Contains(Category.Network)) return;
        p.TcpIpConnect += e => Network(e,"connect","TCP",false);
        p.TcpIpAccept += e => Network(e,"accept","TCP",true);
        p.TcpIpDisconnect += e => Network(e,"disconnect","TCP",false);
        p.TcpIpReconnect += e => Network(e,"reconnect","TCP",false);
        p.TcpIpConnectIPV6 += e => Network(e,"connect","TCP",false);
        p.TcpIpAcceptIPV6 += e => Network(e,"accept","TCP",true);
        p.TcpIpDisconnectIPV6 += e => Network(e,"disconnect","TCP",false);
        p.TcpIpReconnectIPV6 += e => Network(e,"reconnect","TCP",false);
        p.UdpIpSend += e => Network(e,"send","UDP",false);
        p.UdpIpRecv += e => Network(e,"receive","UDP",true);
        p.UdpIpSendIPV6 += e => Network(e,"send","UDP",false);
        p.UdpIpRecvIPV6 += e => Network(e,"receive","UDP",true);
    }
    private void Network(TraceEvent e, string operation, string protocol, bool inbound) => Guard(() =>
    {
        // TraceEvent omits IPv6 addresses from PayloadNames for these two templates.
        string? src = e switch { TcpIpV6ConnectTraceData v6 => v6.saddr.ToString(), UpdIpV6TraceData udp6 => udp6.saddr.ToString(), _ => Text(e,"saddr") };
        string? dst = e switch { TcpIpV6ConnectTraceData v6 => v6.daddr.ToString(), UpdIpV6TraceData udp6 => udp6.daddr.ToString(), _ => Text(e,"daddr") };
        int sport = (int)U64(e,"sport"), dport = (int)U64(e,"dport");
        // TCP lifecycle source means the local endpoint even on Accept. UDP receive
        // records use packet direction, so their destination is the local endpoint.
        bool swap = protocol == "UDP" && inbound;
        pipeline.Publish(new ActivityEvent(Time(e), Category.Network, "network." + operation, Source(e),
            new(Network: new(protocol, swap ? dst : src, swap ? dport : sport, swap ? src : dst, swap ? sport : dport,
                protocol == "UDP" ? (long)U64(e,"size") : null, operation == "disconnect" ? "unknown" : inbound ? "inbound" : "outbound")), e.ProcessID >= 0 ? e.ProcessID : null));
    });
    public void ReportLosses()
    {
        foreach (var entry in sessions)
        {
            try
            {
                int lost = entry.Session.EventsLost;
                pipeline.Report(entry.Name, lost > 0 || decodeErrors > 0 || registryNames.Evictions > 0 ? "degraded" : "active", "Cumulative ETW losses and decoder counters.", new Dictionary<string,long> { ["etwLost"] = lost, ["decodeErrors"] = Interlocked.Read(ref decodeErrors), ["registryCacheEvictions"] = registryNames.Evictions });
            }
            catch (Exception ex) { pipeline.Report(entry.Name,"degraded","Unable to query ETW statistics: " + ex.Message); }
        }
    }
    public async ValueTask DisposeAsync()
    {
        Interlocked.Exchange(ref stopping, 1);
        ReportLosses();
        foreach (var entry in sessions)
        {
            try { entry.Session.Flush(); entry.Session.Dispose(); }
            catch (Exception ex) { pipeline.Report(entry.Name,"degraded","Session cleanup: " + ex.Message); }
        }
        try { await Task.WhenAll(sessions.Select(x => x.Pump)).WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (TimeoutException) { pipeline.Report("etw","degraded","ETW shutdown timed out; final buffers may be incomplete."); }
    }
}
