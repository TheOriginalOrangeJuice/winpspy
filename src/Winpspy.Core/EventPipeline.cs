using System.Threading.Channels;

namespace Winpspy.Core;

public sealed class EventPipeline : IAsyncDisposable
{
    private readonly Options options;
    private readonly int ownPid;
    private readonly Channel<CaptureItem> input;
    private readonly Channel<ActivityEvent> console;
    private readonly ProcessCatalog processes = new();
    private readonly ThreadCatalog threads = new();
    private readonly FileCorrelator files = new();
    private readonly EventLogDecoder logs = new();
    private readonly ConsoleFilter filter;
    private readonly ConsolePresentation presentation;
    private readonly EvidenceWriter? evidence;
    private readonly Task consumer;
    private readonly Task consoleConsumer;
    private readonly TaskCompletionSource failure = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Guid sessionId = Guid.NewGuid();
    private readonly Dictionary<string, long> kinds = [];
    private long accepted, inputDrops, consoleDrops, exported, filtered, excluded, decodeErrors;
    private long id;
    private bool completed;
    public Guid SessionId => sessionId;
    public Task Failure => failure.Task;
    public Exception? Error { get; private set; }

    public EventPipeline(Options options, Action<ActivityEvent> consoleWrite, int? ownPid = null, int capacity = 65536)
    {
        this.options = options; this.ownPid = ownPid ?? Environment.ProcessId;
        filter = new(options);
        if (options.Output != null) evidence = new(options.Output, options.Format);
        input = Channel.CreateBounded<CaptureItem>(new BoundedChannelOptions(capacity) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
        console = Channel.CreateBounded<ActivityEvent>(new BoundedChannelOptions(8192) { SingleReader = true, SingleWriter = true, FullMode = BoundedChannelFullMode.Wait });
        presentation = new(options, consoleWrite);
        consoleConsumer = Task.Run(ConsoleLoop);
        consumer = Task.Run(Consume);
    }
    public bool Publish(ActivityEvent e) => Publish(new CaptureItem(e.TimestampUtc, Event: e));
    public bool Publish(CaptureItem item)
    {
        if (input.Writer.TryWrite(item)) { Interlocked.Increment(ref accepted); return true; }
        Interlocked.Increment(ref inputDrops); return false;
    }
    public void Report(string collector, string state, string message, IReadOnlyDictionary<string,long>? counts = null) => Publish(ActivityEvent.Health(collector,state,message,counts));
    private async Task ConsoleLoop()
    {
        try
        {
            while (!console.Reader.Completion.IsCompleted)
            {
                int batch = 0;
                while (batch++ < 4096 && console.Reader.TryRead(out var e)) presentation.Accept(e, DateTimeOffset.UtcNow);
                presentation.Tick(DateTimeOffset.UtcNow);
                if (batch == 1) await Task.Delay(50);
            }
            while (console.Reader.TryRead(out var e)) presentation.Accept(e, DateTimeOffset.UtcNow);
            presentation.Tick(DateTimeOffset.UtcNow, true);
        }
        catch (Exception ex) { Fail(ex); }
    }
    private async Task Consume()
    {
        var reorder = new PriorityQueue<CaptureItem, long>();
        var healthAt = DateTimeOffset.UtcNow.AddSeconds(5);
        var flushAt = DateTimeOffset.UtcNow.AddSeconds(1);
        try
        {
            Emit(ActivityEvent.Health("session", "active", $"Session {sessionId}; evidence={(options.Output ?? "disabled")}. Console filters never remove evidence records."));
            while (!input.Reader.Completion.IsCompleted)
            {
                int batch = 0;
                while (batch++ < 8192 && input.Reader.TryRead(out var item)) reorder.Enqueue(item, item.TimestampUtc.UtcTicks);
                var now = DateTimeOffset.UtcNow;
                while (reorder.TryPeek(out _, out long tick) && (tick <= now.AddMilliseconds(-250).UtcTicks || reorder.Count >= 32768))
                    Handle(reorder.Dequeue());
                if (now >= flushAt)
                {
                    foreach (var e in files.Flush(now)) EmitAttributed(e);
                    foreach (var e in logs.Flush(now)) EmitAttributed(e);
                    processes.Prune(now); threads.Prune(now);
                    evidence?.Flush(); flushAt = now.AddSeconds(1);
                }
                if (now >= healthAt) { EmitHealth(); healthAt = now.AddSeconds(5); }
                if (batch == 1) await Task.Delay(25);
                if (Error != null) break;
            }
            while (input.Reader.TryRead(out var item)) reorder.Enqueue(item, item.TimestampUtc.UtcTicks);
            while (reorder.TryDequeue(out var item, out _)) Handle(item);
            foreach (var e in files.Flush(DateTimeOffset.UtcNow, true)) EmitAttributed(e);
            foreach (var e in logs.Flush(DateTimeOffset.UtcNow, true)) EmitAttributed(e);
            EmitHealth();
            Emit(ActivityEvent.Health("session", "stopped", "Capture stopped; individual event counts by kind.", new Dictionary<string,long>(kinds)));
            evidence?.Flush();
        }
        catch (Exception ex) { Fail(ex); }
        finally { console.Writer.TryComplete(); }
    }
    private void Handle(CaptureItem item)
    {
        if (item.Thread is { } thread) { threads.Apply(thread); return; }
        if (item.File is { } file) { foreach (var e in files.Accept(file)) EmitAttributed(e); return; }
        if (item.LogXml != null)
        {
            try { foreach (var e in logs.Decode(item.LogXml)) EmitAttributed(e); }
            catch (Exception ex) when (ex is System.Xml.XmlException or FormatException or OverflowException or ArgumentException)
            {
                decodeErrors++;
                if (decodeErrors == 1) Emit(ActivityEvent.Health("event-log", "degraded", "Event decoding failed: " + ex.Message));
            }
            return;
        }
        if (item.Event is not { } activity) return;
        if (activity.Category == Category.Process && activity.Pid is int pid && activity.Details.Process is { } data)
        {
            ProcessIdentity? identity;
            switch (activity.Kind)
            {
                case "process.start": case "process.snapshot":
                    var result = processes.Start(pid, data, activity.TimestampUtc, activity.Kind == "process.snapshot");
                    if (!result.Added) return;
                    identity = result.Identity;
                    break;
                case "process.stop": identity = processes.Stop(pid, activity.TimestampUtc); break;
                case "process.enriched": identity = processes.Enrich(pid, data); break;
                default: identity = processes.Resolve(pid, activity.TimestampUtc); break;
            }
            if (identity != null) filter.Observe(identity);
            Emit(activity with { Process = identity, Attribution = identity == null ? "pid-only" : "process-instance" });
        }
        else EmitAttributed(activity);
    }
    private void EmitAttributed(ActivityEvent e)
    {
        int? pid = e.Pid;
        if (pid is null or < 0 && e.Tid is int tid) pid = threads.Resolve(tid, e.TimestampUtc);
        var process = pid is int p ? processes.Resolve(p, e.TimestampUtc) : null;
        Emit(e with { Pid = pid, Process = process, Attribution = process != null ? "process-instance" : pid != null ? "pid-only" : "unavailable" });
    }
    private void Emit(ActivityEvent e)
    {
        if (e.Pid == ownPid || (e.Details.File?.Path is string outputPath && evidence?.IsCapturePath(outputPath) == true)) { excluded++; return; }
        if (e.Internal || !options.Events.Contains(e.Category)) return;
        if (!options.Verbose && (e.Kind is "file.read" or "registry.open" or "registry.query" or "registry.queryValue" ||
            e.Kind == "file.open" && e.Details.File?.Result == "success")) return;
        if (e.Details.File is { } file && options.Paths.Count > 0)
        {
            bool matches = options.Paths.Any(root => (file.Path != null && WindowsPaths.IsWithin(file.Path, root, options.Recursive)) ||
                (file.OldPath != null && WindowsPaths.IsWithin(file.OldPath, root, options.Recursive)));
            if (!matches && (file.Path != null || options.ExplicitPaths)) { excluded++; return; }
        }
        e = e with { SessionId = sessionId, EventId = ++id };
        kinds[e.Kind] = kinds.GetValueOrDefault(e.Kind) + 1;
        evidence?.Write(e);
        if (evidence != null) exported++;
        if (!filter.Matches(e)) { filtered++; return; }
        if (!console.Writer.TryWrite(e)) Interlocked.Increment(ref consoleDrops);
    }
    private void EmitHealth()
    {
        var counts = new Dictionary<string,long>
        {
            ["acceptedInputs"] = Interlocked.Read(ref accepted), ["applicationQueueDrops"] = Interlocked.Read(ref inputDrops),
            ["consoleQueueDrops"] = Interlocked.Read(ref consoleDrops), ["exportedEvents"] = exported,
            ["consoleFiltered"] = filtered, ["scopeOrSelfExcluded"] = excluded, ["decodeErrors"] = decodeErrors,
            ["processCacheEvictions"] = processes.Evictions, ["threadCacheEvictions"] = threads.Evictions,
            ["fileCacheEvictions"] = files.Evictions
        };
        bool degraded = counts["applicationQueueDrops"] + counts["consoleQueueDrops"] + decodeErrors + processes.Evictions + threads.Evictions + files.Evictions > 0;
        Emit(ActivityEvent.Health("pipeline", degraded ? "degraded" : "active", "Cumulative collection health; ETW losses are reported separately.", counts));
    }
    private void Fail(Exception ex) { Error ??= ex; failure.TrySetResult(); }
    public async ValueTask DisposeAsync()
    {
        if (completed) return;
        completed = true;
        input.Writer.TryComplete();
        await consumer;
        await consoleConsumer;
        try { evidence?.Dispose(); } catch (Exception ex) { Fail(ex); }
    }
}
