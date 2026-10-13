using Winpspy.Core;

namespace Winpspy.Collectors;

internal sealed class PipeCollector(EventPipeline pipeline) : IAsyncDisposable
{
    private readonly CancellationTokenSource stop = new();
    private Task? worker;
    public void Start() => worker = Task.Run(async () =>
    {
        var previous = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool initial = true, failed = false;
        while (!stop.IsCancellationRequested)
        {
            try
            {
                var current = Directory.EnumerateFiles(@"\\.\pipe\").Take(16384).ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (string name in current.Except(previous)) Emit(initial ? "snapshot" : "observed", name);
                foreach (string name in previous.Except(current)) Emit("disappeared", name);
                if (current.Count == 16384) pipeline.Report("pipes","degraded","Pipe sample limit reached; listing is incomplete.");
                if (initial || failed) pipeline.Report("pipes","active","One-second sampled pipe-name listing; short-lived pipes may be missed.");
                previous = current; initial = false; failed = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (!failed) pipeline.Report("pipes","unavailable",ex.Message);
                failed = true;
            }
            try { await Task.Delay(1000,stop.Token); } catch (OperationCanceledException) { break; }
        }
    });
    private void Emit(string kind, string name) => pipeline.Publish(new ActivityEvent(DateTimeOffset.UtcNow,
        Category.Pipe,"pipe."+kind,new("winpspy.pipe-sample"),new(Pipe:name)));
    public async ValueTask DisposeAsync()
    {
        await stop.CancelAsync();
        if (worker != null) await worker;
        stop.Dispose();
    }
}
