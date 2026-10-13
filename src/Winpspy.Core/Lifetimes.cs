namespace Winpspy.Core;

/// <summary>Timestamp-based lookup; never attach a recycled PID to an older event.</summary>
public sealed class ProcessCatalog(int capacity = 32768)
{
    private sealed class Entry(ProcessIdentity identity, bool snapshot)
    {
        public ProcessIdentity Identity = identity;
        public DateTimeOffset? End;
        public bool Snapshot = snapshot;
    }
    private readonly Dictionary<int, List<Entry>> entries = [];
    private int count;
    public long Evictions { get; private set; }
    public ProcessIdentity? Resolve(int pid, DateTimeOffset at)
    {
        var entry = Find(pid, at);
        if (entry == null) return null;
        // A live child can arrive before its parent's startup snapshot.
        if (entry.Identity.ParentInstanceId == null && entry.Identity.ParentPid is int parentPid && parentPid != pid)
        {
            var parent = Find(parentPid, entry.Identity.StartedUtc);
            if (parent != null) entry.Identity = entry.Identity with { ParentInstanceId = parent.Identity.InstanceId };
        }
        return entry.Identity;
    }
    private Entry? Find(int pid, DateTimeOffset at) => entries.TryGetValue(pid, out var list)
        ? list.LastOrDefault(e => e.Identity.StartedUtc <= at && (e.End == null || at <= e.End)) : null;

    public (ProcessIdentity Identity, bool Added) Start(int pid, ProcessActivity data, DateTimeOffset at, bool snapshot)
    {
        var start = data.StartedUtc ?? at;
        if (!entries.TryGetValue(pid, out var list)) entries[pid] = list = [];
        // WMI creation times and ETW start times have different precision. Only reconcile
        // across snapshot/live sources, never two distinct live starts.
        var existing = list.FirstOrDefault(e => e.Identity.StartedUtc == start ||
            ((snapshot || e.Snapshot) && Math.Abs((e.Identity.StartedUtc - start).TotalMilliseconds) < 20));
        if (existing != null)
        {
            // A process may edit its PEB after launch. A later WMI snapshot must not
            // replace the original command line captured by the kernel start event.
            if (snapshot && !existing.Snapshot && existing.Identity.CommandLine != null)
                data = data with { CommandLine = existing.Identity.CommandLine };
            existing.Identity = Merge(existing.Identity, data);
            existing.Snapshot &= snapshot;
            return (existing.Identity, false);
        }
        var prior = list.LastOrDefault(e => e.Identity.StartedUtc < start && e.End == null);
        if (prior != null) prior.End = start.AddTicks(-1);
        var parent = data.ParentPid is int parentPid ? Resolve(parentPid, start) : null;
        var identity = new ProcessIdentity(pid, start, data.ParentPid, parent?.InstanceId,
            data.Image, data.CommandLine, data.User, data.UserSid, data.Session, data.Enrichment ?? "pending");
        var next = list.FirstOrDefault(e => e.Identity.StartedUtc > start);
        list.Add(new(identity, snapshot) { End = next?.Identity.StartedUtc.AddTicks(-1) });
        list.Sort((a, b) => a.Identity.StartedUtc.CompareTo(b.Identity.StartedUtc));
        count++;
        if (count > capacity) Prune(at, true);
        return (identity, true);
    }
    public ProcessIdentity? Stop(int pid, DateTimeOffset at)
    {
        var e = Find(pid, at);
        if (e == null) return null;
        e.End = at;
        return Resolve(pid, at);
    }
    public ProcessIdentity? Enrich(int pid, ProcessActivity data)
    {
        if (!entries.TryGetValue(pid, out var list)) return null;
        var e = list.FirstOrDefault(x => x.Identity.StartedUtc == data.StartedUtc);
        if (e == null) return null;
        return e.Identity = Merge(e.Identity, data);
    }
    private static ProcessIdentity Merge(ProcessIdentity p, ProcessActivity d) => p with
    {
        Image = string.IsNullOrEmpty(d.Image) ? p.Image : d.Image,
        CommandLine = d.CommandLine ?? p.CommandLine,
        User = d.User ?? p.User, UserSid = d.UserSid ?? p.UserSid,
        Session = d.Session ?? p.Session, Enrichment = d.Enrichment ?? p.Enrichment
    };
    public void Prune(DateTimeOffset now, bool force = false)
    {
        foreach (var pair in entries.ToArray())
        {
            int removed = pair.Value.RemoveAll(e => e.End < now.AddMinutes(-2));
            count -= removed;
            if (pair.Value.Count == 0) entries.Remove(pair.Key);
        }
        if (!force || count <= capacity) return;
        foreach (var pair in entries.OrderBy(x => x.Value[0].Identity.StartedUtc).ToArray())
        {
            count -= pair.Value.Count;
            Evictions += pair.Value.Count;
            entries.Remove(pair.Key);
            if (count <= capacity * 3 / 4) break;
        }
    }
}

public sealed class ThreadCatalog(int capacity = 65536)
{
    private sealed record Entry(DateTimeOffset Start, int Pid, DateTimeOffset? End = null);
    private readonly Dictionary<int, List<Entry>> entries = [];
    private int count;
    public long Evictions { get; private set; }
    public void Apply(ThreadActivity e)
    {
        if (!entries.TryGetValue(e.Tid, out var list)) entries[e.Tid] = list = [];
        if (e.Start)
        {
            if (list.Any(x => x.Start == e.TimestampUtc && x.Pid == e.Pid)) return;
            var previous = list.FindLastIndex(x => x.End == null && x.Start <= e.TimestampUtc);
            if (previous >= 0)
            {
                if (e.Snapshot && list[previous].Pid == e.Pid) return;
                list[previous] = list[previous] with { End = e.TimestampUtc.AddTicks(-1) };
            }
            var next = list.FirstOrDefault(x => x.Start > e.TimestampUtc);
            list.Add(new(e.Snapshot ? DateTimeOffset.MinValue : e.TimestampUtc, e.Pid, next?.Start.AddTicks(-1)));
            list.Sort((a,b) => a.Start.CompareTo(b.Start));
            count++;
        }
        else
        {
            int i = list.FindLastIndex(x => x.Pid == e.Pid && x.Start <= e.TimestampUtc && x.End == null);
            if (i >= 0) list[i] = list[i] with { End = e.TimestampUtc };
        }
        if (count > capacity) Prune(e.TimestampUtc, true);
    }
    public int? Resolve(int tid, DateTimeOffset at) => entries.TryGetValue(tid, out var list)
        ? list.LastOrDefault(x => x.Start <= at && (x.End == null || at <= x.End))?.Pid : null;
    public void Prune(DateTimeOffset now, bool force = false)
    {
        foreach (var pair in entries.ToArray())
        {
            count -= pair.Value.RemoveAll(e => e.End < now.AddMinutes(-2));
            if (pair.Value.Count == 0) entries.Remove(pair.Key);
        }
        if (!force || count <= capacity) return;
        foreach (var key in entries.Keys.Take(capacity / 4).ToArray())
        {
            Evictions += entries[key].Count;
            count -= entries[key].Count;
            entries.Remove(key);
        }
    }
}
