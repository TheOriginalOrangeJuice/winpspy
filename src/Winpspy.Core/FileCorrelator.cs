namespace Winpspy.Core;

/// <summary>Correlates operations by IRP and names by file-object lifetime, not timing proximity.</summary>
public sealed class FileCorrelator(int capacity = 32768)
{
    private sealed record Name(string Path, DateTimeOffset Seen);
    private sealed record Pending(NativeFileEvent Event, string? OldPath, string? Path);
    private readonly Dictionary<ulong, Name> objects = [];
    private readonly Dictionary<ulong, Name> keys = [];
    private readonly Dictionary<ulong, Pending> pending = [];
    public long Evictions { get; private set; }
    public int PendingCount => pending.Count;

    public IEnumerable<ActivityEvent> Accept(NativeFileEvent e)
    {
        if (e.Id is 10 or 11) // Name creation/deletion, not evidence that a user created/deleted a file.
        {
            if (e.Id == 10 && e.Path != null) Remember(keys, e.FileKey != 0 ? e.FileKey : e.FileObject, e.Path, e.TimestampUtc);
            if (e.Id == 11) keys.Remove(e.FileKey != 0 ? e.FileKey : e.FileObject);
            yield break;
        }
        if (e.Id == 14) { objects.Remove(e.FileObject); yield break; }
        if (e.Id == 24)
        {
            if (pending.Remove(e.Irp, out var operation))
            {
                var result = Complete(operation, e.Status, e.Extra);
                if (e.Status is uint status && unchecked((int)status) >= 0 && operation.Event.Id is 19 or 27 or 29 && operation.Path != null)
                    Remember(objects, operation.Event.FileObject, operation.Path, e.TimestampUtc);
                yield return result;
            }
            yield break;
        }
        if (e.Id is not (12 or 15 or 16 or 17 or 18 or 19 or 26 or 27 or 28 or 29 or 30 or 31 or 33)) yield break;
        string? known = objects.GetValueOrDefault(e.FileObject)?.Path ?? keys.GetValueOrDefault(e.FileKey)?.Path;
        string? path = e.Path ?? known;
        string? oldPath = e.Id is 19 or 27 or 29 ? known : null;
        if (e.Id is 12 or 30 && e.Path != null) Remember(objects, e.FileObject, e.Path, e.TimestampUtc);
        if (e.FileKey != 0 && known != null) Remember(keys, e.FileKey, known, e.TimestampUtc);

        if (e.Irp == 0) { yield return Complete(new(e, oldPath, path), null, 0); yield break; }
        if (pending.TryGetValue(e.Irp, out var prior))
        {
            // Path-detail and CreateNewFile events supplement the corresponding operation.
            bool related = prior.Event.FileObject == e.FileObject &&
                ((prior.Event.Id is 12 or 30 && e.Id is 12 or 30) ||
                 (prior.Event.Id is 18 or 26 && e.Id is 18 or 26) ||
                 (prior.Event.Id is 19 or 27 or 29 && e.Id is 19 or 27 or 29));
            if (related)
            {
                var chosen = e.Id is 26 or 27 or 30 ? e : prior.Event;
                pending[e.Irp] = new(chosen, prior.OldPath ?? oldPath, e.Path ?? prior.Path);
                yield break;
            }
            // IRP reuse without a completion: preserve the unresolved previous operation.
            yield return Complete(prior, null, 0);
        }
        pending[e.Irp] = new(e, oldPath, path);
        if (pending.Count > capacity)
        {
            var oldest = pending.MinBy(p => p.Value.Event.TimestampUtc);
            pending.Remove(oldest.Key);
            Evictions++;
            yield return Complete(oldest.Value, null, 0);
        }
    }
    public IEnumerable<ActivityEvent> Flush(DateTimeOffset now, bool all = false)
    {
        foreach (var pair in pending.Where(p => all || p.Value.Event.TimestampUtc < now.AddSeconds(-2)).ToArray())
        {
            pending.Remove(pair.Key);
            yield return Complete(pair.Value, null, 0);
        }
    }
    private void Remember(Dictionary<ulong, Name> cache, ulong key, string path, DateTimeOffset at)
    {
        if (key == 0) return;
        cache[key] = new(path, at);
        if (cache.Count <= capacity) return;
        foreach (var old in cache.OrderBy(x => x.Value.Seen).Take(capacity / 4).Select(x => x.Key).ToArray()) cache.Remove(old);
        Evictions += capacity / 4;
    }
    private static ActivityEvent Complete(Pending p, uint? status, ulong extra)
    {
        var e = p.Event;
        bool success = status is uint s && unchecked((int)s) >= 0;
        string operation = e.Id switch
        {
            12 when success && extra == 2 => "create",
            12 when success && extra is 0 or 3 => "overwrite",
            12 when !success && e.CreateDisposition is not null and not 1 => "createOrOpen",
            12 => "open", 30 => "create", 15 => "read", 16 => "write",
            18 or 26 => "delete", 19 or 27 or 29 => "rename", 28 => "link",
            31 => "security", 33 => "extendedAttributes", _ => "setInformation"
        };
        string result = status == null ? "unknown" : success ? "success" : "failed";
        string? detail = operation == "delete" ? "Deletion disposition; final removal may wait for open handles." : null;
        return new(e.TimestampUtc, Category.File, "file." + operation, e.Source,
            new(File: new(p.Path, p.OldPath, e.Bytes, result, status, e.FileObject, e.Offset, detail, e.CreateDisposition)), e.Pid, e.Tid);
    }
}
