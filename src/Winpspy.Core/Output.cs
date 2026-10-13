using System.Text;

namespace Winpspy.Core;

public sealed record RenderedLine(string Text, ConsoleColor Color);
public static class TimelineFormatter
{
    public static string Escape(string? value)
    {
        if (value == null) return "unavailable";
        var b = new StringBuilder(value.Length);
        foreach (char c in value)
            b.Append(c switch
            {
                '\r' => "\\r", '\n' => "\\n", '\t' => "\\t",
                _ when char.IsControl(c) || c is '\u2028' or '\u2029' or '\u202a' or '\u202b' or '\u202d' or '\u202e' or '\u202c' or '\u2066' or '\u2067' or '\u2068' or '\u2069' => $"\\u{(int)c:x4}",
                _ => c.ToString()
            });
        return b.ToString();
    }
    public static IEnumerable<RenderedLine> Lines(ActivityEvent e)
    {
        string time = e.TimestampUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss.fff zzz");
        string actor = $"PID={e.Pid?.ToString() ?? "?"} {Escape(e.Process?.Image)}";
        string prefix = $"{time} [{e.Kind.ToUpperInvariant()}]";
        var d = e.Details;
        ConsoleColor color = e.Category switch
        {
            Category.File => ConsoleColor.Blue,
            Category.Process when e.Kind == "process.stop" => ConsoleColor.Gray,
            Category.Process => ConsoleColor.Green,
            Category.PowerShell => ConsoleColor.Magenta,
            Category.Network or Category.Dns => ConsoleColor.Cyan,
            Category.Registry => ConsoleColor.Yellow,
            Category.Health when d.Health?.State is "degraded" or "unavailable" or "failed" => ConsoleColor.Red,
            _ => ConsoleColor.White
        };
        string text;
        if (d.Health is { } h)
            text = $"{Escape(h.Collector)} {h.State}: {Escape(h.Message)}" +
                (h.Counts == null ? "" : " | " + string.Join(" ", h.Counts.Select(x => $"{x.Key}={x.Value}")));
        else if (d.File is { } f)
            text = $"{actor} | {(f.OldPath != null ? Escape(f.OldPath) + " → " : "")}{Escape(f.Path)} | result={f.Result}" +
                (f.Status == null ? "" : $" status=0x{f.Status:x8}") +
                (f.RequestedDisposition == null ? "" : $" requestedDisposition={f.RequestedDisposition}") +
                (f.Bytes == null ? "" : $" requestedBytes={f.Bytes}") + (e.Count > 1 ? $" count={e.Count}" : "");
        else if (d.Registry is { } r)
            text = $"{actor} | {Escape(r.Key)}{(r.ValueName == null ? "" : " :: " + Escape(r.ValueName))} | status={(r.Status == null ? "unknown" : $"0x{r.Status:x8}")}" + (r.KeyResolution == "relative" ? " key=relative" : "");
        else if (d.Network is { } n)
            text = n.Query != null ? $"{actor} | {Escape(n.Query)} → {Escape(n.Answers)} status={n.Status?.ToString() ?? "unknown"}" :
                $"{actor} | {n.Protocol} {n.Direction} {Endpoint(n.LocalAddress,n.LocalPort)} ↔ {Endpoint(n.RemoteAddress,n.RemotePort)}" + (n.Bytes == null ? "" : $" bytes={n.Bytes}");
        else if (d.Script is { } s)
            text = $"{actor} | script={Escape(s.Id)} path={Escape(s.Path)} parts={s.ReceivedParts}/{s.ExpectedParts} complete={s.Complete} | {Escape(s.Text)}";
        else if (d.Log is { } l)
            text = $"{actor} | {Escape(l.Name)} | " + string.Join(" ", l.Fields.Select(x => $"{Escape(x.Key)}={Escape(x.Value)}"));
        else if (d.Pipe != null) text = Escape(d.Pipe) + " (sampled)";
        else
            text = $"{actor} PPID={e.Process?.ParentPid ?? d.Process?.ParentPid} USER={Escape(e.Process?.User ?? e.Process?.UserSid)}" +
                (d.Process?.ExitCode is int exit ? $" EXIT={exit}" : "");
        yield return new($"{prefix} {text}", color);
        if (e.Kind is "process.start" or "process.snapshot" or "process.enriched")
            yield return new("    [CMD] " + Escape(e.Process?.CommandLine ?? d.Process?.CommandLine), ConsoleColor.Magenta);
    }
    public static string Plain(ActivityEvent e) => string.Join(Environment.NewLine, Lines(e).Select(x => x.Text));
    private static string Endpoint(string? address,int? port) =>
        (address?.Contains(':') == true ? "[" + Escape(address) + "]" : Escape(address)) + ":" + (port?.ToString() ?? "?");
}

public sealed class ConsolePresentation(Options options, Action<ActivityEvent> write)
{
    private sealed record Group(ActivityEvent Event, DateTimeOffset Deadline);
    private readonly Dictionary<string, Group> writes = [];
    private readonly Dictionary<string, long> suppressed = [];
    private DateTimeOffset rateWindow;
    private int displayed;
    public long Summarized { get; private set; }
    public void Accept(ActivityEvent e, DateTimeOffset now)
    {
        Tick(now);
        if (options.Raw) { write(e); return; }
        if (e.Kind == "file.write" && e.Details.File?.Path is string path)
        {
            string key = $"{e.Process?.InstanceId ?? (e.Pid?.ToString() + ":unknown")}|{path.ToUpperInvariant()}|{e.Details.File.Result}|{e.Details.File.Status}";
            if (writes.TryGetValue(key, out var group))
            {
                var previous = group.Event;
                writes[key] = group with { Event = previous with { Count = previous.Count + 1,
                    Details = previous.Details with { File = previous.Details.File! with { Bytes = (previous.Details.File.Bytes ?? 0) + (e.Details.File.Bytes ?? 0) } } } };
                return;
            }
            if (writes.Count >= 8192) FlushWrites(now, true);
            writes[key] = new(e, now.AddMilliseconds(500));
            return;
        }
        if (e.Category == Category.File) FlushWrites(now, true); // lifecycle boundaries cannot be swallowed by write groups
        Emit(e, now);
    }
    public void Tick(DateTimeOffset now, bool all = false)
    {
        FlushWrites(now, all);
        if (all || now - rateWindow >= TimeSpan.FromSeconds(1))
        {
            if (suppressed.Count > 0)
            {
                write(ActivityEvent.Health("console", "summary", "Additional entries summarized; exports retain individual events. Use --raw for every console entry.", new Dictionary<string,long>(suppressed)));
                suppressed.Clear();
            }
            displayed = 0;
            rateWindow = now;
        }
    }
    private void FlushWrites(DateTimeOffset now, bool all)
    {
        foreach (var pair in writes.Where(p => all || p.Value.Deadline <= now).ToArray())
        {
            writes.Remove(pair.Key);
            Emit(pair.Value.Event, now);
        }
    }
    private void Emit(ActivityEvent e, DateTimeOffset now)
    {
        if (e.Category is Category.File or Category.Network or Category.Dns or Category.Registry)
        {
            if (now - rateWindow >= TimeSpan.FromSeconds(1))
            {
                if (suppressed.Count > 0) write(ActivityEvent.Health("console", "summary", "Additional entries summarized; exports are unaffected.", new Dictionary<string,long>(suppressed)));
                suppressed.Clear(); rateWindow = now; displayed = 0;
            }
            if (displayed++ >= 25)
            {
                suppressed[e.Kind] = suppressed.GetValueOrDefault(e.Kind) + e.Count;
                Summarized += e.Count;
                return;
            }
        }
        write(e);
    }
}

public sealed class EvidenceWriter : IDisposable
{
    private readonly string path;
    private readonly string format;
    private readonly long rotateBytes;
    private FileStream stream;
    private int segment;
    private bool closed;
    public EvidenceWriter(string path, string format = "jsonl", long rotateBytes = 100L * 1024 * 1024)
    {
        this.path = Path.GetFullPath(path); this.format = format; this.rotateBytes = rotateBytes;
        string directory = Path.GetDirectoryName(this.path)!;
        if (!Directory.Exists(directory)) throw new DirectoryNotFoundException($"Output directory does not exist: {directory}");
        string stem = Path.GetFileNameWithoutExtension(path), ext = Path.GetExtension(path);
        if (File.Exists(this.path) || Directory.EnumerateFiles(directory, stem + ".*" + ext).Any(IsCapturePath))
            throw new IOException($"Capture already exists: {path}. Choose a new output path.");
        stream = Open();
    }
    private string SegmentPath => segment == 0 ? path : Path.Combine(Path.GetDirectoryName(path)!,
        $"{Path.GetFileNameWithoutExtension(path)}.{segment:D4}{Path.GetExtension(path)}");
    private FileStream Open() => new(SegmentPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 65536);
    public bool IsCapturePath(string value)
    {
        if (value.Equals(path, StringComparison.OrdinalIgnoreCase)) return true;
        if (!string.Equals(Path.GetDirectoryName(value), Path.GetDirectoryName(path), StringComparison.OrdinalIgnoreCase)) return false;
        string name = Path.GetFileNameWithoutExtension(value);
        string prefix = Path.GetFileNameWithoutExtension(path) + ".";
        return Path.GetExtension(value).Equals(Path.GetExtension(path), StringComparison.OrdinalIgnoreCase) &&
            name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && int.TryParse(name[prefix.Length..], out _);
    }
    public void Write(ActivityEvent e)
    {
        ObjectDisposedException.ThrowIf(closed,this);
        byte[] bytes = Encoding.UTF8.GetBytes((format == "jsonl" ? EventJson.Serialize(e) : TimelineFormatter.Plain(e)) + "\n");
        if (stream.Position > 0 && stream.Position + bytes.Length > rotateBytes)
        {
            stream.Flush(true); stream.Dispose(); closed = true;
            segment++; stream = Open(); closed = false;
        }
        stream.Write(bytes);
    }
    public void Flush() { if (!closed) stream.Flush(); }
    public void Dispose()
    {
        if (closed) return;
        try { stream.Flush(true); }
        finally { stream.Dispose(); closed = true; }
    }
}
