using System.Globalization;

namespace Winpspy.Core;

public sealed class Options
{
    public HashSet<Category> Events { get; } = Enum.GetValues<Category>().Where(x => x != Category.Pipe).ToHashSet();
    public List<string> Paths { get; } = [];
    public bool ExplicitPaths { get; private set; }
    public bool Recursive { get; private set; } = true;
    public HashSet<int> Pids { get; } = [];
    public bool FollowChildren { get; private set; }
    public List<string> Processes { get; } = [];
    public List<string> Users { get; } = [];
    public List<string> Includes { get; } = [];
    public List<string> Excludes { get; } = [];
    public string? Contains { get; private set; }
    public string? Output { get; private set; }
    public string Format { get; private set; } = "jsonl";
    public bool NoColor { get; private set; }
    public bool Verbose { get; private set; }
    public bool Raw { get; private set; }
    public bool Check { get; private set; }
    public bool Help { get; private set; }
    public TimeSpan? Duration { get; private set; }
    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            string Next() => ++i < args.Length ? args[i] : throw new ArgumentException($"{a} requires a value.");
            switch (a)
            {
                case "--help": case "-h": o.Help = true; break;
                case "--path": o.Paths.Add(Next()); break;
                case "--recursive": o.Recursive = true; break;
                case "--recursive=false": case "--no-recursive": o.Recursive = false; break;
                case "--events":
                    o.Events.Clear();
                    foreach (string v in Next().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    {
                        if (v.Equals("all", StringComparison.OrdinalIgnoreCase)) o.Events.UnionWith(Enum.GetValues<Category>());
                        else if (Enum.TryParse<Category>(v, true, out var c) && Enum.IsDefined(c)) o.Events.Add(c);
                        else throw new ArgumentException($"Unknown event category: {v}.");
                    }
                    if (o.Events.Count == 0) throw new ArgumentException("--events cannot be empty.");
                    o.Events.Add(Category.Health);
                    break;
                case "--pid":
                    foreach (string p in Next().Split(','))
                        if (int.TryParse(p, out int pid) && pid > 0) o.Pids.Add(pid);
                        else throw new ArgumentException("--pid requires positive process IDs.");
                    break;
                case "--follow-children": o.FollowChildren = true; break;
                case "--process": o.Processes.Add(Next()); break;
                case "--user": o.Users.Add(Next()); break;
                case "--include": o.Includes.Add(Next()); break;
                case "--exclude": o.Excludes.Add(Next()); break;
                case "--contains": o.Contains = Next(); break;
                case "--output": o.Output = Path.GetFullPath(Next()); break;
                case "--format":
                    o.Format = Next().ToLowerInvariant();
                    if (o.Format is not ("text" or "jsonl")) throw new ArgumentException("--format must be jsonl or text.");
                    break;
                case "--no-color": o.NoColor = true; break;
                case "--verbose": o.Verbose = true; break;
                case "--raw": o.Raw = true; break;
                case "--check": o.Check = true; break;
                case "--duration":
                    if (!double.TryParse(Next(), CultureInfo.InvariantCulture, out var seconds) || !double.IsFinite(seconds) || seconds <= 0 || seconds > 604800)
                        throw new ArgumentException("--duration requires seconds greater than 0 and at most 604800.");
                    o.Duration = TimeSpan.FromSeconds(seconds);
                    break;
                default:
                    if (a.StartsWith('-')) throw new ArgumentException($"Unknown option: {a}.");
                    o.Paths.Add(a);
                    break;
            }
        }
        if (o.FollowChildren && o.Pids.Count == 0) throw new ArgumentException("--follow-children requires --pid.");
        o.ExplicitPaths = o.Paths.Count > 0;
        for (int i = 0; i < o.Paths.Count; i++) o.Paths[i] = Path.GetFullPath(o.Paths[i]);
        return o;
    }
    public const string Usage = """
    winpspy 2.0 - live Windows activity monitor (based on xct/winpspy)
    Usage: winpspy.exe [directories...] [options]
      --path DIR              Add a file collection root; default: all local fixed drives
      --recursive             Include subdirectories (default)
      --recursive=false       Only direct children of each root
      --events LIST           process,file,network,dns,registry,service,task,powershell,pipe
                              Default: all except sampled pipes; 'all' includes pipes
      --pid PID[,PID]         Filter console by process ID
      --follow-children       Follow those process instances and their descendants
      --process GLOB          Filter console by image name or full image path (repeatable)
      --user GLOB             Filter console by account or SID (repeatable)
      --include GLOB          Include console paths/key names (repeatable)
      --exclude GLOB          Exclude console paths/key names (repeatable)
      --contains TEXT         Case-insensitive console text search
      --output FILE           Save individual events; no file is created by default
      --format jsonl|text     Export format (default: jsonl); rotate at 100 MiB
      --raw                   Disable console write grouping and burst summaries
      --verbose               Include file opens/reads, registry queries, enrichment updates
      --no-color              Plain text (automatic when redirected)
      --duration SECONDS      Stop and flush after this duration
      --check                 Report capabilities without collecting or changing settings
      --help                  Show this help

    Run monitoring in an elevated terminal. Ctrl+C stops and flushes the capture.
    --events and directories control collection. Other filters affect only the console.
    Colors indicate activity categories, not maliciousness. Unknown attribution is explicit.
    """;
}
