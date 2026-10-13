namespace Winpspy.Core;

public static class WindowsPaths
{
    public static string Normalize(string p) => p.Replace('/', '\\').TrimEnd('\\');
    public static bool IsWithin(string path, string root, bool recursive)
    {
        path = Normalize(path); root = Normalize(root);
        if (path.Equals(root, StringComparison.OrdinalIgnoreCase)) return true;
        if (!path.StartsWith(root + "\\", StringComparison.OrdinalIgnoreCase)) return false;
        return recursive || !path[(root.Length + 1)..].Contains('\\');
    }
    public static bool Glob(string pattern, string? value)
    {
        if (value == null) return false;
        // Backslashes in Windows paths/accounts are literal separators, not glob escapes.
        int p = 0, v = 0, star = -1, retry = 0;
        while (v < value.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(value[v]))) { p++; v++; }
            else if (p < pattern.Length && pattern[p] == '*') { star = p++; retry = v; }
            else if (star >= 0) { p = star + 1; v = ++retry; }
            else return false;
        }
        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}

public sealed class ConsoleFilter(Options options)
{
    private readonly HashSet<string> followed = [];
    private readonly Dictionary<int, string> roots = [];
    public void Observe(ProcessIdentity p)
    {
        if (!options.FollowChildren) return;
        if (options.Pids.Contains(p.Pid) && !roots.ContainsKey(p.Pid)) roots[p.Pid] = p.InstanceId;
        if ((roots.GetValueOrDefault(p.Pid) == p.InstanceId) ||
            (p.ParentInstanceId != null && followed.Contains(p.ParentInstanceId)))
        {
            if (followed.Count < 32768) followed.Add(p.InstanceId);
        }
    }
    public bool Matches(ActivityEvent e)
    {
        if (e.Category == Category.Health) return true;
        // With a user filter, the launch may precede account lookup. Show the
        // matching enrichment record with the original launch command when it arrives.
        if (e.Kind == "process.enriched" && !options.Verbose && options.Users.Count == 0) return false;
        if (options.Pids.Count > 0)
        {
            if (options.FollowChildren)
            {
                var p = e.Process;
                if (p == null) return false;
                Observe(p);
                if (!followed.Contains(p.InstanceId)) return false;
            }
            else if (e.Pid == null || !options.Pids.Contains(e.Pid.Value)) return false;
        }
        string? image = e.Process?.Image ?? e.Details.Process?.Image;
        string? name = image?.Replace('/', '\\').Split('\\').Last();
        if (options.Processes.Count > 0 && !options.Processes.Any(x => WindowsPaths.Glob(x, image) || WindowsPaths.Glob(x, name))) return false;
        if (options.Users.Count > 0 && !options.Users.Any(x => WindowsPaths.Glob(x, e.Process?.User) || WindowsPaths.Glob(x, e.Process?.UserSid))) return false;
        string?[] paths = [e.Details.File?.Path, e.Details.File?.OldPath, e.Details.Registry?.Key,
            e.Details.Script?.Path, e.Details.Log?.Name, e.Details.Pipe, image];
        if (options.Includes.Count > 0 && !options.Includes.Any(x => paths.Any(p => WindowsPaths.Glob(x, p)))) return false;
        if (options.Excludes.Any(x => paths.Any(p => WindowsPaths.Glob(x, p)))) return false;
        return options.Contains == null || TimelineFormatter.Plain(e).Contains(options.Contains, StringComparison.OrdinalIgnoreCase);
    }
}
