using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace Winpspy.Core;

public sealed class EventLogDecoder
{
    private sealed class Assembly(ActivityEvent first, string id, string? path, int total)
    {
        public ActivityEvent First = first;
        public string Id = id;
        public string? Path = path;
        public int Total = total;
        public readonly SortedDictionary<int, string> Parts = [];
        public int Characters;
    }
    private readonly Dictionary<string, Assembly> scripts = [];
    private readonly HashSet<string> completed = [];
    private readonly Queue<string> completedOrder = [];
    public IEnumerable<ActivityEvent> Decode(string xml)
    {
        using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, MaxCharactersInDocument = 8 * 1024 * 1024 });
        var root = XDocument.Load(reader).Root ?? throw new FormatException("Missing event root.");
        XNamespace ns = root.Name.Namespace;
        var system = root.Element(ns + "System") ?? throw new FormatException("Missing System element.");
        string provider = (string?)system.Element(ns + "Provider")?.Attribute("Name") ?? "unknown";
        int id = (int?)system.Element(ns + "EventID") ?? 0;
        int version = (int?)system.Element(ns + "Version") ?? 0;
        string channel = (string?)system.Element(ns + "Channel") ?? "unknown";
        DateTimeOffset time = DateTimeOffset.Parse((string?)system.Element(ns + "TimeCreated")?.Attribute("SystemTime") ?? throw new FormatException("Missing timestamp."), CultureInfo.InvariantCulture).ToUniversalTime();
        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int unnamed = 0;
        foreach (var field in root.Element(ns + "EventData")?.Elements() ?? [])
            fields[(string?)field.Attribute("Name") ?? $"param{++unnamed}"] = field.Value;
        foreach (var field in root.Element(ns + "UserData")?.Descendants().Where(x => !x.HasElements) ?? []) fields[field.Name.LocalName] = field.Value;
        int? Number(string name) => fields.TryGetValue(name, out var value) && int.TryParse(value, out int n) ? n : null;
        bool powerShell = provider.Contains("PowerShell", StringComparison.OrdinalIgnoreCase);
        bool task = provider.Contains("TaskScheduler", StringComparison.OrdinalIgnoreCase) || (provider == "Microsoft-Windows-Security-Auditing" && id is >= 4698 and <= 4702);
        bool service = provider == "Service Control Manager" || (provider == "Microsoft-Windows-Security-Auditing" && id == 4697);
        Category category = powerShell ? Category.PowerShell : task ? Category.Task : service ? Category.Service : Category.Health;
        // The event logger's header PID is not generally the actor (SCM, Security, TaskScheduler).
        int? pid = powerShell ? (int?)system.Element(ns + "Execution")?.Attribute("ProcessID") :
            task && id == 129 ? Number("ProcessID") : provider == "Microsoft-Windows-Security-Auditing" ? Number("ClientProcessId") : null;
        var source = new EventSource(provider, id, version, channel, (long?)system.Element(ns + "EventRecordID"));
        string name = fields.GetValueOrDefault("TaskName") ?? fields.GetValueOrDefault("ServiceName") ?? fields.GetValueOrDefault("param1") ?? provider;
        var e = new ActivityEvent(time, category, category.ToString().ToLowerInvariant() + ".event", source, new(Log: new(name, fields)), pid);
        if (!powerShell || id != 4104) { yield return e; yield break; }
        string scriptId = fields.GetValueOrDefault("ScriptBlockId") ?? "unknown";
        string key = $"{channel}|{pid}|{scriptId}";
        if (completed.Contains(key)) yield break;
        int total = Number("MessageTotal") ?? 1, index = Number("MessageNumber") ?? 1;
        if (total is < 1 or > 4096 || index < 1 || index > total) throw new FormatException("Invalid script-block part count.");
        if (!scripts.TryGetValue(key, out var assembly))
        {
            if (scripts.Count >= 256)
            {
                var oldest = scripts.MinBy(x => x.Value.First.TimestampUtc);
                scripts.Remove(oldest.Key);
                yield return Finish(oldest.Value, false);
            }
            scripts[key] = assembly = new(e, scriptId, fields.GetValueOrDefault("Path"), total);
        }
        else if (assembly.Total != total)
        {
            yield return Finish(assembly,false);
            scripts[key] = assembly = new(e,scriptId,fields.GetValueOrDefault("Path"),total);
        }
        string text = fields.GetValueOrDefault("ScriptBlockText") ?? "";
        if (!assembly.Parts.ContainsKey(index))
        {
            assembly.Characters += text.Length;
            assembly.Parts[index] = text;
        }
        if (assembly.Parts.Count == total || assembly.Characters >= 4 * 1024 * 1024)
        {
            scripts.Remove(key);
            RememberCompleted(key);
            yield return Finish(assembly, assembly.Parts.Count == total);
        }
        // A count bound alone would permit 256 multi-megabyte incomplete scripts.
        while (scripts.Values.Sum(x => (long)x.Characters) > 8 * 1024 * 1024)
        {
            var oldest = scripts.MinBy(x => x.Value.First.TimestampUtc);
            scripts.Remove(oldest.Key);
            yield return Finish(oldest.Value,false);
        }
    }
    private void RememberCompleted(string key)
    {
        completed.Add(key); completedOrder.Enqueue(key);
        while (completedOrder.Count > 4096) completed.Remove(completedOrder.Dequeue());
    }
    public IEnumerable<ActivityEvent> Flush(DateTimeOffset now, bool all = false)
    {
        foreach (var pair in scripts.Where(x => all || now - x.Value.First.TimestampUtc > TimeSpan.FromSeconds(30)).ToArray())
        {
            scripts.Remove(pair.Key);
            yield return Finish(pair.Value, false);
        }
    }
    private static ActivityEvent Finish(Assembly a, bool complete) => a.First with
    {
        Kind = "powershell.script",
        Details = new(Script: new(a.Id, a.Path, string.Concat(a.Parts.Values), a.Parts.Count, a.Total, complete))
    };
}
