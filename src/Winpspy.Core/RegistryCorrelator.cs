namespace Winpspy.Core;

public sealed record NativeRegistryEvent(int Id, ulong KeyObject, ulong BaseObject = 0,
    string? BaseName = null, string? RelativeName = null, string? KeyName = null,
    string? ValueName = null, uint? Status = null);

/// <summary>Key-object lifetime map. Relative names stay explicitly relative when a root predates tracing.</summary>
public sealed class RegistryCorrelator(int capacity = 65536)
{
    private readonly Dictionary<ulong,string> names = [];
    public long Evictions { get; private set; }
    public RegistryActivity Resolve(NativeRegistryEvent e)
    {
        string? name = string.IsNullOrEmpty(e.KeyName) ? names.GetValueOrDefault(e.KeyObject) : e.KeyName;
        if (e.Id is 1 or 2)
        {
            string? root = string.IsNullOrEmpty(e.BaseName) ? names.GetValueOrDefault(e.BaseObject) : e.BaseName;
            string relative = e.RelativeName ?? "";
            name = relative.StartsWith("\\REGISTRY\\",StringComparison.OrdinalIgnoreCase) ? relative :
                string.IsNullOrEmpty(root) ? relative : root.TrimEnd('\\') + (relative.Length == 0 ? "" : "\\" + relative.TrimStart('\\'));
            if (e.KeyObject != 0 && e.Status == 0 && !string.IsNullOrEmpty(name))
            {
                names[e.KeyObject] = name;
                if (names.Count > capacity)
                {
                    int remove = Math.Max(1,capacity / 4);
                    foreach (var key in names.Keys.Take(remove).ToArray()) names.Remove(key);
                    Evictions += remove;
                }
            }
        }
        if (e.Id == 13) names.Remove(e.KeyObject);
        if (string.IsNullOrEmpty(name)) name = null;
        string resolution = name == null ? "unavailable" : name.StartsWith("\\REGISTRY\\",StringComparison.OrdinalIgnoreCase) ? "absolute" : "relative";
        return new(name,e.ValueName,e.Status,resolution,e.KeyObject);
    }
}
