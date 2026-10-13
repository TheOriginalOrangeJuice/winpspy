using System.Runtime.InteropServices;
using System.Text;

namespace Winpspy.Collectors;

internal sealed class DevicePaths
{
    private readonly (string Device, string Drive)[] drives;
    public DevicePaths()
    {
        var mappings = new List<(string, string)>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            var buffer = new StringBuilder(32768);
            string name = drive.Name.TrimEnd('\\');
            if (QueryDosDevice(name, buffer, buffer.Capacity) > 0) mappings.Add((buffer.ToString().Split('\0')[0], name));
        }
        drives = mappings.OrderByDescending(x => x.Item1.Length).ToArray();
    }
    public string? Resolve(string? value)
    {
        if (string.IsNullOrEmpty(value)) return null;
        if (value.StartsWith("\\??\\", StringComparison.Ordinal)) return value[4..];
        foreach (var pair in drives)
            if (value.StartsWith(pair.Device + "\\", StringComparison.OrdinalIgnoreCase)) return pair.Drive + value[pair.Device.Length..];
        if (value.StartsWith("\\Device\\Mup\\", StringComparison.OrdinalIgnoreCase)) return "\\\\" + value[12..];
        return value;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint QueryDosDevice(string name, StringBuilder target, int size);
}
