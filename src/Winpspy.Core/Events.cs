using System.Text.Json;
using System.Text.Json.Serialization;

namespace Winpspy.Core;

public enum Category { Process, File, Network, Dns, Registry, Service, Task, PowerShell, Pipe, Health }
public sealed record EventSource(string Provider, int? Id = null, int? Version = null,
    string? Channel = null, long? RecordId = null, int? Opcode = null);
public sealed record ProcessIdentity(int Pid, DateTimeOffset StartedUtc, int? ParentPid = null,
    string? ParentInstanceId = null, string? Image = null, string? CommandLine = null,
    string? User = null, string? UserSid = null, int? Session = null, string Enrichment = "pending")
{
    public string InstanceId => $"{Pid}:{StartedUtc.UtcTicks}";
}
public sealed record ProcessActivity(DateTimeOffset? StartedUtc = null, int? ParentPid = null,
    string? Image = null, string? CommandLine = null, int? Session = null, int? ExitCode = null,
    string? User = null, string? UserSid = null, string? Enrichment = null);
public sealed record FileActivity(string? Path, string? OldPath = null, long? Bytes = null,
    string Result = "unknown", uint? Status = null, ulong? FileObject = null,
    long? Offset = null, string? Detail = null, int? RequestedDisposition = null);
public sealed record NetworkActivity(string? Protocol = null, string? LocalAddress = null,
    int? LocalPort = null, string? RemoteAddress = null, int? RemotePort = null,
    long? Bytes = null, string? Direction = null, string? Query = null,
    string? Answers = null, uint? Status = null);
public sealed record RegistryActivity(string? Key, string? ValueName, uint? Status,
    string KeyResolution = "unavailable", ulong? KeyObject = null);
public sealed record ScriptActivity(string Id, string? Path, string Text, int ReceivedParts,
    int ExpectedParts, bool Complete);
public sealed record LogActivity(string Name, IReadOnlyDictionary<string, string> Fields);
public sealed record HealthActivity(string Collector, string State, string Message,
    IReadOnlyDictionary<string, long>? Counts = null);
public sealed record EventDetails(ProcessActivity? Process = null, FileActivity? File = null,
    NetworkActivity? Network = null, RegistryActivity? Registry = null, ScriptActivity? Script = null,
    LogActivity? Log = null, string? Pipe = null, HealthActivity? Health = null);
public sealed record ActivityEvent(DateTimeOffset TimestampUtc, Category Category, string Kind,
    EventSource Source, EventDetails Details, int? Pid = null, int? Tid = null)
{
    public int SchemaVersion => 1;
    public Guid SessionId { get; init; }
    public long EventId { get; init; }
    public string Host { get; init; } = Environment.MachineName;
    public ProcessIdentity? Process { get; init; }
    public string Attribution { get; init; } = "unavailable";
    public int Count { get; init; } = 1;
    [JsonIgnore] public bool Internal { get; init; }
    public static ActivityEvent Health(string collector, string state, string message,
        IReadOnlyDictionary<string, long>? counts = null) =>
        new(DateTimeOffset.UtcNow, Category.Health, "health", new("winpspy"),
            new(Health: new(collector, state, message, counts)));
}
public static class EventJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };
    public static string Serialize(ActivityEvent value) => JsonSerializer.Serialize(value, Options);
}
public sealed record ThreadActivity(DateTimeOffset TimestampUtc, int Tid, int Pid, bool Start, bool Snapshot = false);
public sealed record NativeFileEvent(DateTimeOffset TimestampUtc, int Id, EventSource Source,
    ulong Irp = 0, ulong FileObject = 0, ulong FileKey = 0, int? Tid = null,
    string? Path = null, uint? Status = null, ulong Extra = 0, long? Bytes = null,
    long? Offset = null, int? Pid = null, int? CreateDisposition = null);
public sealed record CaptureItem(DateTimeOffset TimestampUtc, ActivityEvent? Event = null,
    NativeFileEvent? File = null, ThreadActivity? Thread = null, string? LogXml = null);
