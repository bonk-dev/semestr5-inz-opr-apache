namespace Schiza.Domain;

public sealed record FlaggedEvent(
    long Id,
    DateTimeOffset EventTimeUtc,
    DateTimeOffset DetectedAtUtc,
    string RawLogLine,
    string RequestJson,
    string DetectionJson,
    string Severity,
    string Method,
    string Url,
    string ClientIp);
