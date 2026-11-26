using System.Net;
using System.Text.Json.Serialization;

using Schiza.Shared.Requests;

namespace Schiza.Application.Legacy;

[JsonConverter(typeof(JsonStringEnumConverter<EventSource>))]
public enum EventSource { LogAnalysis, BlockingModule }

public sealed record EventQuery(
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    IPAddress? ClientIp = null,
    int? RuleId = null,
    EventSource? Source = null,
    string? Severity = null,
    [property: System.ComponentModel.DataAnnotations.Range(0, int.MaxValue)] int Skip = 0,
    [property: System.ComponentModel.DataAnnotations.Range(1, 200)] int Take = 50);

public sealed record SecurityEvent(int Id, DateTimeOffset ClassifiedAt, EventSource Source, ApacheRequest Request, ClassificationResult Classification);
public sealed record EventPage(IReadOnlyList<SecurityEvent> Items, int Total);
