using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.Json.Serialization;

using Schiza.Shared.Requests;

namespace Schiza.Application.Legacy;

[JsonConverter(typeof(JsonStringEnumConverter<Verdict>))]
public enum Verdict { Safe, Unsafe }

[JsonConverter(typeof(JsonStringEnumConverter<EventSource>))]
public enum EventSource { LogAnalysis, BlockingModule }

[JsonConverter(typeof(JsonStringEnumConverter<RuleField>))]
public enum RuleField { Path, Query, RequestLine, UserAgent, Referer, Host }

[JsonConverter(typeof(JsonStringEnumConverter<RuleMatchType>))]
public enum RuleMatchType { Contains, Regex }

public sealed record ClassificationResult(Verdict Verdict, double Score, string? Reason, int? RuleId)
{
    public static ClassificationResult Safe { get; } = new(Verdict.Safe, 0.0, null, null);
}

public sealed record StaticRule(int Id, string Name, string? Description, RuleField Field, RuleMatchType MatchType, string Pattern, double Score, bool IsActive, DateTimeOffset CreatedAt);

public sealed record CreateRuleRequest(
    [Required, StringLength(100)] string Name,
    [StringLength(1000)] string? Description,
    [Required] RuleField? Field,
    RuleMatchType MatchType,
    [Required, StringLength(1000)] string Pattern,
    [Range(0.0, 1.0)] double Score = 1.0,
    bool IsActive = true);

public sealed record EventQuery(DateTimeOffset? From = null, DateTimeOffset? To = null, IPAddress? ClientIp = null, int? RuleId = null, EventSource? Source = null, [Range(0, int.MaxValue)] int Skip = 0, [Range(1, 200)] int Take = 50);

public sealed record SecurityEvent(int Id, DateTimeOffset ClassifiedAt, EventSource Source, ApacheRequest Request, ClassificationResult Classification);
public sealed record EventPage(IReadOnlyList<SecurityEvent> Items, int Total);

public interface IEventStore
{
    SecurityEvent Add(ApacheRequest request, ClassificationResult classification);
    SecurityEvent? Get(int id);
    EventPage Query(EventQuery query);
}

public interface IRequestClassifier
{
    ClassificationResult Classify(ApacheRequest request);
}

public interface IRuleStore
{
    IReadOnlyList<StaticRule> GetAll();
    StaticRule? Get(int id);
    StaticRule Add(CreateRuleRequest request);
    StaticRule? SetActive(int id, bool isActive);
    bool Remove(int id);
}
