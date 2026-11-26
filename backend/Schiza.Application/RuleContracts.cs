using System.ComponentModel.DataAnnotations;
using Schiza.Shared.Requests;

namespace Schiza.Application.Legacy;

public enum RuleField { Path, Query, RequestLine, UserAgent, Referer, Host, Body }

public enum RuleMatchType { Contains, Regex }

public sealed record StaticRule(int Id, string Name, string? Description, RuleField Field, RuleMatchType MatchType, string Pattern, double Score, bool IsActive, DateTimeOffset CreatedAt);

public sealed record CreateRuleRequest(
    [Required, StringLength(100)] string Name,
    [StringLength(1000)] string? Description,
    [Required] RuleField? Field,
    RuleMatchType MatchType,
    [Required, StringLength(1000)] string Pattern,
    [Range(0.0, 1.0)] double Score = 1.0,
    bool IsActive = true);

public interface IRuleStore
{
    IReadOnlyList<StaticRule> GetAll();
    StaticRule? Get(int id);
    StaticRule Add(CreateRuleRequest request);
    StaticRule? SetActive(int id, bool isActive);
    bool Remove(int id);
}
