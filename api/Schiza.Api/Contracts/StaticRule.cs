namespace Schiza.Api.Contracts;

/// <param name="Id">Rule identifier.</param>
/// <param name="Name">Short name shown in the UI and as the classification reason.</param>
/// <param name="Description">Optional longer description.</param>
/// <param name="Field">Part of the request the pattern is matched against.</param>
/// <param name="MatchType">How the pattern is matched.</param>
/// <param name="Pattern">Substring or regular expression.</param>
/// <param name="Score">Score given to a request matching the rule, from 0 to 1.</param>
/// <param name="IsActive">Inactive rules are kept but not evaluated.</param>
/// <param name="CreatedAt">When the rule was added.</param>
public sealed record StaticRule(
    int Id,
    string Name,
    string? Description,
    RuleField Field,
    RuleMatchType MatchType,
    string Pattern,
    double Score,
    bool IsActive,
    DateTimeOffset CreatedAt);
