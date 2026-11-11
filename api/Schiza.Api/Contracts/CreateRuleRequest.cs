using System.ComponentModel.DataAnnotations;

namespace Schiza.Api.Contracts;

/// <param name="Name">Short name shown in the UI and as the classification reason.</param>
/// <param name="Description">Optional longer description.</param>
/// <param name="Field">Part of the request the pattern is matched against.</param>
/// <param name="MatchType">How the pattern is matched, <see cref="RuleMatchType.Contains"/> by default.</param>
/// <param name="Pattern">Substring or regular expression.</param>
/// <param name="Score">Score given to a matching request, 1 by default.</param>
/// <param name="IsActive">Whether the rule is evaluated right away, true by default.</param>
public sealed record CreateRuleRequest(
    [Required, StringLength(100)] string Name,
    [StringLength(1000)] string? Description,
    [Required] RuleField? Field,
    RuleMatchType MatchType,
    [Required, StringLength(1000)] string Pattern,
    [Range(0.0, 1.0)] double Score = 1.0,
    bool IsActive = true);
