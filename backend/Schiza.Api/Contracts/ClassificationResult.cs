namespace Schiza.Api.Contracts;

/// <param name="Verdict">Whether the request is safe.</param>
/// <param name="Score">Confidence that the request is malicious, from 0 to 1.</param>
/// <param name="Reason">Human readable reason, null for safe requests.</param>
/// <param name="RuleId">Static rule that matched, null when no rule matched.</param>
public sealed record ClassificationResult(Verdict Verdict, double Score, string? Reason, int? RuleId)
{
    public static ClassificationResult Safe { get; } = new(Verdict.Safe, 0.0, null, null);
}
