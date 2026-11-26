using Schiza.Shared.Requests;

namespace Schiza.Application.Legacy;

public enum Verdict { Safe, Unsafe }

public sealed record ClassificationResult(
    Verdict Verdict,
    double Score,
    string? Reason,
    int? RuleId,
    bool StaticRulesMatched = false,
    bool AutoencoderThresholdExceeded = false,
    double? AnomalyScore = null,
    string? DetectionJson = null)
{
    public static ClassificationResult Safe { get; } = new(Verdict.Safe, 0.0, null, null);
}

public interface IRequestClassifier : IClassifier
{
}

public sealed class ClassificationFailedException : Exception
{
    public ClassificationFailedException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
