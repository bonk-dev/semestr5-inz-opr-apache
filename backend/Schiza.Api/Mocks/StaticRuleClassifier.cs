using Schiza.Api.Contracts;
using Schiza.Shared.Requests;

namespace Schiza.Api.Mocks;

public sealed class StaticRuleClassifier(IRuleStore rules) : IRequestClassifier
{
    public const double UnsafeThreshold = 0.5;

    public ClassificationResult Classify(ApacheRequest request)
    {
        if (request.RequestLine.Kind != RequestLineKind.Parsed)
        {
            return new ClassificationResult(Verdict.Unsafe, 0.9, $"Request line {request.RequestLine.Kind}", null);
        }

        StaticRule? best = rules.GetAll()
            .Where(r => r.IsActive && RuleMatcher.IsMatch(r, request))
            .MaxBy(r => r.Score);
        if (best is null)
        {
            return ClassificationResult.Safe;
        }

        Verdict verdict = best.Score >= UnsafeThreshold ? Verdict.Unsafe : Verdict.Safe;
        return new ClassificationResult(verdict, best.Score, best.Name, best.Id);
    }
}
