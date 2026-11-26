using Schiza.Application;
using Schiza.Application.Legacy;
using Schiza.Shared.Requests;

namespace Schiza.Infrastructure;

public sealed class StaticRuleClassifier(IRuleStore rules) : IRequestClassifier
{
    public Task<ClassificationResult> ClassifyAsync(ApacheRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        StaticRule? best = rules.GetAll().Where(rule => rule.IsActive && StaticRuleMatcher.IsMatch(rule, request)).MaxBy(rule => rule.Score);
        ClassificationResult result = best is null
            ? ClassificationResult.Safe
            : new(best.Score >= .5 ? Verdict.Unsafe : Verdict.Safe, best.Score, best.Name, best.Id, true);
        return Task.FromResult(result);
    }
}
