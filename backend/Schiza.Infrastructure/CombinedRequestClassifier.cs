using System.Text.Json;
using Schiza.Application;
using Schiza.Application.Legacy;
using Schiza.Shared.Requests;

namespace Schiza.Infrastructure;

public sealed class CombinedRequestClassifier(StaticRuleClassifier staticRules, IAnomalyDetector autoencoder) : IRequestClassifier
{
    public async Task<ClassificationResult> ClassifyAsync(ApacheRequest request, CancellationToken cancellationToken)
    {
        ClassificationResult staticResult = await staticRules.ClassifyAsync(request, cancellationToken);
        ClassificationResult autoencoderResult = await autoencoder.ClassifyAsync(request, cancellationToken);
        bool isAnomaly = staticResult.StaticRulesMatched || autoencoderResult.AutoencoderThresholdExceeded;
        string? detectionJson = autoencoderResult.DetectionJson;
        string? reason = staticResult.StaticRulesMatched && autoencoderResult.AutoencoderThresholdExceeded
            ? $"{staticResult.Reason}; {autoencoderResult.Reason}"
            : staticResult.StaticRulesMatched ? staticResult.Reason : autoencoderResult.Reason;
        double score = autoencoderResult.AnomalyScore ?? staticResult.Score;
        return new(
            isAnomaly ? Verdict.Unsafe : Verdict.Safe,
            score,
            reason,
            staticResult.RuleId,
            staticResult.StaticRulesMatched,
            autoencoderResult.AutoencoderThresholdExceeded,
            autoencoderResult.AnomalyScore,
            detectionJson);
    }
}
