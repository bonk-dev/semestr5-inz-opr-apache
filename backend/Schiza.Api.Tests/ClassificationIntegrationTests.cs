using System.Net;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Schiza.Application;
using Schiza.Application.Legacy;
using Schiza.Infrastructure;
using Schiza.Shared.Requests;

namespace Schiza.Api.Tests;

public sealed class ClassificationIntegrationTests
{
    [Fact]
    public async Task StaticRuleMatchesRequestBody()
    {
        FakeRuleStore rules = new(new StaticRule(1, "Body attack", null, RuleField.Body, RuleMatchType.Contains, "DROP TABLE", 1, true, DateTimeOffset.UtcNow));
        StaticRuleClassifier classifier = new(rules);
        ClassificationResult result = await classifier.ClassifyAsync(Request(body: "DROP TABLE users"), CancellationToken.None);

        Assert.True(result.StaticRulesMatched);
        Assert.Equal(Verdict.Unsafe, result.Verdict);
        Assert.Equal(1, result.RuleId);
    }

    [Fact]
    public async Task DisabledRuleDoesNotMatch()
    {
        FakeRuleStore rules = new(new StaticRule(1, "Body attack", null, RuleField.Body, RuleMatchType.Contains, "DROP TABLE", 1, false, DateTimeOffset.UtcNow));
        StaticRuleClassifier classifier = new(rules);

        ClassificationResult result = await classifier.ClassifyAsync(Request(body: "DROP TABLE users"), CancellationToken.None);

        Assert.False(result.StaticRulesMatched);
        Assert.Equal(Verdict.Safe, result.Verdict);
    }

    [Fact]
    public async Task CombinedClassifierUsesOrAndPreservesAnomalyScore()
    {
        StaticRuleClassifier staticClassifier = new(new FakeRuleStore(new StaticRule(1, "Path attack", null, RuleField.Path, RuleMatchType.Contains, "/attack", 1, true, DateTimeOffset.UtcNow)));
        FakeAnomalyDetector detector = new(new ClassificationResult(Verdict.Safe, .271828, "Autoencoder", null, false, false, .271828, "{\"is_anomaly\":false,\"anomaly_score\":0.271828}"));
        CombinedRequestClassifier classifier = new(staticClassifier, detector);

        ClassificationResult result = await classifier.ClassifyAsync(Request(path: "/attack"), CancellationToken.None);

        Assert.Equal(Verdict.Unsafe, result.Verdict);
        Assert.True(result.StaticRulesMatched);
        Assert.False(result.AutoencoderThresholdExceeded);
        Assert.Equal(.271828, result.AnomalyScore);
        Assert.Contains("anomaly_score", result.DetectionJson, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AutoencoderDetectionMakesSafeStaticResultUnsafe()
    {
        CombinedRequestClassifier classifier = new(
            new StaticRuleClassifier(new FakeRuleStore()),
            new FakeAnomalyDetector(new ClassificationResult(Verdict.Unsafe, .812345, "Autoencoder", null, false, true, .812345, "{\"is_anomaly\":true,\"anomaly_score\":0.812345}")));

        ClassificationResult result = await classifier.ClassifyAsync(Request(), CancellationToken.None);

        Assert.Equal(Verdict.Unsafe, result.Verdict);
        Assert.True(result.AutoencoderThresholdExceeded);
        Assert.Equal(.812345, result.AnomalyScore);
    }

    [Fact]
    public async Task RuleActivityIsPersistent()
    {
        string directory = Path.Combine(Path.GetTempPath(), "schiza-tests", Guid.NewGuid().ToString("N"));
        string databasePath = Path.Combine(directory, "rules.db");
        try
        {
            IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["Storage:DatabasePath"] = databasePath }).Build();
            SqliteRuleStore first = new(configuration, TimeProvider.System);
            await first.InitializeAsync(CancellationToken.None);
            StaticRule rule = first.Add(new("Persistent", null, RuleField.Body, RuleMatchType.Contains, "blocked"));
            Assert.NotNull(first.SetActive(rule.Id, false));

            SqliteRuleStore second = new(configuration, TimeProvider.System);
            await second.InitializeAsync(CancellationToken.None);
            Assert.False(second.Get(rule.Id)!.IsActive);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, true);
        }
    }

    private static ApacheRequest Request(string path = "/", string? body = null) => new(
        IPAddress.Loopback,
        DateTimeOffset.UtcNow,
        new RequestLine(RequestLineKind.Parsed, $"GET {path} HTTP/1.1", "GET", path, null, "HTTP/1.1"),
        null, "test", "localhost", null, null, null,
        body is null ? null : new RequestBody("text/plain", body));

    private sealed class FakeRuleStore(params StaticRule[] rules) : IRuleStore
    {
        private readonly List<StaticRule> _rules = [.. rules];
        public IReadOnlyList<StaticRule> GetAll() => _rules;
        public StaticRule? Get(int id) => _rules.SingleOrDefault(rule => rule.Id == id);
        public StaticRule Add(CreateRuleRequest request) => throw new NotSupportedException();
        public StaticRule? SetActive(int id, bool isActive) => throw new NotSupportedException();
        public bool Remove(int id) => throw new NotSupportedException();
    }

    private sealed class FakeAnomalyDetector(ClassificationResult result) : IAnomalyDetector
    {
        public Task<ClassificationResult> ClassifyAsync(ApacheRequest request, CancellationToken cancellationToken) => Task.FromResult(result);
        public Task<JsonDocument> PredictAsync(ApacheRequest request, CancellationToken cancellationToken) => Task.FromResult(JsonDocument.Parse(result.DetectionJson ?? "{}"));
    }
}
