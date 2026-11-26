using Schiza.Domain;
using Schiza.Application.Legacy;
using Schiza.Shared.Requests;

namespace Schiza.Application;

public interface IAnomalyDetector : IClassifier
{
}

public interface IClassifier
{
    Task<Legacy.ClassificationResult> ClassifyAsync(ApacheRequest request, CancellationToken cancellationToken);
}

public interface IFlaggedEventRepository
{
    Task<FlaggedEvent?> GetAsync(long id, CancellationToken cancellationToken);
    Task<(IReadOnlyList<FlaggedEvent> Items, int Total)> QueryAsync(EventQuery query, CancellationToken cancellationToken);
    Task<FlaggedEvent?> AddIfNewAsync(ApacheRequest request, string rawLogLine, ClassificationResult classification, EventSource source, CancellationToken cancellationToken);
    Task<int> DeleteOlderThanAsync(DateTimeOffset cutoffUtc, CancellationToken cancellationToken);
}

public interface IPasswordVerifier
{
    bool Verify(string password, string encodedHash);
}
