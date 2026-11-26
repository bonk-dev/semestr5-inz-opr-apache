using System.Text.Json;

using Schiza.Domain;
using Schiza.Shared.Requests;

namespace Schiza.Application;

public interface IAnomalyDetector
{
    Task<JsonDocument> PredictAsync(ApacheRequest request, CancellationToken cancellationToken);
}

public interface IFlaggedEventRepository
{
    Task<FlaggedEvent?> GetAsync(long id, CancellationToken cancellationToken);
    Task<(IReadOnlyList<FlaggedEvent> Items, int Total)> QueryAsync(int page, int pageSize, string? severity, CancellationToken cancellationToken);
    Task<FlaggedEvent?> AddIfNewAsync(ApacheRequest request, string rawLogLine, JsonDocument detection, CancellationToken cancellationToken);
    Task<int> DeleteOlderThanAsync(DateTimeOffset cutoffUtc, CancellationToken cancellationToken);
}

public interface IPasswordVerifier
{
    bool Verify(string password, string encodedHash);
}
