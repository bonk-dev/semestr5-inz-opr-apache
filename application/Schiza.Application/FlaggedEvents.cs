using System.Text.Json;
using Microsoft.Extensions.Logging;
using Schiza.Domain;
using Schiza.Shared.Requests;

namespace Schiza.Application;

public sealed class LogEventProcessor(IAnomalyDetector detector, IFlaggedEventRepository repository, ILogger<LogEventProcessor> logger)
{
    public async Task ProcessAsync(ApacheRequest request, string rawLogLine, CancellationToken cancellationToken)
    {
        try
        {
            using JsonDocument result = await detector.PredictAsync(request, cancellationToken);
            if (result.RootElement.TryGetProperty("is_anomaly", out JsonElement flag) && flag.ValueKind == JsonValueKind.True)
                await repository.AddIfNewAsync(request, rawLogLine, result, cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or InvalidOperationException)
        {
            logger.LogError(exception, "Błąd przetwarzania zdarzenia przez moduł detekcji");
        }
    }
}

public sealed class FlaggedEventQueries(IFlaggedEventRepository repository)
{
    public Task<(IReadOnlyList<FlaggedEvent> Items, int Total)> ListAsync(int page, int pageSize, string? severity, CancellationToken cancellationToken) => repository.QueryAsync(page, pageSize, severity, cancellationToken);
    public Task<FlaggedEvent?> GetAsync(long id, CancellationToken cancellationToken) => repository.GetAsync(id, cancellationToken);
}
