using Microsoft.Extensions.Logging;
using Schiza.Domain;
using Schiza.Application.Legacy;
using Schiza.Shared.Requests;

namespace Schiza.Application;

public sealed class LogEventProcessor(IRequestClassifier classifier, IFlaggedEventRepository repository, ILogger<LogEventProcessor> logger)
{
    public async Task ProcessAsync(ApacheRequest request, string rawLogLine, CancellationToken cancellationToken)
    {
        try
        {
            ClassificationResult result = await classifier.ClassifyAsync(request, cancellationToken);
            if (result.Verdict == Verdict.Unsafe)
                await repository.AddIfNewAsync(request, rawLogLine, result, EventSource.LogAnalysis, cancellationToken);
        }
        catch (ClassificationFailedException exception)
        {
            logger.LogError(exception, "Błąd przetwarzania zdarzenia przez moduł detekcji");
        }
    }
}

public sealed class FlaggedEventQueries(IFlaggedEventRepository repository)
{
    public Task<(IReadOnlyList<FlaggedEvent> Items, int Total)> ListAsync(EventQuery query, CancellationToken cancellationToken) => repository.QueryAsync(query, cancellationToken);
    public Task<FlaggedEvent?> GetAsync(long id, CancellationToken cancellationToken) => repository.GetAsync(id, cancellationToken);
}

public sealed record FlaggedEventPage(IReadOnlyList<FlaggedEvent> Items, int Total);
