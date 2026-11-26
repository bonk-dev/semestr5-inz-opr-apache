using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using Schiza.Application;
using Schiza.LogEngine.Parsing;
using Schiza.Shared.Requests;

namespace Schiza.Infrastructure;

public sealed class ApacheLogWorker(IConfiguration configuration, IApacheLogParser parser, LogEventProcessor processor, ILogger<ApacheLogWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        string? path = configuration["ApacheLog:Path"];
        if (string.IsNullOrWhiteSpace(path)) { logger.LogInformation("ApacheLog:Path nie jest skonfigurowane"); return; }
        long position = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (File.Exists(path))
                {
                    using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                    if (stream.Length < position) position = 0;
                    stream.Seek(position, SeekOrigin.Begin);
                    using StreamReader reader = new(stream);
                    while (await reader.ReadLineAsync(stoppingToken) is { } line)
                    {
                        switch (parser.Parse(line))
                        {
                            case LogParseResult.Parsed parsed: await processor.ProcessAsync(parsed.Request, line, stoppingToken); break;
                            case LogParseResult.Unparseable error: logger.LogWarning("Nie można sparsować wpisu Apache: {Error}", error.Error); break;
                        }
                    }
                    position = stream.Position;
                }
                await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
            catch (Exception exception) { logger.LogError(exception, "Błąd monitorowania logu Apache"); await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
        }
    }
}

public sealed class FlaggedEventRetentionWorker(IFlaggedEventRepository repository, TimeProvider time, ILogger<FlaggedEventRetentionWorker> logger) : BackgroundService
{
    private static readonly TimeSpan RetentionPeriod = TimeSpan.FromDays(30);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await CleanupAsync(stoppingToken);
        using PeriodicTimer timer = new(TimeSpan.FromDays(1));
        try { while (await timer.WaitForNextTickAsync(stoppingToken)) await CleanupAsync(stoppingToken); }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    private async Task CleanupAsync(CancellationToken cancellationToken)
    {
        try { await repository.DeleteOlderThanAsync(time.GetUtcNow() - RetentionPeriod, cancellationToken); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception exception) { logger.LogError(exception, "Nie udało się wykonać czyszczenia retencji zdarzeń"); }
    }
}
