using System.Net;
using System.Text.Json;

using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

using Schiza.Domain;
using Schiza.Infrastructure;
using Schiza.Shared.Requests;

namespace Schiza.Api.Tests;

public sealed class SqliteFlaggedEventRepositoryTests
{
    [Fact]
    public async Task WritesAndReadsFlaggedEvent()
    {
        string directory = Path.Combine(Path.GetTempPath(), "schiza-tests", Guid.NewGuid().ToString("N"));
        string databasePath = Path.Combine(directory, "events.db");
        try
        {
            IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Storage:DatabasePath"] = databasePath
            }).Build();
            SqliteFlaggedEventRepository repository = new(configuration, TimeProvider.System, NullLogger<SqliteFlaggedEventRepository>.Instance);
            await repository.InitializeAsync(CancellationToken.None);
            ApacheRequest request = new(IPAddress.Loopback, DateTimeOffset.UtcNow,
                new RequestLine(RequestLineKind.Parsed, "GET /attack HTTP/1.1", "GET", "/attack", null, "HTTP/1.1"),
                null, "test-agent", "localhost", null, null, null);
            using JsonDocument detection = JsonDocument.Parse("{\"is_anomaly\":true,\"severity\":\"high\",\"xai\":{\"reason\":\"test\"}}");

            FlaggedEvent? saved = await repository.AddIfNewAsync(request, "raw apache line", detection, CancellationToken.None);
            FlaggedEvent? loaded = await repository.GetAsync(saved!.Id, CancellationToken.None);

            Assert.NotNull(loaded);
            Assert.Equal("raw apache line", loaded.RawLogLine);
            Assert.Contains("xai", loaded.DetectionJson, StringComparison.Ordinal);
            Assert.Equal("LogAnalysis", loaded.Source);
            SqliteFlaggedEventRepository reopened = new(configuration, TimeProvider.System, NullLogger<SqliteFlaggedEventRepository>.Instance);
            await reopened.InitializeAsync(CancellationToken.None);
            Assert.NotNull(await reopened.GetAsync(saved.Id, CancellationToken.None));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task DeletesOnlyEventsOlderThanCutoff()
    {
        string directory = Path.Combine(Path.GetTempPath(), "schiza-tests", Guid.NewGuid().ToString("N"));
        string databasePath = Path.Combine(directory, "events.db");
        try
        {
            IConfiguration configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Storage:DatabasePath"] = databasePath
            }).Build();
            SqliteFlaggedEventRepository repository = new(configuration, TimeProvider.System, NullLogger<SqliteFlaggedEventRepository>.Instance);
            await repository.InitializeAsync(CancellationToken.None);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            ApacheRequest template = new(IPAddress.Loopback, now,
                new RequestLine(RequestLineKind.Parsed, "GET /retention HTTP/1.1", "GET", "/retention", null, "HTTP/1.1"),
                null, "test-agent", "localhost", null, null, null);
            using JsonDocument detection = JsonDocument.Parse("{\"is_anomaly\":true,\"severity\":\"high\"}");

            await repository.AddIfNewAsync(template with { Timestamp = now.AddDays(-31) }, "old apache line", detection, CancellationToken.None);
            FlaggedEvent? recent = await repository.AddIfNewAsync(template with { Timestamp = now.AddDays(-29) }, "recent apache line", detection, CancellationToken.None);

            int deleted = await repository.DeleteOlderThanAsync(now.AddDays(-30), CancellationToken.None);

            Assert.Equal(1, deleted);
            Assert.Null(await repository.GetAsync(recent!.Id - 1, CancellationToken.None));
            Assert.NotNull(await repository.GetAsync(recent.Id, CancellationToken.None));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}
