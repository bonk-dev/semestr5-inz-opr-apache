using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

using Schiza.Application;
using Schiza.Application.Legacy;
using Schiza.Domain;
using Schiza.Shared.Requests;

namespace Schiza.Infrastructure;

public sealed class SqliteFlaggedEventRepository(IConfiguration configuration, TimeProvider time, ILogger<SqliteFlaggedEventRepository> logger) : IFlaggedEventRepository
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = configuration["Storage:DatabasePath"] ?? "App_Data/schiza.db",
        Mode = SqliteOpenMode.ReadWriteCreate,
    }.ToString();

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        string? directory = Path.GetDirectoryName(new SqliteConnectionStringBuilder(_connectionString).DataSource);
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS FlaggedEvents (
                Id INTEGER PRIMARY KEY AUTOINCREMENT, EventTimeUtc TEXT NOT NULL, DetectedAtUtc TEXT NOT NULL,
                RawLogLine TEXT NOT NULL, RequestJson TEXT NOT NULL, DetectionJson TEXT NOT NULL,
                Severity TEXT NOT NULL, Method TEXT NOT NULL, Url TEXT NOT NULL, ClientIp TEXT NOT NULL,
                Source TEXT NOT NULL DEFAULT 'LogAnalysis',
                EventKey TEXT NOT NULL UNIQUE
            );
            CREATE INDEX IF NOT EXISTS IX_FlaggedEvents_EventTimeUtc ON FlaggedEvents(EventTimeUtc DESC);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        try
        {
            await using SqliteCommand migration = connection.CreateCommand();
            migration.CommandText = "ALTER TABLE FlaggedEvents ADD COLUMN Source TEXT NOT NULL DEFAULT 'LogAnalysis'";
            await migration.ExecuteNonQueryAsync(cancellationToken);
        }
        catch (SqliteException) { }
    }

    public Task<FlaggedEvent?> AddIfNewAsync(ApacheRequest request, string rawLogLine, JsonDocument detection, CancellationToken cancellationToken)
    {
        using JsonDocument document = JsonDocument.Parse(detection.RootElement.GetRawText());
        bool isAnomaly = document.RootElement.TryGetProperty("is_anomaly", out JsonElement flag) && flag.ValueKind == JsonValueKind.True;
        double score = document.RootElement.TryGetProperty("anomaly_score", out JsonElement scoreElement) && scoreElement.ValueKind == JsonValueKind.Number ? scoreElement.GetDouble() : 1.0;
        ClassificationResult classification = new(isAnomaly ? Verdict.Unsafe : Verdict.Safe, score, null, null, false, isAnomaly, isAnomaly ? score : null, document.RootElement.GetRawText());
        return AddIfNewAsync(request, rawLogLine, classification, EventSource.LogAnalysis, cancellationToken);
    }

    public async Task<FlaggedEvent?> AddIfNewAsync(ApacheRequest request, string rawLogLine, ClassificationResult classification, EventSource source, CancellationToken cancellationToken)
    {
        string requestJson = JsonSerializer.Serialize(request, JsonSerializerOptions.Web);
        string detectionJson = classification.DetectionJson ?? JsonSerializer.Serialize(new
        {
            is_anomaly = classification.Verdict == Verdict.Unsafe,
            anomaly_score = classification.AnomalyScore,
            static_rules_matched = classification.StaticRulesMatched,
            autoencoder_threshold_exceeded = classification.AutoencoderThresholdExceeded,
            reason = classification.Reason,
            rule_id = classification.RuleId,
        }, JsonSerializerOptions.Web);
        string key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source.ToString() + "|" + rawLogLine)));
        string severity = classification.Verdict == Verdict.Unsafe ? "high" : "safe";
        try
        {
            await using SqliteConnection connection = new(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = """
                INSERT OR IGNORE INTO FlaggedEvents
                (EventTimeUtc, DetectedAtUtc, RawLogLine, RequestJson, DetectionJson, Severity, Method, Url, ClientIp, Source, EventKey)
                VALUES ($eventTime, $detectedAt, $raw, $request, $detection, $severity, $method, $url, $ip, $source, $key);
                SELECT Id, EventTimeUtc, DetectedAtUtc, RawLogLine, RequestJson, DetectionJson, Severity, Method, Url, ClientIp, Source
                FROM FlaggedEvents WHERE EventKey = $key;
                """;
            command.Parameters.AddWithValue("$eventTime", request.Timestamp.UtcDateTime.ToString("O"));
            command.Parameters.AddWithValue("$detectedAt", time.GetUtcNow().UtcDateTime.ToString("O"));
            command.Parameters.AddWithValue("$raw", rawLogLine);
            command.Parameters.AddWithValue("$request", requestJson);
            command.Parameters.AddWithValue("$detection", detectionJson);
            command.Parameters.AddWithValue("$severity", severity);
            command.Parameters.AddWithValue("$method", request.RequestLine.Method ?? "UNKNOWN");
            command.Parameters.AddWithValue("$url", request.RequestLine.Path ?? request.RequestLine.Raw);
            command.Parameters.AddWithValue("$ip", request.ClientIp.ToString());
            command.Parameters.AddWithValue("$source", source.ToString());
            command.Parameters.AddWithValue("$key", key);
            await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
            return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
        }
        catch (SqliteException exception) { logger.LogError(exception, "Nie udało się zapisać oflagowanego zdarzenia"); throw; }
    }

    public Task<FlaggedEvent?> GetAsync(long id, CancellationToken cancellationToken) => QuerySingleAsync("WHERE Id = $id", [new("$id", id)], cancellationToken);

    public async Task<int> DeleteOlderThanAsync(DateTimeOffset cutoffUtc, CancellationToken cancellationToken)
    {
        try
        {
            await using SqliteConnection connection = new(_connectionString);
            await connection.OpenAsync(cancellationToken);
            await using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "DELETE FROM FlaggedEvents WHERE EventTimeUtc < $cutoff";
            command.Parameters.AddWithValue("$cutoff", cutoffUtc.UtcDateTime.ToString("O"));
            int deleted = await command.ExecuteNonQueryAsync(cancellationToken);
            logger.LogInformation("Retencja zdarzeń: usunięto {DeletedCount} rekordów starszych niż {CutoffUtc}", deleted, cutoffUtc);
            return deleted;
        }
        catch (SqliteException exception) { logger.LogError(exception, "Błąd czyszczenia retencji"); throw; }
    }

    public async Task<(IReadOnlyList<FlaggedEvent> Items, int Total)> QueryAsync(EventQuery query, CancellationToken cancellationToken)
    {
        int offset = query.Skip;
        List<SqliteParameter> parameters = [];
        List<string> filters = [];
        if (query.From is { } from) { filters.Add("EventTimeUtc >= $from"); parameters.Add(new("$from", from.UtcDateTime.ToString("O"))); }
        if (query.To is { } to) { filters.Add("EventTimeUtc < $to"); parameters.Add(new("$to", to.UtcDateTime.ToString("O"))); }
        if (query.ClientIp is { } clientIp) { filters.Add("ClientIp = $clientIp"); parameters.Add(new("$clientIp", clientIp.ToString())); }
        if (query.Source is { } source) { filters.Add("Source = $source"); parameters.Add(new("$source", source.ToString())); }
        if (!string.IsNullOrWhiteSpace(query.Severity)) { filters.Add("Severity = $severity"); parameters.Add(new("$severity", query.Severity)); }
        if (query.RuleId is { } ruleId) { filters.Add("json_extract(DetectionJson, '$.rule_id') = $ruleId"); parameters.Add(new("$ruleId", ruleId)); }
        string filter = filters.Count == 0 ? "" : $"WHERE {string.Join(" AND ", filters)}";
        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using SqliteCommand count = connection.CreateCommand();
        count.CommandText = $"SELECT COUNT(*) FROM FlaggedEvents {filter}";
        count.Parameters.AddRange(parameters);
        int total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken));
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"SELECT Id, EventTimeUtc, DetectedAtUtc, RawLogLine, RequestJson, DetectionJson, Severity, Method, Url, ClientIp, Source FROM FlaggedEvents {filter} ORDER BY EventTimeUtc DESC LIMIT $limit OFFSET $offset";
        command.Parameters.AddRange(parameters);
        command.Parameters.AddWithValue("$limit", query.Take);
        command.Parameters.AddWithValue("$offset", offset);
        List<FlaggedEvent> items = [];
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken)) items.Add(Read(reader));
        return (items, total);
    }

    private async Task<FlaggedEvent?> QuerySingleAsync(string where, IEnumerable<SqliteParameter> parameters, CancellationToken cancellationToken)
    {
        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"SELECT Id, EventTimeUtc, DetectedAtUtc, RawLogLine, RequestJson, DetectionJson, Severity, Method, Url, ClientIp, Source FROM FlaggedEvents {where}";
        command.Parameters.AddRange(parameters);
        await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? Read(reader) : null;
    }

    private static FlaggedEvent Read(SqliteDataReader reader) => new(reader.GetInt64(0), DateTimeOffset.Parse(reader.GetString(1)), DateTimeOffset.Parse(reader.GetString(2)), reader.GetString(3), reader.GetString(4), reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.GetString(8), reader.GetString(9), reader.GetString(10));
}
