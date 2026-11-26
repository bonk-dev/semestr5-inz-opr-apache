using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;

using Schiza.Application.Legacy;
using Schiza.Shared.Requests;

namespace Schiza.Infrastructure;

public sealed class SqliteRuleStore(IConfiguration configuration, TimeProvider time) : IRuleStore
{
    private readonly string _connectionString = new SqliteConnectionStringBuilder
    {
        DataSource = configuration["Storage:DatabasePath"] ?? "App_Data/schiza.db",
        Mode = SqliteOpenMode.ReadWriteCreate,
    }.ToString();
    private readonly Lock _lock = new();

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        string? directory = Path.GetDirectoryName(new SqliteConnectionStringBuilder(_connectionString).DataSource);
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        await using SqliteConnection connection = new(_connectionString);
        await connection.OpenAsync(cancellationToken);
        await using SqliteCommand command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS StaticRules (
                Id INTEGER PRIMARY KEY AUTOINCREMENT, Name TEXT NOT NULL, Description TEXT NULL,
                Field TEXT NOT NULL, MatchType TEXT NOT NULL, Pattern TEXT NOT NULL,
                Score REAL NOT NULL, IsActive INTEGER NOT NULL, CreatedAt TEXT NOT NULL
            );
            """;
        await command.ExecuteNonQueryAsync(cancellationToken);
        await SeedAsync(connection, cancellationToken);
    }

    public IReadOnlyList<StaticRule> GetAll()
    {
        lock (_lock) return ReadRules();
    }

    public StaticRule? Get(int id)
    {
        lock (_lock) return ReadRules("WHERE Id = $id", [new SqliteParameter("$id", id)]).SingleOrDefault();
    }

    public StaticRule Add(CreateRuleRequest request)
    {
        ArgumentNullException.ThrowIfNull(request.Field);
        lock (_lock)
        {
            DateTimeOffset createdAt = time.GetUtcNow();
            using SqliteConnection connection = Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO StaticRules (Name, Description, Field, MatchType, Pattern, Score, IsActive, CreatedAt)
                VALUES ($name, $description, $field, $matchType, $pattern, $score, $active, $createdAt);
                SELECT last_insert_rowid();
                """;
            AddParameters(command, request.Name, request.Description, request.Field.Value, request.MatchType, request.Pattern, request.Score, request.IsActive, createdAt);
            int id = Convert.ToInt32(command.ExecuteScalar());
            return new(id, request.Name, request.Description, request.Field.Value, request.MatchType, request.Pattern, request.Score, request.IsActive, createdAt);
        }
    }

    public StaticRule? SetActive(int id, bool isActive)
    {
        lock (_lock)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "UPDATE StaticRules SET IsActive = $active WHERE Id = $id";
            command.Parameters.AddWithValue("$active", isActive ? 1 : 0);
            command.Parameters.AddWithValue("$id", id);
            return command.ExecuteNonQuery() == 0 ? null : Get(id);
        }
    }

    public bool Remove(int id)
    {
        lock (_lock)
        {
            using SqliteConnection connection = Open();
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "DELETE FROM StaticRules WHERE Id = $id";
            command.Parameters.AddWithValue("$id", id);
            return command.ExecuteNonQuery() != 0;
        }
    }

    private List<StaticRule> ReadRules(string where = "", params SqliteParameter[] parameters)
    {
        using SqliteConnection connection = Open();
        using SqliteCommand command = connection.CreateCommand();
        command.CommandText = $"SELECT Id, Name, Description, Field, MatchType, Pattern, Score, IsActive, CreatedAt FROM StaticRules {where} ORDER BY Id";
        command.Parameters.AddRange(parameters);
        using SqliteDataReader reader = command.ExecuteReader();
        List<StaticRule> rules = [];
        while (reader.Read())
        {
            rules.Add(new(reader.GetInt32(0), reader.GetString(1), reader.IsDBNull(2) ? null : reader.GetString(2),
                Enum.Parse<RuleField>(reader.GetString(3)), Enum.Parse<RuleMatchType>(reader.GetString(4)), reader.GetString(5),
                reader.GetDouble(6), reader.GetInt64(7) != 0, DateTimeOffset.Parse(reader.GetString(8))));
        }
        return rules;
    }

    private SqliteConnection Open()
    {
        SqliteConnection connection = new(_connectionString);
        connection.Open();
        return connection;
    }

    private async Task SeedAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        using SqliteCommand count = connection.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM StaticRules";
        if (Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken)) != 0) return;
        foreach (CreateRuleRequest rule in DefaultRules)
        {
            using SqliteCommand command = connection.CreateCommand();
            command.CommandText = "INSERT INTO StaticRules (Name, Description, Field, MatchType, Pattern, Score, IsActive, CreatedAt) VALUES ($name, $description, $field, $matchType, $pattern, $score, $active, $createdAt)";
            AddParameters(command, rule.Name, rule.Description, rule.Field!.Value, rule.MatchType, rule.Pattern, rule.Score, rule.IsActive, time.GetUtcNow());
            await command.ExecuteNonQueryAsync(cancellationToken);
        }
    }

    private static void AddParameters(SqliteCommand command, string name, string? description, RuleField field, RuleMatchType matchType, string pattern, double score, bool active, DateTimeOffset createdAt)
    {
        command.Parameters.AddWithValue("$name", name);
        command.Parameters.AddWithValue("$description", (object?)description ?? DBNull.Value);
        command.Parameters.AddWithValue("$field", field.ToString());
        command.Parameters.AddWithValue("$matchType", matchType.ToString());
        command.Parameters.AddWithValue("$pattern", pattern);
        command.Parameters.AddWithValue("$score", score);
        command.Parameters.AddWithValue("$active", active ? 1 : 0);
        command.Parameters.AddWithValue("$createdAt", createdAt.ToString("O"));
    }

    private static readonly CreateRuleRequest[] DefaultRules =
    [
        new("Path traversal", "../ and URL-encoded forms", RuleField.Path, RuleMatchType.Regex, @"\.\./|\.\.%2f|%2e%2e|\.%2e"),
        new("/etc/passwd", null, RuleField.RequestLine, RuleMatchType.Contains, "/etc/passwd"),
        new("Environment file", "Probing for leaked .env files", RuleField.Path, RuleMatchType.Contains, "/.env"),
        new("Git repository", "Probing for an exposed .git directory", RuleField.Path, RuleMatchType.Contains, "/.git"),
        new("WordPress login", "We do not run WordPress", RuleField.Path, RuleMatchType.Contains, "/wp-login.php", .8),
        new("Scanner user agent", null, RuleField.UserAgent, RuleMatchType.Regex, "sqlmap|nikto|zgrab|masscan|nmap|l9scan", .95),
        new("phpMyAdmin", "Disabled example rule", RuleField.Path, RuleMatchType.Contains, "/phpmyadmin", .7, false),
    ];

}
