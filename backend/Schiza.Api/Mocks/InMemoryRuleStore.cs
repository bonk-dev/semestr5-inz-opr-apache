using Schiza.Api.Contracts;

namespace Schiza.Api.Mocks;

public sealed class InMemoryRuleStore : IRuleStore
{
    private readonly Lock _lock = new();
    private readonly SortedDictionary<int, StaticRule> _rules = [];
    private readonly TimeProvider _time;
    private int _nextId = 1;

    public InMemoryRuleStore(TimeProvider time)
    {
        _time = time;

        Add(new("Path traversal", "../ and its URL-encoded forms", RuleField.Path, RuleMatchType.Regex, @"\.\./|\.\.%2f|%2e%2e|\.%2e", 1.0, true));
        Add(new("/etc/passwd", null, RuleField.RequestLine, RuleMatchType.Contains, "/etc/passwd", 1.0, true));
        Add(new("Environment file", "Probing for leaked .env files", RuleField.Path, RuleMatchType.Contains, "/.env", 1.0, true));
        Add(new("Git repository", "Probing for an exposed .git directory", RuleField.Path, RuleMatchType.Contains, "/.git", 1.0, true));
        Add(new("WordPress login", "We do not run WordPress", RuleField.Path, RuleMatchType.Contains, "/wp-login.php", 0.8, true));
        Add(new("Scanner user agent", null, RuleField.UserAgent, RuleMatchType.Regex, "sqlmap|nikto|zgrab|masscan|nmap|l9scan", 0.95, true));
        Add(new("phpMyAdmin", "Disabled example rule", RuleField.Path, RuleMatchType.Contains, "/phpmyadmin", 0.7, false));
    }

    public IReadOnlyList<StaticRule> GetAll()
    {
        lock (_lock)
        {
            return [.. _rules.Values];
        }
    }

    public StaticRule? Get(int id)
    {
        lock (_lock)
        {
            return _rules.GetValueOrDefault(id);
        }
    }

    public StaticRule Add(CreateRuleRequest request)
    {
        lock (_lock)
        {
            StaticRule rule = new(
                _nextId++,
                request.Name,
                request.Description,
                request.Field ?? throw new ArgumentException("Field is required", nameof(request)),
                request.MatchType,
                request.Pattern,
                request.Score,
                request.IsActive,
                _time.GetUtcNow());
            _rules.Add(rule.Id, rule);
            return rule;
        }
    }

    public StaticRule? SetActive(int id, bool isActive)
    {
        lock (_lock)
        {
            return !_rules.TryGetValue(id, out StaticRule? rule)
                ? null
                : (_rules[id] = rule with { IsActive = isActive });
        }
    }

    public bool Remove(int id)
    {
        lock (_lock)
        {
            return _rules.Remove(id);
        }
    }
}
