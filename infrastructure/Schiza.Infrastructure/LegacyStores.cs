using System.Text.RegularExpressions;
using Schiza.Application.Legacy;
using Schiza.Shared.Requests;

namespace Schiza.Infrastructure;

public sealed class InMemoryRuleStore : IRuleStore
{
    private readonly Lock _lock = new();
    private readonly SortedDictionary<int, StaticRule> _rules = [];
    private readonly TimeProvider _time;
    private int _nextId = 1;

    public InMemoryRuleStore() : this(TimeProvider.System) { }
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
    public IReadOnlyList<StaticRule> GetAll() { lock (_lock) return [.. _rules.Values]; }
    public StaticRule? Get(int id) { lock (_lock) return _rules.GetValueOrDefault(id); }
    public StaticRule Add(CreateRuleRequest request) { lock (_lock) { StaticRule rule = new(_nextId++, request.Name, request.Description, request.Field ?? throw new ArgumentException("Field is required"), request.MatchType, request.Pattern, request.Score, request.IsActive, _time.GetUtcNow()); _rules.Add(rule.Id, rule); return rule; } }
    public StaticRule? SetActive(int id, bool isActive) { lock (_lock) return !_rules.TryGetValue(id, out StaticRule? rule) ? null : (_rules[id] = rule with { IsActive = isActive }); }
    public bool Remove(int id) { lock (_lock) return _rules.Remove(id); }
}

public sealed class InMemoryEventStore(TimeProvider time) : IEventStore
{
    private readonly Lock _lock = new();
    private readonly LinkedList<SecurityEvent> _events = [];
    private int _nextId = 1;
    public SecurityEvent Add(ApacheRequest request, ClassificationResult classification) { lock (_lock) { SecurityEvent item = new(_nextId++, time.GetUtcNow(), request.Response is null ? EventSource.BlockingModule : EventSource.LogAnalysis, request, classification); _events.AddFirst(item); if (_events.Count > 1000) _events.RemoveLast(); return item; } }
    public SecurityEvent? Get(int id) { lock (_lock) return _events.FirstOrDefault(e => e.Id == id); }
    public EventPage Query(EventQuery query) { lock (_lock) { List<SecurityEvent> result = [.. _events.Where(e => Matches(e, query))]; return new([.. result.Skip(query.Skip).Take(query.Take)], result.Count); } }
    private static bool Matches(SecurityEvent e, EventQuery q) => (q.From is null || e.Request.Timestamp >= q.From) && (q.To is null || e.Request.Timestamp < q.To) && (q.ClientIp is null || e.Request.ClientIp.Equals(q.ClientIp)) && (q.RuleId is null || e.Classification.RuleId == q.RuleId) && (q.Source is null || e.Source == q.Source);
}

public sealed class StaticRuleClassifier(IRuleStore rules) : IRequestClassifier
{
    public ClassificationResult Classify(ApacheRequest request)
    {
        if (request.RequestLine.Kind != RequestLineKind.Parsed) return new(Verdict.Unsafe, .9, $"Request line {request.RequestLine.Kind}", null);
        StaticRule? best = rules.GetAll().Where(r => r.IsActive && RuleMatcher.IsMatch(r, request)).MaxBy(r => r.Score);
        return best is null ? ClassificationResult.Safe : new(best.Score >= .5 ? Verdict.Unsafe : Verdict.Safe, best.Score, best.Name, best.Id);
    }
}

public static class RuleMatcher
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(20);
    private static readonly RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    public static bool IsMatch(StaticRule rule, ApacheRequest request)
    {
        string? value = rule.Field switch { RuleField.Path => request.RequestLine.Path, RuleField.Query => request.RequestLine.Query, RuleField.RequestLine => request.RequestLine.Raw, RuleField.UserAgent => request.UserAgent, RuleField.Referer => request.Referer, RuleField.Host => request.Host, _ => null };
        if (value is null) return false;
        if (rule.MatchType == RuleMatchType.Contains) return value.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase);
        try { return Regex.IsMatch(value, rule.Pattern, Options, Timeout); } catch (RegexMatchTimeoutException) { return false; }
    }
    public static bool TryValidatePattern(RuleMatchType type, string pattern, out string? error) { error = null; if (type != RuleMatchType.Regex) return true; try { _ = new Regex(pattern, Options, Timeout); return true; } catch (ArgumentException e) { error = e.Message; return false; } }
}
