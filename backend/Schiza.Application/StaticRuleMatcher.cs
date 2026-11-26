using System.Text.RegularExpressions;

using Schiza.Shared.Requests;

namespace Schiza.Application.Legacy;

public static class StaticRuleMatcher
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(20);
    private static readonly RegexOptions RegexOptions = System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant;

    public static bool IsMatch(StaticRule rule, ApacheRequest request)
    {
        string? value = rule.Field switch
        {
            RuleField.Path => request.RequestLine.Path,
            RuleField.Query => request.RequestLine.Query,
            RuleField.RequestLine => request.RequestLine.Raw,
            RuleField.UserAgent => request.UserAgent,
            RuleField.Referer => request.Referer,
            RuleField.Host => request.Host,
            RuleField.Body => request.Body?.Content,
            _ => null,
        };
        if (value is null) return false;
        if (rule.MatchType == RuleMatchType.Contains) return value.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase);
        try { return Regex.IsMatch(value, rule.Pattern, RegexOptions, RegexTimeout); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    public static bool TryValidatePattern(RuleMatchType type, string pattern, out string? error)
    {
        error = null;
        if (type != RuleMatchType.Regex) return true;
        try { _ = new Regex(pattern, RegexOptions, RegexTimeout); return true; }
        catch (ArgumentException exception) { error = exception.Message; return false; }
    }
}
