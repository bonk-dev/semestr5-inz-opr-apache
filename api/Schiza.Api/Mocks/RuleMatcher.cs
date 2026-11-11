using System.Text.RegularExpressions;

using Schiza.Api.Contracts;
using Schiza.Shared.Requests;

namespace Schiza.Api.Mocks;

public static class RuleMatcher
{
    private const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(20);

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
            _ => null,
        };
        if (value is null)
        {
            return false;
        }

        if (rule.MatchType == RuleMatchType.Contains)
        {
            return value.Contains(rule.Pattern, StringComparison.OrdinalIgnoreCase);
        }

        try
        {
            return Regex.IsMatch(value, rule.Pattern, Options, MatchTimeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    public static bool TryValidatePattern(RuleMatchType matchType, string pattern, out string? error)
    {
        error = null;
        if (matchType != RuleMatchType.Regex)
        {
            return true;
        }

        try
        {
            _ = new Regex(pattern, Options, MatchTimeout);
            return true;
        }
        catch (ArgumentException e)
        {
            error = e.Message;
            return false;
        }
    }
}
