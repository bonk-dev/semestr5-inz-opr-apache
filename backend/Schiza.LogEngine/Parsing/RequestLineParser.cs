using Schiza.Shared.Requests;

namespace Schiza.LogEngine.Parsing;

internal static class RequestLineParser
{
    public static RequestLine Parse(ReadOnlySpan<char> raw)
    {
        if (raw is "-")
        {
            return new RequestLine(RequestLineKind.Missing, "-");
        }

        string rawText = raw.ToString();
        int firstSpace = raw.IndexOf(' ');
        int lastSpace = raw.LastIndexOf(' ');
        if (firstSpace < 0 || firstSpace == lastSpace)
        {
            return new RequestLine(RequestLineKind.Malformed, rawText);
        }

        ReadOnlySpan<char> method = raw[..firstSpace];
        ReadOnlySpan<char> target = raw[(firstSpace + 1)..lastSpace];
        ReadOnlySpan<char> protocol = raw[(lastSpace + 1)..];
        if (!IsMethod(method) || target.IsEmpty || target.Contains(' ') || !IsHttpProtocol(protocol))
        {
            return new RequestLine(RequestLineKind.Malformed, rawText);
        }

        int queryStart = target.IndexOf('?');
        return new RequestLine(
            RequestLineKind.Parsed,
            rawText,
            method.ToString(),
            (queryStart < 0 ? target : target[..queryStart]).ToString(),
            queryStart < 0 ? null : target[(queryStart + 1)..].ToString(),
            protocol.ToString());
    }

    private static bool IsMethod(ReadOnlySpan<char> value)
    {
        foreach (char c in value)
        {
            if (!char.IsAsciiLetter(c) && c is not ('-' or '_'))
            {
                return false;
            }
        }

        return !value.IsEmpty;
    }

    // accepts both HTTP/x and HTTP/x.y
    private static bool IsHttpProtocol(ReadOnlySpan<char> value)
    {
        if (!value.StartsWith("HTTP/"))
        {
            return false;
        }

        ReadOnlySpan<char> version = value["HTTP/".Length..];
        return version switch
        {
            [char major] => char.IsAsciiDigit(major),
            [char major, '.', char minor] => char.IsAsciiDigit(major) && char.IsAsciiDigit(minor),
            _ => false,
        };
    }
}
