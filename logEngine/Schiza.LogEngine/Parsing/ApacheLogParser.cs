using System.Globalization;
using System.Net;

using Schiza.Shared.Requests;

namespace Schiza.LogEngine.Parsing;

public sealed class ApacheLogParser : IApacheLogParser
{
    private const string TimestampFormat = "dd/MMM/yyyy:HH:mm:ss zzz";
    private const long MaxDurationMicroseconds = long.MaxValue / TimeSpan.TicksPerMicrosecond;

    /// <inheritdoc/>
    public LogParseResult Parse(string line)
    {
        ArgumentNullException.ThrowIfNull(line);

        if (line.Length == 0)
        {
            return new LogParseResult.Unparseable(line, LogParseError.Empty);
        }

        LineScanner scanner = new(line);
        if (!(scanner.TryReadToken(out ReadOnlySpan<char> clientIpField)
              && scanner.TryReadToken(out _) // %l
              && scanner.TryReadToken(out _) // %u
              && scanner.TryReadBracketed(out ReadOnlySpan<char> timestampField)
              && scanner.TryReadQuoted(out ReadOnlySpan<char> requestLineField)
              && scanner.TryReadToken(out ReadOnlySpan<char> statusField)
              && scanner.TryReadToken(out ReadOnlySpan<char> bytesSentField)
              && scanner.TryReadQuoted(out ReadOnlySpan<char> refererField)
              && scanner.TryReadQuoted(out ReadOnlySpan<char> userAgentField)
              && scanner.TryReadToken(out ReadOnlySpan<char> durationField)
              && scanner.TryReadQuoted(out ReadOnlySpan<char> hostField)
              && scanner.TryReadToken(out _) // %v:%p
              && scanner.TryReadToken(out ReadOnlySpan<char> tlsField)))
        {
            return new LogParseResult.Unparseable(line, LogParseError.UnexpectedStructure);
        }

        ReadOnlySpan<char> bodyBytesField = default;
        ReadOnlySpan<char> uniqueIdField = default;
        bool hasOptionalFields = !scanner.IsAtEnd;
        if (hasOptionalFields
            && !(scanner.TryReadToken(out bodyBytesField) && scanner.TryReadToken(out uniqueIdField) && scanner.IsAtEnd))
        {
            return new LogParseResult.Unparseable(line, LogParseError.UnexpectedStructure);
        }

        if (!IPAddress.TryParse(clientIpField, out IPAddress? clientIp))
        {
            return new LogParseResult.Unparseable(line, LogParseError.InvalidClientIp);
        }

        if (!DateTimeOffset.TryParseExact(
                timestampField,
                TimestampFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out DateTimeOffset timestamp))
        {
            return new LogParseResult.Unparseable(line, LogParseError.InvalidTimestamp);
        }

        long? bodyBytes = null;
        if (!TryParseNumber(statusField, out long status)
            || status > int.MaxValue
            || !TryParseNumber(bytesSentField, out long bytesSent)
            || !TryParseNumber(durationField, out long durationMicroseconds)
            || durationMicroseconds > MaxDurationMicroseconds
            || (hasOptionalFields && !TryParseOptionalNumber(bodyBytesField, out bodyBytes)))
        {
            return new LogParseResult.Unparseable(line, LogParseError.InvalidNumber);
        }

        ApacheRequest request = new(
            clientIp,
            timestamp,
            ParseRequestLine(requestLineField),
            NullIfDash(refererField),
            NullIfDash(userAgentField),
            NullIfDash(hostField),
            NullIfDash(tlsField),
            hasOptionalFields ? NullIfDash(uniqueIdField) : null,
            new ResponseInfo((int)status, bytesSent, bodyBytes, TimeSpan.FromMicroseconds(durationMicroseconds)));

        return new LogParseResult.Parsed(request);
    }

    private static RequestLine ParseRequestLine(ReadOnlySpan<char> raw)
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

    private static bool TryParseNumber(ReadOnlySpan<char> value, out long number) =>
        long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out number);

    private static bool TryParseOptionalNumber(ReadOnlySpan<char> value, out long? number)
    {
        bool parsed = TryParseNumber(value, out long parsedNumber);
        number = parsedNumber;
        return parsed;
    }

    private static string? NullIfDash(ReadOnlySpan<char> value) => value is "-" ? null : value.ToString();
}
