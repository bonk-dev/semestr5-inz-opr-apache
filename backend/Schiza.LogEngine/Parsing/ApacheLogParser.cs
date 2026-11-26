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
            RequestLineParser.Parse(requestLineField),
            NullIfDash(refererField),
            NullIfDash(userAgentField),
            NullIfDash(hostField),
            NullIfDash(tlsField),
            hasOptionalFields ? NullIfDash(uniqueIdField) : null,
            new ResponseInfo((int)status, bytesSent, bodyBytes, TimeSpan.FromMicroseconds(durationMicroseconds)));

        return new LogParseResult.Parsed(request);
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
