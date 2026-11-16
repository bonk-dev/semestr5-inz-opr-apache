using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;

using Schiza.LogEngine.Parsing;
using Schiza.Shared.Requests;

namespace Schiza.LogEngine.ModSecurity;

public sealed class ModSecAuditLogParser : IModSecAuditLogParser
{
    private const string TimestampFormat = "dd/MMM/yyyy:HH:mm:ss.FFFFFF zzz";

    /// <inheritdoc/>
    public AuditLogParseResult Parse(string line)
    {
        ArgumentNullException.ThrowIfNull(line);

        if (line.Length == 0)
        {
            return new AuditLogParseResult.Unparseable(line, AuditLogParseError.Empty);
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(line);
            return Parse(line, document.RootElement);
        }
        catch (JsonException)
        {
            return new AuditLogParseResult.Unparseable(line, AuditLogParseError.InvalidJson);
        }
    }

    private static AuditLogParseResult Parse(string line, JsonElement root)
    {
        if (!TryGetObject(root, "transaction", out JsonElement transaction)
            || GetString(transaction, "transaction_id") is not { Length: > 0 } transactionId
            || GetString(transaction, "time") is not { } timeField
            || GetString(transaction, "remote_address") is not { } clientIpField)
        {
            return new AuditLogParseResult.Unparseable(line, AuditLogParseError.UnexpectedStructure);
        }

        if (!IPAddress.TryParse(clientIpField, out IPAddress? clientIp))
        {
            return new AuditLogParseResult.Unparseable(line, AuditLogParseError.InvalidClientIp);
        }

        if (!DateTimeOffset.TryParseExact(
                timeField,
                TimestampFormat,
                CultureInfo.InvariantCulture,
                DateTimeStyles.None,
                out DateTimeOffset timestamp))
        {
            return new AuditLogParseResult.Unparseable(line, AuditLogParseError.InvalidTimestamp);
        }

        TryGetObject(root, "request", out JsonElement request);
        Dictionary<string, string> headers = ReadHeaders(request);
        string? requestLine = GetString(request, "request_line");
        string? body = ReadBody(request);

        ModSecAuditEntry entry = new(
            transactionId,
            clientIp,
            timestamp,
            requestLine is null ? new RequestLine(RequestLineKind.Missing, "-") : RequestLineParser.Parse(requestLine),
            headers,
            body is null ? null : new RequestBody(headers.GetValueOrDefault("Content-Type"), body),
            ReadStatus(root));

        return new AuditLogParseResult.Parsed(entry);
    }

    private static Dictionary<string, string> ReadHeaders(JsonElement request)
    {
        Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
        if (!TryGetObject(request, "headers", out JsonElement element))
        {
            return headers;
        }

        foreach (JsonProperty header in element.EnumerateObject())
        {
            if (header.Value.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            string value = ReadString(header.Value);
            headers[header.Name] = headers.TryGetValue(header.Name, out string? previous) ? $"{previous}, {value}" : value;
        }

        return headers;
    }

    private static string? ReadBody(JsonElement request)
    {
        if (request.ValueKind != JsonValueKind.Object || !request.TryGetProperty("body", out JsonElement element))
        {
            return null;
        }

        string? body = element.ValueKind switch
        {
            JsonValueKind.String => ReadString(element),
            JsonValueKind.Array => JoinChunks(element),
            _ => null,
        };
        return string.IsNullOrEmpty(body) ? null : body;
    }

    private static string JoinChunks(JsonElement chunks)
    {
        StringBuilder body = new();
        foreach (JsonElement chunk in chunks.EnumerateArray())
        {
            if (chunk.ValueKind == JsonValueKind.String)
            {
                body.Append(ReadString(chunk));
            }
        }

        return body.ToString();
    }

    private static int? ReadStatus(JsonElement root) =>
        TryGetObject(root, "response", out JsonElement response)
        && response.TryGetProperty("status", out JsonElement status)
        && status.ValueKind == JsonValueKind.Number
        && status.TryGetInt32(out int value)
            ? value
            : null;

    private static bool TryGetObject(JsonElement parent, string name, out JsonElement value)
    {
        value = default;
        return parent.ValueKind == JsonValueKind.Object
               && parent.TryGetProperty(name, out value)
               && value.ValueKind == JsonValueKind.Object;
    }

    private static string? GetString(JsonElement parent, string name) =>
        parent.ValueKind == JsonValueKind.Object
        && parent.TryGetProperty(name, out JsonElement value)
        && value.ValueKind == JsonValueKind.String
            ? ReadString(value)
            : null;

    // a lone surrogate (e.g. \ud800) makes GetString throw, so it is kept escaped
    private static string ReadString(JsonElement element)
    {
        try
        {
            return element.GetString()!;
        }
        catch (InvalidOperationException)
        {
            return element.GetRawText()[1..^1];
        }
    }
}
