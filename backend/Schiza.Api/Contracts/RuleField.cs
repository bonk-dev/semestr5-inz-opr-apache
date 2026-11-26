using System.Text.Json.Serialization;

namespace Schiza.Api.Contracts;

/// <summary>
/// Part of the request a static rule is matched against.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<RuleField>))]
public enum RuleField
{
    /// <summary>Request target up to the first ?.</summary>
    Path,

    /// <summary>Text after the first ?.</summary>
    Query,

    /// <summary>Whole raw request line, also for malformed lines.</summary>
    RequestLine,

    UserAgent,
    Referer,
    Host,
}
