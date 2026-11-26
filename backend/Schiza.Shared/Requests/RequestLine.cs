using System.Text.Json.Serialization;

namespace Schiza.Shared.Requests;

[JsonConverter(typeof(JsonStringEnumConverter<RequestLineKind>))]
public enum RequestLineKind
{
    /// <summary>
    /// Valid request line. Does not say anything about the nature of the request itself: might be an attack or a valid request
    /// </summary>
    Parsed,

    /// <summary>
    /// No request line was received (%r, logged as "-" by Apache).
    /// </summary>
    Missing,

    /// <summary>
    /// Anything else, including a completely empty string or non-HTTP protocols, or garbled input (e.g. HTTPS traffic on HTTP port).
    /// </summary>
    Malformed,
}

/// <param name="Kind">Tells about the validity of the request line</param>
/// <param name="Raw">Unparsed request line</param>
/// <param name="Method">HTTP method (GET, PUT etc.), which may be non-standard.</param>
/// <param name="Path">Request target up to the first ?.</param>
/// <param name="Query">Text after the first ?, or null when the target has no ?.</param>
/// <param name="Protocol">Protocol, for example <c>HTTP/1.1</c>.</param>
public sealed record RequestLine(
    RequestLineKind Kind,
    string Raw,
    string? Method = null,
    string? Path = null,
    string? Query = null,
    string? Protocol = null);
