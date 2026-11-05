using System.Net;
using System.Text.Json.Serialization;

namespace Schiza.Shared.Requests;

/// <summary>
/// A single HTTP request coming from Apache logs file or intercepted by the blocking module.
/// URL-encoded values are preserved (e.g. %20%20..) as these could be a malicious sign as well.
/// </summary>
/// <param name="ClientIp">Client address</param>
/// <param name="Timestamp">Time the request was received</param>
/// <param name="RequestLine">Request line</param>
/// <param name="Referer">Referer header</param>
/// <param name="UserAgent">User-Agent header</param>
/// <param name="Host">Host header sent by the client</param>
/// <param name="TlsProtocol">TLS version, or null for plain HTTP.</param>
/// <param name="UniqueId">mod_unique_id value</param>
/// <param name="Response">
/// Response data, or null in blocking mode, where the request is classified before it is handled.
/// </param>
public sealed record ApacheRequest(
    [property: JsonConverter(typeof(IPAddressJsonConverter))] IPAddress ClientIp,
    DateTimeOffset Timestamp,
    RequestLine RequestLine,
    string? Referer,
    string? UserAgent,
    string? Host,
    string? TlsProtocol,
    string? UniqueId,
    ResponseInfo? Response);
