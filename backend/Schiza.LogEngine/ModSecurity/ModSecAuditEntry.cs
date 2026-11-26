using System.Net;

using Schiza.Shared.Requests;

namespace Schiza.LogEngine.ModSecurity;

public sealed record ModSecAuditEntry(
    // same value as ApacheRequest.UniqueId of the matching access.log line
    string TransactionId,
    IPAddress ClientIp,
    DateTimeOffset Timestamp,
    RequestLine RequestLine,
    IReadOnlyDictionary<string, string> RequestHeaders,
    RequestBody? Body,
    int? ResponseStatus);
