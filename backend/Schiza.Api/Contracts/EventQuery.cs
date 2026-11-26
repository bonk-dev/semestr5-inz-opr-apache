using System.ComponentModel.DataAnnotations;
using System.Net;

namespace Schiza.Api.Contracts;

/// <param name="From">Only events with the request timestamp at or after this time.</param>
/// <param name="To">Only events with the request timestamp before this time.</param>
/// <param name="ClientIp">Only events from this client address.</param>
/// <param name="RuleId">Only events matched by this rule.</param>
/// <param name="Source">Only events from this source.</param>
/// <param name="Skip">Number of events to skip, newest first.</param>
/// <param name="Take">Page size.</param>
public sealed record EventQuery(
    DateTimeOffset? From = null,
    DateTimeOffset? To = null,
    IPAddress? ClientIp = null,
    int? RuleId = null,
    EventSource? Source = null,
    [Range(0, int.MaxValue)] int Skip = 0,
    [Range(1, 200)] int Take = 50);
