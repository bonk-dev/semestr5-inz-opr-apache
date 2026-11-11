using Schiza.Shared.Requests;

namespace Schiza.Api.Contracts;

/// <summary>
/// A classified request. Only unsafe requests are stored, because client IP addresses are personal data (GDPR).
/// </summary>
/// <param name="Id">Event identifier.</param>
/// <param name="ClassifiedAt">When the backend classified the request.</param>
/// <param name="Source">Where the request came from.</param>
/// <param name="Request">The classified request.</param>
/// <param name="Classification">Classification result.</param>
public sealed record SecurityEvent(
    int Id,
    DateTimeOffset ClassifiedAt,
    EventSource Source,
    ApacheRequest Request,
    ClassificationResult Classification);
