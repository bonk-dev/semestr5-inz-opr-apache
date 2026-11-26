namespace Schiza.Api.Contracts;

/// <param name="Items">Events on this page, newest first.</param>
/// <param name="Total">Number of events matching the query.</param>
public sealed record EventPage(IReadOnlyList<SecurityEvent> Items, int Total);
