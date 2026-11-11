using Schiza.Api.Contracts;
using Schiza.Shared.Requests;

namespace Schiza.Api.Mocks;

public sealed class InMemoryEventStore(TimeProvider time) : IEventStore
{
    public const int Capacity = 1000;

    private readonly Lock _lock = new();
    private readonly LinkedList<SecurityEvent> _events = []; // newest first
    private int _nextId = 1;

    public SecurityEvent Add(ApacheRequest request, ClassificationResult classification)
    {
        EventSource source = request.Response is null ? EventSource.BlockingModule : EventSource.LogAnalysis;
        lock (_lock)
        {
            SecurityEvent securityEvent = new(_nextId++, time.GetUtcNow(), source, request, classification);
            _events.AddFirst(securityEvent);
            if (_events.Count > Capacity)
            {
                _events.RemoveLast();
            }

            return securityEvent;
        }
    }

    public SecurityEvent? Get(int id)
    {
        lock (_lock)
        {
            return _events.FirstOrDefault(e => e.Id == id);
        }
    }

    public EventPage Query(EventQuery query)
    {
        lock (_lock)
        {
            List<SecurityEvent> matching = [.. _events.Where(e => Matches(e, query))];
            return new EventPage([.. matching.Skip(query.Skip).Take(query.Take)], matching.Count);
        }
    }

    private static bool Matches(SecurityEvent e, EventQuery query) =>
        (query.From is null || e.Request.Timestamp >= query.From)
        && (query.To is null || e.Request.Timestamp < query.To)
        && (query.ClientIp is null || e.Request.ClientIp.Equals(query.ClientIp))
        && (query.RuleId is null || e.Classification.RuleId == query.RuleId)
        && (query.Source is null || e.Source == query.Source);
}
