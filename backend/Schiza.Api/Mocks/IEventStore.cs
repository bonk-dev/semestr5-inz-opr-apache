using Schiza.Api.Contracts;
using Schiza.Shared.Requests;

namespace Schiza.Api.Mocks;

public interface IEventStore
{
    SecurityEvent Add(ApacheRequest request, ClassificationResult classification);
    SecurityEvent? Get(int id);
    EventPage Query(EventQuery query);
}
