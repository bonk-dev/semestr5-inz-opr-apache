using Schiza.Api.Contracts;

namespace Schiza.Api.Mocks;

public interface IRuleStore
{
    IReadOnlyList<StaticRule> GetAll();
    StaticRule? Get(int id);
    StaticRule Add(CreateRuleRequest request);
    StaticRule? SetActive(int id, bool isActive);
    bool Remove(int id);
}
