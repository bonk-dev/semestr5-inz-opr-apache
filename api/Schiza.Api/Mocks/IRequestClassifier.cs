using Schiza.Api.Contracts;
using Schiza.Shared.Requests;

namespace Schiza.Api.Mocks;

public interface IRequestClassifier
{
    ClassificationResult Classify(ApacheRequest request);
}
