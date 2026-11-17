using System.Net.Http.Json;
using System.Text.Json;
using Schiza.Application;
using Schiza.Shared.Requests;

namespace Schiza.Infrastructure;

public sealed class PythonAnomalyDetector(HttpClient client) : IAnomalyDetector
{
    public async Task<JsonDocument> PredictAsync(ApacheRequest request, CancellationToken cancellationToken)
    {
        var input = new
        {
            method = request.RequestLine.Method ?? "UNKNOWN",
            url = request.RequestLine.Path is { } path ? path + (request.RequestLine.Query is { } query ? "?" + query : "") : request.RequestLine.Raw,
            user_agent = request.UserAgent ?? "",
            body = request.Body?.Content ?? ""
        };
        using HttpResponseMessage response = await client.PostAsJsonAsync("predict", input, cancellationToken);
        response.EnsureSuccessStatusCode();
        await using Stream content = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonDocument.ParseAsync(content, cancellationToken: cancellationToken);
    }
}
