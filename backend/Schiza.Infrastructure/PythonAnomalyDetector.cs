using System.Net.Http.Json;
using System.Text.Json;
using Schiza.Application;
using Schiza.Application.Legacy;
using Schiza.Shared.Requests;

namespace Schiza.Infrastructure;

public sealed class PythonAnomalyDetector(HttpClient client) : IAnomalyDetector
{
    public async Task<ClassificationResult> ClassifyAsync(ApacheRequest request, CancellationToken cancellationToken)
    {
        try
        {
            using JsonDocument detection = await PredictAsync(request, cancellationToken);
            JsonElement root = detection.RootElement;
            bool isAnomaly = root.TryGetProperty("is_anomaly", out JsonElement flag) && flag.ValueKind == JsonValueKind.True;
            double? score = root.TryGetProperty("anomaly_score", out JsonElement scoreElement) && scoreElement.ValueKind == JsonValueKind.Number
                ? scoreElement.GetDouble()
                : null;
            double responseScore = score ?? (isAnomaly ? 1.0 : 0.0);
            string? severity = root.TryGetProperty("severity", out JsonElement severityElement) ? severityElement.GetString() : null;
            return new(isAnomaly ? Verdict.Unsafe : Verdict.Safe, responseScore, severity ?? "Autoencoder", null, false, isAnomaly, score, root.GetRawText());
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException or InvalidOperationException)
        {
            throw new ClassificationFailedException("Nie udało się uzyskać klasyfikacji z modułu Python.", exception);
        }
    }

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
