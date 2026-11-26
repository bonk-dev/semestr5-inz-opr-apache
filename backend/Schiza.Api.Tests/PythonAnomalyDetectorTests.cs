using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

using Schiza.Infrastructure;
using Schiza.Shared.Requests;

namespace Schiza.Api.Tests;

public sealed class PythonAnomalyDetectorTests
{
    [Fact]
    public async Task SendsRequestAndPreservesDetectorJson()
    {
        FakeHandler handler = new();
        using HttpClient client = new(handler) { BaseAddress = new Uri("http://detector/") };
        PythonAnomalyDetector detector = new(client);
        ApacheRequest request = new(IPAddress.Loopback, DateTimeOffset.UtcNow,
            new RequestLine(RequestLineKind.Parsed, "GET /attack?q=1 HTTP/1.1", "GET", "/attack", "q=1", "HTTP/1.1"),
            null, "test-agent", "localhost", null, null,
            null, new RequestBody("application/x-www-form-urlencoded", "name=attack"));

        using JsonDocument result = await detector.PredictAsync(request, CancellationToken.None);

        Assert.True(result.RootElement.GetProperty("is_anomaly").GetBoolean());
        Assert.Equal("high", result.RootElement.GetProperty("severity").GetString());
        using JsonDocument input = JsonDocument.Parse(handler.RequestBody!);
        Assert.Equal("name=attack", input.RootElement.GetProperty("body").GetString());
    }

    private sealed class FakeHandler : HttpMessageHandler
    {
        public string? RequestBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestBody = await request.Content!.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(new { is_anomaly = true, severity = "high", reasons = new[] { new { category = "test" } } })
            };
        }
    }
}
