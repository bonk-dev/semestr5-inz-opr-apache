using System.Net;

using Schiza.Api.Contracts;
using Schiza.Shared.Requests;

namespace Schiza.Api.Mocks;

public static class MockDetectionExtensions
{
    public static IServiceCollection AddMockDetection(this IServiceCollection services)
    {
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IRuleStore, InMemoryRuleStore>();
        services.AddSingleton<IEventStore, InMemoryEventStore>();
        services.AddSingleton<IRequestClassifier, StaticRuleClassifier>();
        return services;
    }

    public static void SeedMockEvents(this IServiceProvider services)
    {
        IRequestClassifier classifier = services.GetRequiredService<IRequestClassifier>();
        IEventStore events = services.GetRequiredService<IEventStore>();
        DateTimeOffset now = services.GetRequiredService<TimeProvider>().GetLocalNow();

        ApacheRequest[] samples =
        [
            Logged(now.AddMinutes(-50), "198.51.100.3", "GET /.git/config HTTP/1.1", "/.git/config", null, "Mozilla/5.0", 404),
            Logged(now.AddMinutes(-42), "203.0.113.77", "POST /wp-login.php HTTP/1.1", "/wp-login.php", null, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 404),
            Logged(now.AddMinutes(-30), "198.51.100.9", "GET /cgi-bin/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1", "/cgi-bin/.%2e/.%2e/.%2e/etc/passwd", null, "curl/8.5.0", 400),
            Logged(now.AddMinutes(-21), "203.0.113.12", "\\x16\\x03\\x01", null, null, null, 400, RequestLineKind.Malformed),
            Intercepted(now.AddMinutes(-9), "198.51.100.44", "GET /index.php?id=1%27%20OR%201=1 HTTP/1.1", "/index.php", "id=1%27%20OR%201=1", "sqlmap/1.8.4#stable (https://sqlmap.org)"),
            Intercepted(now.AddMinutes(-2), "203.0.113.77", "GET /.env HTTP/1.1", "/.env", null, "Mozilla/5.0"),
        ];

        foreach (ApacheRequest request in samples)
        {
            ClassificationResult result = classifier.Classify(request);
            if (result.Verdict == Verdict.Unsafe)
            {
                events.Add(request, result);
            }
        }
    }

    private static ApacheRequest Logged(
        DateTimeOffset time,
        string ip,
        string raw,
        string? path,
        string? query,
        string? userAgent,
        int status,
        RequestLineKind kind = RequestLineKind.Parsed) =>
        Request(time, ip, raw, path, query, userAgent, kind) with
        {
            Response = new ResponseInfo(status, 512, 196, TimeSpan.FromMilliseconds(2)),
        };

    private static ApacheRequest Intercepted(DateTimeOffset time, string ip, string raw, string path, string? query, string userAgent) =>
        Request(time, ip, raw, path, query, userAgent, RequestLineKind.Parsed);

    private static ApacheRequest Request(
        DateTimeOffset time,
        string ip,
        string raw,
        string? path,
        string? query,
        string? userAgent,
        RequestLineKind kind)
    {
        RequestLine line = kind == RequestLineKind.Parsed
            ? new RequestLine(kind, raw, raw[..raw.IndexOf(' ')], path, query, "HTTP/1.1")
            : new RequestLine(kind, raw);
        return new ApacheRequest(IPAddress.Parse(ip), time, line, null, userAgent, "example.com", null, null, null);
    }
}
