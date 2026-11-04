using System.Text.Json;

using Schiza.LogEngine.Parsing;
using Schiza.Shared.Requests;

namespace Schiza.LogEngine.Tests;

public class ApacheRequestJsonTests
{
    private static readonly IApacheLogParser Parser = new ApacheLogParser();

    public static TheoryData<string> AllLabels => [.. AccessLogFixture.Labels];

    [Theory]
    [MemberData(nameof(AllLabels))]
    public void ParsedRequest_SurvivesJsonRoundTrip(string label)
    {
        ApacheRequest request = Assert.IsType<LogParseResult.Parsed>(Parser.Parse(AccessLogFixture.Line(label))).Request;

        string json = JsonSerializer.Serialize(request, JsonSerializerOptions.Web);

        Assert.Equal(request, JsonSerializer.Deserialize<ApacheRequest>(json, JsonSerializerOptions.Web));
    }

    [Fact]
    public void ClientIp_IsWrittenAsText()
    {
        ApacheRequest request = Assert.IsType<LogParseResult.Parsed>(Parser.Parse(AccessLogFixture.Line("get-plain-zgrab"))).Request;

        using JsonDocument json = JsonDocument.Parse(JsonSerializer.Serialize(request, JsonSerializerOptions.Web));

        Assert.Equal("198.51.100.3", json.RootElement.GetProperty("clientIp").GetString());
    }
}
