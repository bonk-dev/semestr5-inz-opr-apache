using System.Net;
using System.Text.Json;

using Schiza.LogEngine.ModSecurity;
using Schiza.Shared.Requests;

namespace Schiza.LogEngine.Tests;

public class ModSecAuditLogParserTests
{
    private static readonly IModSecAuditLogParser Parser = new ModSecAuditLogParser();

    public static TheoryData<string> AllLabels => [.. LabeledFixture.ModSecAuditLog.Labels];

    [Theory]
    [MemberData(nameof(AllLabels))]
    public void Parse_AcceptsEveryRealLine(string label)
    {
        Assert.IsType<AuditLogParseResult.Parsed>(Parser.Parse(LabeledFixture.ModSecAuditLog.Line(label)));
    }

    [Fact]
    public void Parse_ReadsAllFieldsOfPost()
    {
        ModSecAuditEntry entry = ParseEntry("post-urlencoded-curl");

        Assert.Equal("avssSZ7_O5vbg1sOxL5esAAAAEU", entry.TransactionId);
        Assert.Equal(IPAddress.Parse("198.51.100.1"), entry.ClientIp);
        Assert.Equal(new DateTimeOffset(2026, 11, 16, 17, 16, 9, TimeSpan.FromHours(1)).AddTicks(8992540), entry.Timestamp);
        Assert.Equal(new RequestLine(RequestLineKind.Parsed, "POST / HTTP/1.1", "POST", "/", null, "HTTP/1.1"), entry.RequestLine);
        Assert.Equal(new RequestBody("application/x-www-form-urlencoded", """{"aa": 123}"""), entry.Body);
        Assert.Equal("curl/8.23.0", entry.RequestHeaders["User-Agent"]);
        Assert.Equal("11", entry.RequestHeaders["Content-Length"]);
        Assert.Equal(200, entry.ResponseStatus);
    }

    [Theory]
    [InlineData("get-root-browser", "/", 200)]
    [InlineData("get-favicon-referer", "/favicon.ico", 404)]
    public void Parse_LeavesBodyEmptyForGet(string label, string path, int status)
    {
        ModSecAuditEntry entry = ParseEntry(label);

        Assert.Equal("GET", entry.RequestLine.Method);
        Assert.Equal(path, entry.RequestLine.Path);
        Assert.Null(entry.Body);
        Assert.Equal(status, entry.ResponseStatus);
    }

    [Fact]
    public void Parse_LooksUpHeadersCaseInsensitively()
    {
        ModSecAuditEntry entry = ParseEntry("get-favicon-referer");

        Assert.Equal("https://server.example.org/", entry.RequestHeaders["referer"]);
        Assert.Equal("server.example.org", entry.RequestHeaders["HOST"]);
    }

    [Fact]
    public void Body_CanBeAttachedToAccessLogRequest()
    {
        ModSecAuditEntry entry = ParseEntry("post-urlencoded-curl");
        ApacheRequest request = SyntheticRequest(entry.TransactionId) with { Body = entry.Body };

        ApacheRequest roundTripped = JsonSerializer.Deserialize<ApacheRequest>(
            JsonSerializer.Serialize(request, JsonSerializerOptions.Web), JsonSerializerOptions.Web)!;

        Assert.Equal(request, roundTripped);
        Assert.Equal("""{"aa": 123}""", roundTripped.Body!.Content);
    }

    [Theory]
    [InlineData("""["a=1&", "b=2"]""", "a=1&b=2")]
    [InlineData("""["a=1&", 5, null, "b=2"]""", "a=1&b=2")]
    [InlineData("\"a=1\"", "a=1")]
    [InlineData("""["<?php system($_GET[\"c\"]); ?>"]""", """<?php system($_GET["c"]); ?>""")]
    [InlineData("""["\u0000\u0016\u0003"]""", "\0\u0016\u0003")]
    public void Parse_JoinsBodyChunks(string bodyJson, string body)
    {
        ModSecAuditEntry entry = ParseSynthetic(request: $$"""{"request_line":"POST /x HTTP/1.1","headers":{},"body":{{bodyJson}}}""");

        Assert.Equal(new RequestBody(null, body), entry.Body);
    }

    [Fact]
    public void Parse_KeepsEntryWithLoneSurrogateInBody()
    {
        ModSecAuditEntry entry = ParseSynthetic(request: """{"request_line":"POST /x HTTP/1.1","body":["a\ud800b"]}""");

        Assert.Equal("""a\ud800b""", entry.Body!.Content);
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("""[""]""")]
    [InlineData("\"\"")]
    [InlineData("null")]
    [InlineData("{}")]
    public void Parse_TreatsEmptyBodyAsMissing(string bodyJson)
    {
        ModSecAuditEntry entry = ParseSynthetic(request: $$"""{"request_line":"POST /x HTTP/1.1","body":{{bodyJson}}}""");

        Assert.Null(entry.Body);
    }

    [Fact]
    public void Parse_JoinsRepeatedHeaders()
    {
        ModSecAuditEntry entry = ParseSynthetic(
            request: """{"request_line":"GET / HTTP/1.1","headers":{"Cookie":"a=1","cookie":"b=2","X-Number":5}}""");

        Assert.Equal("a=1, b=2", entry.RequestHeaders["Cookie"]);
        Assert.False(entry.RequestHeaders.ContainsKey("X-Number"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("""{"headers":{}}""")]
    [InlineData("""{"request_line":5}""")]
    public void Parse_TreatsAbsentRequestLineAsMissing(string? request)
    {
        ModSecAuditEntry entry = ParseSynthetic(request: request);

        Assert.Equal(new RequestLine(RequestLineKind.Missing, "-"), entry.RequestLine);
        Assert.Empty(entry.RequestHeaders);
        Assert.Null(entry.Body);
    }

    [Theory]
    [InlineData("""{"request_line":"\u0016\u0003\u0001"}""", "\u0016\u0003\u0001")]
    [InlineData("""{"request_line":"GET /a b HTTP/1.1"}""", "GET /a b HTTP/1.1")]
    public void Parse_KeepsGarbageRequestLineAsMalformed(string request, string raw)
    {
        Assert.Equal(new RequestLine(RequestLineKind.Malformed, raw), ParseSynthetic(request: request).RequestLine);
    }

    [Fact]
    public void Parse_AcceptsTimeWithoutFraction()
    {
        ModSecAuditEntry entry = ParseSynthetic(time: "16/Nov/2026:17:16:09 +0100");

        Assert.Equal(new DateTimeOffset(2026, 11, 16, 17, 16, 9, TimeSpan.FromHours(1)), entry.Timestamp);
    }

    [Theory]
    [InlineData("""{"protocol":"HTTP/1.1"}""")]
    [InlineData("""{"status":"200"}""")]
    [InlineData("""{"status":99999999999}""")]
    public void Parse_LeavesUnknownStatusEmpty(string response)
    {
        Assert.Null(ParseSynthetic(response: response).ResponseStatus);
    }

    [Fact]
    public void Parse_NeverThrowsOnTruncatedRealLines()
    {
        foreach (string label in LabeledFixture.ModSecAuditLog.Labels)
        {
            string line = LabeledFixture.ModSecAuditLog.Line(label);
            for (int length = 0; length < line.Length; length++)
            {
                Assert.IsType<AuditLogParseResult.Unparseable>(Parser.Parse(line[..length]));
            }
        }
    }

    [Theory]
    [InlineData("", AuditLogParseError.Empty)]
    [InlineData("garbage", AuditLogParseError.InvalidJson)]
    [InlineData("[]", AuditLogParseError.UnexpectedStructure)]
    [InlineData("null", AuditLogParseError.UnexpectedStructure)]
    [InlineData("{}", AuditLogParseError.UnexpectedStructure)]
    [InlineData("""{"transaction":[]}""", AuditLogParseError.UnexpectedStructure)]
    [InlineData("""{"transaction":{"time":"16/Nov/2026:17:16:09 +0100","transaction_id":"id","remote_address":"\ud800"}}""", AuditLogParseError.InvalidClientIp)]
    [InlineData("""{"transaction":{"time":"16/Nov/2026:17:16:09 +0100","remote_address":"203.0.113.7"}}""", AuditLogParseError.UnexpectedStructure)]
    [InlineData("""{"transaction":{"time":"16/Nov/2026:17:16:09 +0100","transaction_id":"","remote_address":"203.0.113.7"}}""", AuditLogParseError.UnexpectedStructure)]
    [InlineData("""{"transaction":{"transaction_id":"id","remote_address":"203.0.113.7"}}""", AuditLogParseError.UnexpectedStructure)]
    [InlineData("""{"transaction":{"time":"16/Nov/2026:17:16:09 +0100","transaction_id":"id"}}""", AuditLogParseError.UnexpectedStructure)]
    [InlineData("""{"transaction":{"time":"16/Nov/2026:17:16:09 +0100","transaction_id":"id","remote_address":"not-an-ip"}}""", AuditLogParseError.InvalidClientIp)]
    [InlineData("""{"transaction":{"time":"99/Nov/2026:17:16:09 +0100","transaction_id":"id","remote_address":"203.0.113.7"}}""", AuditLogParseError.InvalidTimestamp)]
    [InlineData("""{"transaction":{"time":"16/Nov/2026:17:16:09.1234567 +0100","transaction_id":"id","remote_address":"203.0.113.7"}}""", AuditLogParseError.InvalidTimestamp)]
    public void Parse_ReportsLineThatBreaksTheFormat(string line, AuditLogParseError error)
    {
        Assert.Equal(new AuditLogParseResult.Unparseable(line, error), Parser.Parse(line));
    }

    private static ModSecAuditEntry ParseEntry(string label) =>
        Assert.IsType<AuditLogParseResult.Parsed>(Parser.Parse(LabeledFixture.ModSecAuditLog.Line(label))).Entry;

    private static ModSecAuditEntry ParseSynthetic(
        string time = "16/Nov/2026:17:16:09.899254 +0100",
        string? request = null,
        string? response = null)
    {
        string line = $$"""{"transaction":{"time":"{{time}}","transaction_id":"id","remote_address":"203.0.113.7"}"""
                      + (request is null ? "" : $$""","request":{{request}}""")
                      + (response is null ? "" : $$""","response":{{response}}""")
                      + "}";
        return Assert.IsType<AuditLogParseResult.Parsed>(Parser.Parse(line)).Entry;
    }

    private static ApacheRequest SyntheticRequest(string uniqueId) =>
        new(
            IPAddress.Parse("203.0.113.7"),
            new DateTimeOffset(2026, 11, 16, 17, 16, 9, TimeSpan.FromHours(1)),
            new RequestLine(RequestLineKind.Parsed, "POST / HTTP/1.1", "POST", "/", null, "HTTP/1.1"),
            null,
            "curl/8.23.0",
            "server.example.org",
            "TLSv1.3",
            uniqueId,
            new ResponseInfo(200, 2400, 2089, TimeSpan.FromMicroseconds(500)));
}
