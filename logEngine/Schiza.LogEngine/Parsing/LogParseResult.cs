using Schiza.Shared.Requests;

namespace Schiza.LogEngine.Parsing;

public abstract record LogParseResult
{
    private LogParseResult()
    {
    }

    public sealed record Parsed(ApacheRequest Request) : LogParseResult;
    public sealed record Unparseable(string RawLine, LogParseError Error) : LogParseResult;
}
