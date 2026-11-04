namespace Schiza.LogEngine.Parsing;

public interface IApacheLogParser
{
    /// <summary>
    /// Parses exactly one line of an Apache log file. Never throws on an invalid line.
    /// </summary>
    LogParseResult Parse(string line);
}
