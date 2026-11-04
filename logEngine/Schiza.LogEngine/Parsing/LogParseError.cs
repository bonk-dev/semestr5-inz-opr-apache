namespace Schiza.LogEngine.Parsing;

public enum LogParseError
{
    Empty,

    /// <summary>
    /// The line did not have the expected format (missing fields)
    /// </summary>
    UnexpectedStructure,

    InvalidClientIp,
    InvalidTimestamp,
    InvalidNumber,
}
