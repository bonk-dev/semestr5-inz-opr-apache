namespace Schiza.LogEngine.ModSecurity;

public enum AuditLogParseError
{
    Empty,
    InvalidJson,
    UnexpectedStructure,
    InvalidClientIp,
    InvalidTimestamp,
}
