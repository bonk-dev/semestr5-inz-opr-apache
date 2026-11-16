namespace Schiza.LogEngine.ModSecurity;

public interface IModSecAuditLogParser
{
    AuditLogParseResult Parse(string line);
}
