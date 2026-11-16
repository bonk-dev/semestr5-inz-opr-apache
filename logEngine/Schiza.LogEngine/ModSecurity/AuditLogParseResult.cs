namespace Schiza.LogEngine.ModSecurity;

public abstract record AuditLogParseResult
{
    private AuditLogParseResult()
    {
    }

    public sealed record Parsed(ModSecAuditEntry Entry) : AuditLogParseResult;
    public sealed record Unparseable(string RawLine, AuditLogParseError Error) : AuditLogParseResult;
}
