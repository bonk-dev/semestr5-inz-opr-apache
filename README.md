# Narzędzie do analizy logów Apache

Projekt na inżynierię oprogramownia

## Członkowie grupy:

- Dawid Pągowski: @bonk-dev
- Bartłomiej Łokaj: @Rotikuningas
- Paweł Świderski: @Pawel-create

## Quick start: LogEngine

Parser czyta logi w formacie:

```apache
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %D \"%{Host}i\" %v:%p %{SSL_PROTOCOL}x %B %{UNIQUE_ID}e" combined_ext
```

Dodaj referencję do `logEngine/Schiza.LogEngine` i parsuj linia po linii:

```csharp
using Schiza.LogEngine.Parsing;

IApacheLogParser parser = new ApacheLogParser();

foreach (string line in File.ReadLines("access.log"))
{
    switch (parser.Parse(line))
    {
        case LogParseResult.Parsed { Request: var request }:
            Console.WriteLine($"{request.ClientIp} {request.RequestLine.Kind} {request.Response?.Status}");
            break;
        case LogParseResult.Unparseable { Error: var error }:
            Console.WriteLine($"Nieparsowalna linia: {error}");
            break;
    }
}
```

## Quick start: ciała żądań z ModSecurity

access.log nie zawiera danych POST, więc bierzemy je z audit logu ModSecurity, zapisywanego jako jeden obiekt JSON na linię:

```
SecRequestBodyAccess On
SecAuditEngine On
SecAuditLogParts ABDEFHIJZ
SecAuditLogType Serial
SecAuditLogFormat JSON
SecAuditLog /var/log/apache2/modsec_audit.log
```

`transaction_id` z audit logu to wartość `UNIQUE_ID`, więc wpis dopasowujemy do linii access.log po `ApacheRequest.UniqueId`:

```csharp
using Schiza.LogEngine.ModSecurity;

IModSecAuditLogParser auditParser = new ModSecAuditLogParser();

Dictionary<string, RequestBody> bodies = [];
foreach (string line in File.ReadLines("modsec_audit.log"))
{
    if (auditParser.Parse(line) is AuditLogParseResult.Parsed { Entry: { Body: { } body } entry })
    {
        bodies[entry.TransactionId] = body;
    }
}

// request sparsowany z access.log
// request ma typ LogParseResult i pochodzi z IApacheLogParser
if (request.UniqueId is { } id && bodies.TryGetValue(id, out RequestBody? body))
{
    request = request with { Body = body };
}
```
