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
