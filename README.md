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

## Uruchomienie całego przepływu

1. Uruchom gotowy moduł `Deep Learning Detection Module` zgodnie z jego dokumentacją,
   domyślnie pod adresem `http://127.0.0.1:8000`.
2. Skonfiguruj `api/Schiza.Api/appsettings.json` lub zmienne środowiskowe:
   `PythonDetection:BaseUrl`, `ApacheLog:Path`, `Storage:DatabasePath`,
   `Admin:Username` oraz `Admin:PasswordHash`. Hasło nie jest przechowywane w repozytorium.
3. Wszystkie poniższe polecenia wykonuj z katalogu głównego repozytorium
   (tego, który zawiera `Schiza.slnx`, `api/`, `frontend/` i `Deep Learning Detection Module/`).
   Przykład ustawienia hasła:

   ```bash
   export SCHIZA_ADMIN_PASSWORD="WybierzSwojeHaslo"
   export Admin__Username="admin"
   export Admin__PasswordHash="$(python -c 'import base64,hashlib,os; p=os.environ["SCHIZA_ADMIN_PASSWORD"].encode(); s=os.urandom(16); h=hashlib.pbkdf2_hmac("sha256",p,s,120000,32); print("pbkdf2.sha256."+base64.b64encode(s).decode()+"."+base64.b64encode(h).decode())')"
   dotnet run --project ./api/Schiza.Api/Schiza.Api.csproj --launch-profile http
    ```

4. Uruchom API: `dotnet run --project api/Schiza.Api/Schiza.Api.csproj`.
   Przy pierwszym uruchomieniu zostanie utworzony katalog i plik SQLite oraz tabela
   `FlaggedEvents`. Worker odczytuje nowe linie z pliku wskazanego przez `ApacheLog:Path`.
5. Uruchom frontend: `cd ./frontend; npm install; npm run dev`. Vite przekazuje `/api`
   do backendu na `http://localhost:5292`.

Oflagowane zdarzenia są zapisywane wyłącznie, gdy odpowiedź modułu Python ma
`is_anomaly: true`. W bazie przechowywany jest surowy wpis Apache, sparsowane żądanie,
pełna odpowiedź JSON detektora oraz czas zdarzenia i detekcji. Deduplikacja używa SHA-256
surowej linii logu. Endpointy `/api/anomalies` wymagają roli `Admin`.

### Windows — opcjonalnie

Linux/bash jest głównym wariantem uruchomienia. Do lokalnego sprawdzenia projektu
na Windows można użyć PowerShell, wykonując polecenia z katalogu głównego repozytorium:

```powershell
cd .
python -m venv ".\Deep Learning Detection Module\.venv"
& ".\Deep Learning Detection Module\.venv\Scripts\Activate.ps1"
pip install -r ".\Deep Learning Detection Module\requirements.txt"
New-Item -ItemType Directory -Force ".\runtime\apache", ".\runtime\schiza"
Copy-Item ".\logEngine\Schiza.LogEngine.Tests\Fixtures\access-sample.txt" ".\runtime\apache\access.log"
dotnet restore .\Schiza.slnx
dotnet run --project .\api\Schiza.Api\Schiza.Api.csproj --launch-profile http
```

W konfiguracji Windows użyj ścieżek względnych `./runtime/apache/access.log`
i `./runtime/schiza/schiza.db` (w JSON zapisanych jako `".\\runtime\\..."`).
Frontend uruchom poleceniami `cd .\frontend`, `npm install` i `npm run dev`.

## Architektura backendu

Backend jest podzielony na warstwy zgodnie z Clean Architecture:

```text
Domain
  ↑
Application
  ↑
Infrastructure

API → Application
API → Infrastructure (wyłącznie rejestracja DI)
```

- `domain/Schiza.Domain` zawiera encje domenowe, w szczególności `FlaggedEvent`.
- `application/Schiza.Application` zawiera przypadki użycia, porty repozytoriów,
  port detektora Python, kontrakty uwierzytelniania oraz kontrakty obsługiwanej
  klasyfikacji legacy.
- `infrastructure/Schiza.Infrastructure` zawiera SQLite, klienta HTTP Python,
  adapter `LogEngine`, worker odczytu Apache, worker retencji 30 dni oraz
  implementacje magazynów legacy.
- `api/Schiza.Api` zawiera kontrolery, cookie authentication, autoryzację,
  middleware i composition root w `Program.cs`.
- `shared/Schiza.Shared` jest niezależnym shared kernel dla modeli żądań Apache.
- `logEngine/Schiza.LogEngine` pozostaje niezależnym parserem.

Kontrolery nie wykonują operacji SQLite ani komunikacji z Pythonem. Te operacje
odbywają się przez interfejsy Application i implementacje Infrastructure.

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
