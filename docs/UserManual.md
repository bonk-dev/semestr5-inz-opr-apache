# Prosta instrukcja uruchomienia projektu

Instrukcja zakłada system Linux oraz uruchamianie poleceń w powłoce bash.
Wszystkie ścieżki są względne względem katalogu głównego repozytorium,
czyli katalogu zawierającego `Schiza.slnx`, `backend/`, `frontend/` i
`Deep Learning Detection Module/`.

## 1. Wymagania

Zainstaluj:

- .NET SDK 10 z obsługą ASP.NET Core,
- Python 3.12 lub nowszy zgodny z zależnościami projektu,
- Node.js i npm.

Sprawdź instalację:

```bash
dotnet --version
python --version
node --version
npm --version
```

## 2. Uruchom moduł Python

Otwórz pierwsze okno terminala i z katalogu głównego repozytorium przejdź
do katalogu modułu:

```bash
cd "./Deep Learning Detection Module"
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Alternatywnie
```bash
python -m uvicorn app.main:app
```

Sprawdź, czy moduł działa — w drugim oknie terminala, również uruchomionym
z katalogu głównego repozytorium:

```bash
curl http://127.0.0.1:8000/health
```

Powinna pojawić się odpowiedź JSON ze statusem modułu.

Nie zamykaj pierwszego okna terminala.

## 3. Przygotuj katalogi i log Apache

W katalogu głównym repozytorium wykonaj:

```bash
mkdir -p ./runtime/apache ./runtime/schiza
cp ./backend/Schiza.LogEngine.Tests/Fixtures/access-sample.txt ./runtime/apache/access.log
```

Przykładowy plik logu służy do testu bez instalowania Apache Web Server.

## 4. Skonfiguruj API

Utwórz lub edytuj plik:

```text
./backend/Schiza.Api/appsettings.Development.json
```

Wstaw:

```json
{
  "PythonDetection": {
    "BaseUrl": "http://127.0.0.1:8000/"
  },
  "ApacheLog": {
    "Path": "./runtime/apache/access.log"
  },
  "Storage": {
    "DatabasePath": "./runtime/schiza/schiza.db"
  },
  "Admin": {
    "Username": "admin",
    "PasswordHash": "pbkdf2.sha256.<salt-base64>.<hash-base64>"
  }
}
```

Przed wstawieniem wartości wygeneruj hash w terminalu. Hasło nie jest zapisywane w pliku:

```bash
export SCHIZA_ADMIN_PASSWORD="WybierzSwojeHaslo"
python -c 'import base64,hashlib,os; p=os.environ["SCHIZA_ADMIN_PASSWORD"].encode(); s=os.urandom(16); h=hashlib.pbkdf2_hmac("sha256",p,s,120000,32); print("pbkdf2.sha256."+base64.b64encode(s).decode()+"."+base64.b64encode(h).decode())'
```

Skopiuj wynik polecenia w miejsce `pbkdf2.sha256.<salt-base64>.<hash-base64>`.
Nie dodawaj prawdziwego hasha do repozytorium. Bez skonfigurowanego hasha logowanie administratora
nie zadziała; do testowania samego przetwarzania logów można pominąć logowanie.

Alternatywnie ustaw konfigurację tylko w bieżącym oknie terminala:

```bash
export Admin__Username="admin"
export Admin__PasswordHash="pbkdf2.sha256.<salt-base64>.<hash-base64>"
```

Wartość zastąp wynikiem generatora.

## 5. Uruchom backend

Otwórz drugie okno terminala i przejdź do katalogu głównego projektu:

```bash
cd .
dotnet restore ./Schiza.slnx
dotnet run --project ./backend/Schiza.Api/Schiza.Api.csproj --launch-profile http
```

API będzie dostępne pod adresem:

```text
http://localhost:5292
```

Przy pierwszym uruchomieniu zostanie utworzona baza:

```text
./runtime/schiza/schiza.db
```

Backend odczyta przykładowy plik Apache, wyśle żądania do modułu Python i zapisze tylko zdarzenia oznaczone jako anomalne.

Nie zamykaj tego okna terminala.

## 6. Uruchom frontend

Otwórz trzecie okno terminala i przejdź do katalogu głównego repozytorium:

```bash
cd ./frontend
npm install
npm run dev
```

Otwórz adres wyświetlony przez Vite, zwykle:

```text
http://localhost:5173
```

Frontend pobiera dane z API przez proxy `/api`.

## 7. Sprawdź działanie

Sprawdź w logach backendu, czy plik Apache został odczytany i czy moduł Python odpowiada.

Możesz również dopisać nowy wpis do pliku:

```bash
printf '%s\n' '198.51.100.10 - - [28/Oct/2026:10:02:11 +0000] "GET /search?q=%27%20OR%201%3D1-- HTTP/1.1" 403 512 "-" "Mozilla/5.0" 2000 "example.com" example.com:443 TLSv1.3 512 UNIQUE123' >> ./runtime/apache/access.log
```

Po kilku sekundach:

1. parser odczyta wpis,
2. API wyśle żądanie do modułu Python,
3. anomalia zostanie zapisana w SQLite,
4. zdarzenie powinno pojawić się na liście w frontendzie.

W szczegółach zdarzenia można sprawdzić pełny JSON detekcji oraz dane XAI.

## 8. Testy automatyczne

W katalogu głównym projektu uruchom:

```bash
dotnet test ./Schiza.slnx
```

Build projektu:

```bash
dotnet build ./Schiza.slnx
```

Build frontendu:

```bash
cd ./frontend
npm run build
```

## 9. Zatrzymanie projektu

W każdym oknie terminala naciśnij:

```text
Ctrl+C
```

Nie usuwaj pliku `./runtime/schiza/schiza.db`, jeśli chcesz zachować zapisane zdarzenia.

Moduł Python pozostaje niezależnym komponentem i jego kod nie jest modyfikowany.

## 10. Windows — opcjonalny wariant lokalny

Linux/bash opisany w poprzednich sekcjach jest głównym wariantem uruchomienia
na serwerze. Poniższe polecenia służą wyłącznie do lokalnego sprawdzenia projektu
na Windows. Wykonuj je w PowerShell z katalogu głównego repozytorium.

### Moduł Python

```powershell
cd .
python -m venv ".\Deep Learning Detection Module\.venv"
& ".\Deep Learning Detection Module\.venv\Scripts\Activate.ps1"
pip install -r ".\Deep Learning Detection Module\requirements.txt"
python -m uvicorn app.main:app --app-dir ".\Deep Learning Detection Module" --host 127.0.0.1 --port 8000
```

Jeżeli PowerShell blokuje aktywację środowiska, ustaw politykę tylko dla bieżącego procesu:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

W drugim oknie PowerShell sprawdź moduł:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

### Katalogi, konfiguracja i backend

Z katalogu głównego repozytorium utwórz katalogi runtime i skopiuj przykładowy log:

```powershell
New-Item -ItemType Directory -Force ".\runtime\apache", ".\runtime\schiza"
Copy-Item ".\backend\Schiza.LogEngine.Tests\Fixtures\access-sample.txt" ".\runtime\apache\access.log"
```

W `api\Schiza.Api\appsettings.Development.json` użyj ścieżek względnych:

```json
{
  "PythonDetection": {
    "BaseUrl": "http://127.0.0.1:8000/"
  },
  "ApacheLog": {
    "Path": ".\\runtime\\apache\\access.log"
  },
  "Storage": {
    "DatabasePath": ".\\runtime\\schiza\\schiza.db"
  }
}
```

Uruchom backend:

```powershell
dotnet restore .\Schiza.slnx
dotnet run --project .\backend\Schiza.Api\Schiza.Api.csproj --launch-profile http
```

### Frontend i testy

W kolejnym oknie PowerShell uruchom frontend:

```powershell
cd .\frontend
npm install
npm run dev
```

Testy i build uruchom z katalogu głównego repozytorium:

```powershell
dotnet test .\Schiza.slnx
dotnet build .\Schiza.slnx
cd .\frontend
npm run build
```
