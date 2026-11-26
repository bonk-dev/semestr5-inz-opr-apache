import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl, unquote_plus

import pandas as pd


# Kolumny trafiające do ColumnTransformera (patrz preprocessing.py)
# oraz surowe wartości używane przez warstwę reguł (rules.py).
FEATURE_COLUMNS = [
    "method",
    "url_length",
    "path_length",
    "path_depth",
    "query_param_count",
    "query_length",
    "special_char_ratio",
    "has_encoded_chars",
    "has_path_traversal",
    "has_suspicious_keywords",
    "user_agent_length",
    "user_agent_category",
    "body_length",
    "body_param_count",
    "body_special_char_ratio",
    # Wartości dla reguł – model ich nie widzi (remainder="drop").
    "path",
    "param_names",
    "is_malformed",
]

METHODS = {
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "TRACE", "CONNECT",
}

# Maksymalna liczba parametrów parsowana w jednym zapytaniu/body.
MAX_PARAMS = 1000

REQUEST_LINE = re.compile(
    r"^([A-Z]+)\s+(\S+)\s+HTTP/(\d+(?:\.\d+)?)$"
)

CSIC_START = re.compile(
    r"(?m)^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)"
    r"\s+\S+\s+HTTP/\d+(?:\.\d+)?\s*$"
)

# Apache zapisuje " jako \" oraz \ jako \\, więc pola w cudzysłowach
# muszą dopuszczać sekwencje escape (inaczej payload z cudzysłowem
# psuje parsowanie i żądanie jest po cichu pomijane).
APACHE_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>(?:[^"\\]|\\.)*)"\s+'
    r'(?P<status>\d{3}|-)\s+'
    r'(?P<size>\d+|-)'
    r'(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"'
    r'\s+"(?P<ua>(?:[^"\\]|\\.)*)")?\s*$'
)

APACHE_ESCAPE = re.compile(r"\\(x[0-9a-fA-F]{2}|.)", re.DOTALL)
APACHE_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
    '"': '"', "\\": "\\",
}

ENCODED_PATTERN = re.compile(r"%[0-9a-fA-F]{2}")

# Ścieżki typu ../ lub ..\ (po zdekodowaniu URL-a).
TRAVERSAL_PATTERN = re.compile(r"\.\.[/\\]|[/\\]\.\.$")

@dataclass(frozen=True)
class Signature:
    """Nazwana sygnatura ataku – nazwa i opis trafiają do wyjaśnienia (XAI)."""

    name: str
    category: str
    description: str
    pattern: str
    fields: tuple[str, ...] = ("url", "body")


# Sygnatury niezależne od aplikacji (działają w trybie „open-world”).
# Sprawdzone na 72 000 normalnych żądań CSIC: 0 trafień.
# Zakresy `.{1,200}?` ograniczają koszt backtrackingu (ReDoS).
SIGNATURES = (
    Signature("sql_union_select", "sql_injection",
              "SQL injection: UNION SELECT",
              r"union\s+(?:all\s+)?select",
              fields=("url", "body", "user_agent")),
    Signature("sql_select_from", "sql_injection",
              "SQL injection: SELECT ... FROM",
              r"select\s+(?:\*|\d+|null\b|distinct\b|top\s+\d+|[\w.]+\s*\(|[\w.]+\s*,)"
              r".{0,150}?\sfrom\b"),
    Signature("sql_dml_ddl", "sql_injection",
              "SQL injection: data-modifying statement",
              r"\binsert\s+into\s+[\w.]+\s*(?:\(|values\b|select\b)"
              r"|\bdelete\s+from\s+[\w.]+\s*(?:where\b|;|--|#|/\*|\))"
              r"|\bdrop\s+(?:table|database)\s+(?:if\s+exists\s+)?[\w.]+"
              r"|\bupdate\s+[\w.]+\s+set\s+[\w.]+\s*="
              # instrukcja „wyrwana” z kontekstu cudzysłowem / średnikiem
              r"|['\";)]\s*(?:insert\s+into|delete\s+from"
              r"|drop\s+(?:table|database)|update\s+\w+\s+set)\b"),
    Signature("sql_tautology", "sql_injection",
              "SQL injection: always-true condition",
              r"\b(?:or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
              fields=("url", "body", "user_agent")),
    Signature("sql_quote_or", "sql_injection",
              "SQL injection: quote-breaking OR/AND",
              r"'\s*(?:or|and)\s+'"),
    Signature("sql_comment", "sql_injection",
              "SQL injection: comment sequence after a value",
              r"(?:'|\"|\)|\d)\s*(?:--(?=\s|$)|#|/\*)"),
    Signature("sql_functions", "sql_injection",
              "SQL injection: time-delay or database function",
              r"\b(?:sleep|benchmark|xp_cmdshell|load_file"
              r"|information_schema)\b"),
    Signature("xss_tag", "xss",
              "Cross-site scripting: HTML tag injection",
              r"<\s*/?\s*(?:script|iframe|img|svg|body|object|embed)\b",
              fields=("url", "body", "user_agent")),
    Signature("xss_js_scheme", "xss",
              "Cross-site scripting: javascript: URL",
              r"javascript\s*:"),
    Signature("xss_event_handler", "xss",
              "Cross-site scripting: inline event handler",
              r"\bon(?:error|load|mouse\w+|click|focus)\s*="),
    Signature("sensitive_file", "file_disclosure",
              "Attempt to read a sensitive system file",
              r"/etc/(?:passwd|shadow)|boot\.ini|win\.ini"
              r"|/proc/self/|wp-config\.php"),
    Signature("hidden_file_probe", "file_disclosure",
              "Probe for hidden or configuration files (.env, .git, ...)",
              r"/\.(?:env|git|svn|hg|htpasswd|htaccess|aws|ssh|DS_Store)"
              r"(?:/|$|\?)"),
    Signature("shell_command", "command_injection",
              "Operating-system command injection",
              r"[;|`]\s*(?:ls|cat|rm|wget|curl|nc|ping|id|whoami|uname)"
              r"(?=[\s;|&`)]|$)|\$\(|cmd\.exe|/bin/(?:ba)?sh"),
    Signature("log4shell", "template_injection",
              "JNDI / template injection (Log4Shell-style)",
              r"\$\{\s*(?:jndi|env|sys|java|lower|upper)\s*:",
              fields=("url", "body", "user_agent")),
    Signature("shellshock", "command_injection",
              "Shellshock-style function definition",
              r"\(\)\s*\{",
              fields=("url", "body", "user_agent")),
    Signature("null_byte", "encoding_abuse",
              "Null byte injection",
              r"\x00",
              fields=("url", "body", "user_agent")),
    Signature("crlf_injection", "encoding_abuse",
              "CR/LF header-injection characters",
              r"[\r\n]",
              fields=("url", "body", "user_agent")),
    Signature("format_string", "encoding_abuse",
              "Format-string attack",
              r"(?:%[sxnp]){3,}"),
    Signature("ssi_injection", "command_injection",
              "Server-side include injection",
              r"<!--\s*#\s*(?:exec|include|echo)"),
    Signature("scanner_user_agent", "scanner",
              "Known security-scanner User-Agent",
              r"\b(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster"
              r"|gobuster|wfuzz|zgrab|havij|w3af|burpsuite)\b",
              fields=("user_agent",)),
)

SCAN_FIELDS = ("url", "body", "user_agent")

COMPILED_SIGNATURES = tuple(
    (signature, re.compile(signature.pattern, re.IGNORECASE))
    for signature in SIGNATURES
)

# Jedno połączone wyrażenie na pole – szybka decyzja tak/nie.
COMBINED_PATTERNS = {
    field: re.compile(
        "|".join(
            f"(?:{signature.pattern})"
            for signature in SIGNATURES
            if field in signature.fields
        ),
        re.IGNORECASE,
    )
    for field in SCAN_FIELDS
}


def classify_user_agent(user_agent: str) -> str:
    value = (user_agent or "").lower()

    if not value:
        return "missing"
    if any(word in value for word in ("bot", "crawler", "spider")):
        return "bot"
    if any(word in value for word in ("mozilla", "chrome", "safari")):
        return "browser"

    return "other"


def _decode(text: str) -> str:
    """Dekoduje procent-encoding dwukrotnie (wykrywa %252e%252e itp.)."""
    return unquote_plus(unquote_plus(text))


def _split_target(url: str) -> tuple[str, str, bool]:
    """
    Zwraca (ścieżka, query, czy_url_uszkodzony). Schemat i host są
    odrzucane, dzięki czemu ``http://localhost:8080/a?x=1`` oraz
    ``/a?x=1`` dają te same cechy (logi Apache zawierają ścieżki
    względne, CSIC – pełne adresy).
    """
    try:
        parsed = urlsplit(url)
        return parsed.path or "/", parsed.query, False
    except ValueError:
        # Np. "http://[::1/x" – zachowujemy ścieżkę „na ile się da”
        # i oznaczamy żądanie jako uszkodzone zamiast zgłaszać wyjątek.
        target = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#]*", "", url)
        target = target.split("#", 1)[0]
        path, _, query = target.partition("?")
        return path or "/", query, True


def _parse_params(query: str) -> tuple[list[tuple[str, str]], bool]:
    """Zwraca (lista par nazwa/wartość, czy_przekroczono_limit)."""
    if not query:
        return [], False

    try:
        pairs = parse_qsl(
            query,
            keep_blank_values=True,
            max_num_fields=MAX_PARAMS,
        )
        return pairs, False
    except ValueError:
        truncated = "&".join(query.split("&")[:MAX_PARAMS])
        pairs = parse_qsl(truncated, keep_blank_values=True)
        return pairs, True


def _special_ratio(text: str) -> float:
    if not text:
        return 0.0

    special = sum(
        not char.isalnum() and char not in "/._-"
        for char in text
    )
    return special / len(text)


def _snippet(text: str, match: re.Match, radius: int = 12) -> str:
    """Fragment tekstu wokół trafienia, bezpieczny do wyświetlenia."""
    start = max(match.start() - radius, 0)
    end = min(match.end() + radius, len(text))
    fragment = text[start:end]

    return "".join(
        char if char.isprintable() else f"\\x{ord(char):02x}"
        for char in fragment
    )[:160]


def find_signatures(
    url: str,
    body: str = "",
    user_agent: str = "",
    limit: int = 5,
) -> list[dict]:
    """
    Zwraca opis trafionych sygnatur (nazwa, kategoria, pole, fragment).
    Używane tylko do wyjaśnień – decyzja zapada w extract_features.
    """
    path, query, _malformed = _split_target(url or "/")
    target = path + (f"?{query}" if query else "")

    texts = {
        "url": _decode(target),
        "body": _decode(body or ""),
        "user_agent": _decode(user_agent or ""),
    }

    matches = []
    for signature, regex in COMPILED_SIGNATURES:
        for field in signature.fields:
            found = regex.search(texts[field])

            if found:
                matches.append({
                    "signature": signature.name,
                    "category": signature.category,
                    "field": field,
                    "evidence": _snippet(texts[field], found),
                    "description": signature.description,
                })
                break

        if len(matches) >= limit:
            break

    return matches


def find_traversal(url: str, body: str = "") -> str | None:
    """Zwraca fragment z sekwencją ../ (lub None)."""
    path, query, _malformed = _split_target(url or "/")
    target = path + (f"?{query}" if query else "")

    for text in (_decode(target), _decode(body or "")):
        found = TRAVERSAL_PATTERN.search(text)
        if found:
            return _snippet(text, found)

    if ".." in [part for part in _decode(path).split("/") if part]:
        return _snippet(_decode(path), re.search(r"\.\.", _decode(path)))

    return None


def extract_features(
    method: str,
    url: str,
    user_agent: str = "",
    body: str = "",
) -> dict:
    """Ekstrahuje cechy z jednego żądania HTTP (nie zgłasza wyjątków)."""

    method = (method or "").upper()
    if method not in METHODS:
        method = "OTHER"

    url = url or "/"
    user_agent = user_agent or ""
    body = body or ""

    path, query, url_malformed = _split_target(url)
    target = path + (f"?{query}" if query else "")

    query_params, query_overflow = _parse_params(query)
    body_params, body_overflow = _parse_params(body)

    decoded_path = _decode(path)
    decoded_target = _decode(target)
    decoded_body = _decode(body)

    path_parts = [part for part in decoded_path.split("/") if part]

    has_traversal = (
        ".." in path_parts
        or bool(TRAVERSAL_PATTERN.search(decoded_target))
        or bool(TRAVERSAL_PATTERN.search(decoded_body))
    )

    has_suspicious = bool(
        COMBINED_PATTERNS["url"].search(decoded_target)
        or COMBINED_PATTERNS["body"].search(decoded_body)
        or COMBINED_PATTERNS["user_agent"].search(_decode(user_agent))
    )

    return {
        "method": method,
        "url_length": len(target),
        "path_length": len(path),
        "path_depth": len(path_parts),
        "query_param_count": len(query_params),
        "query_length": len(query),
        "special_char_ratio": _special_ratio(target),
        "has_encoded_chars": int(bool(ENCODED_PATTERN.search(target))),
        "has_path_traversal": int(has_traversal),
        "has_suspicious_keywords": int(has_suspicious),
        "user_agent_length": len(user_agent),
        "user_agent_category": classify_user_agent(user_agent),
        "body_length": len(body),
        "body_param_count": len(body_params),
        "body_special_char_ratio": _special_ratio(body),
        "path": decoded_path,
        "param_names": tuple(
            name for name, _value in query_params + body_params
        ),
        "is_malformed": int(
            url_malformed or query_overflow or body_overflow
        ),
    }


def parse_csic_block(block: str) -> dict:
    """Parsuje jeden blok żądania z CSIC 2010 (z ciałem żądania)."""

    normalized = block.replace("\r\n", "\n")

    # Nagłówki kończą się pierwszą pustą linią, dalej jest body.
    head, _, body = normalized.partition("\n\n")
    lines = head.splitlines()

    request_line = next(
        (
            line.strip()
            for line in lines
            if REQUEST_LINE.match(line.strip())
        ),
        None,
    )

    if request_line is None:
        raise ValueError("Nie znaleziono linii żądania HTTP.")

    match = REQUEST_LINE.match(request_line)
    method, url, _version = match.groups()

    headers = {}
    for line in lines:
        if line.strip() == request_line:
            continue
        if ":" not in line or line[:1].isspace():
            continue

        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    return {
        "method": method,
        "url": url,
        "user_agent": headers.get("user-agent", ""),
        "body": body.strip(),
    }


def load_csic_file(path: str | Path) -> list[dict]:
    """
    Wczytuje plik tekstowy CSIC zawierający kolejne żądania HTTP.
    Dzieli go po liniach rozpoczynających żądania, a nie po
    pustych liniach, ponieważ puste linie występują też w HTTP.
    """

    text = Path(path).read_text(encoding="utf-8", errors="replace")
    starts = list(CSIC_START.finditer(text))

    if not starts:
        raise ValueError(
            f"Nie znaleziono żądań HTTP w pliku: {path}"
        )

    requests = []
    for index, start in enumerate(starts):
        end = (
            starts[index + 1].start()
            if index + 1 < len(starts)
            else len(text)
        )
        block = text[start.start():end].strip()

        try:
            requests.append(parse_csic_block(block))
        except ValueError:
            continue

    if not requests:
        raise ValueError(f"Nie udało się sparsować pliku: {path}")

    return requests


def _unescape_apache(value: str) -> str:
    """Cofa escapowanie Apache: \\" \\\\ \\n \\t oraz \\xhh."""

    def replace(match: re.Match) -> str:
        token = match.group(1)

        if len(token) == 3 and token[0] == "x":
            return chr(int(token[1:], 16))

        return APACHE_SIMPLE_ESCAPES.get(token, match.group(0))

    return APACHE_ESCAPE.sub(replace, value)


def parse_apache_line(line: str) -> dict:
    """Parsuje pojedynczy wpis w formacie Combined Log Format."""

    match = APACHE_PATTERN.match(line.strip())

    if match is None:
        raise ValueError("Nieprawidłowy format wpisu Apache.")

    data = match.groupdict()
    request_match = REQUEST_LINE.match(_unescape_apache(data["request"]))

    if request_match is None:
        raise ValueError("Nieprawidłowa linia żądania w logu.")

    method, url, _version = request_match.groups()

    return {
        "method": method,
        "url": url,
        "user_agent": _unescape_apache(data.get("ua") or ""),
        "body": "",
    }


def load_apache_file(path: str | Path) -> list[dict]:
    requests = []

    with Path(path).open(encoding="utf-8", errors="replace") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                requests.append(parse_apache_line(line))
            except ValueError:
                print(
                    f"Pominięto nieprawidłowy wpis, "
                    f"linia {line_number}"
                )

    return requests


def requests_to_dataframe(requests: list[dict]) -> pd.DataFrame:
    rows = [
        extract_features(
            method=request["method"],
            url=request["url"],
            user_agent=request.get("user_agent", ""),
            body=request.get("body", ""),
        )
        for request in requests
    ]

    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)
