import numpy as np

from anomaly_detection.explain import (
    build_explanation,
    build_profiles,
    build_reasons,
    build_summary,
    classify_severity,
    explain_features,
)
from anomaly_detection.features import extract_features, requests_to_dataframe
from anomaly_detection.preprocessing import fit_preprocessor
from anomaly_detection.rules import (
    PATH_TRAVERSAL,
    SUSPICIOUS_PAYLOAD,
    UNKNOWN_PATH,
    Vocabulary,
)


def fitted():
    requests = []
    for i in range(300):
        requests.append({
            "method": "POST" if i % 3 == 0 else "GET",
            "url": f"/shop/item?id={i}&page={i % 7}" + "x" * (i % 20),
            "user_agent": "Mozilla/5.0" if i % 5 else "Googlebot/2.1",
            "body": "a=1&b=2" * (i % 4) if i % 3 == 0 else "",
        })

    frame = requests_to_dataframe(requests)
    preprocessor, X = fit_preprocessor(frame)
    return preprocessor, X, frame


def test_profiles_cover_every_model_feature():
    preprocessor, _X, _frame = fitted()
    profiles = build_profiles(preprocessor)

    for name in preprocessor.get_feature_names_out():
        assert name in profiles, name

    assert profiles["url_length"].kind == "numeric"
    assert profiles["method_POST"].kind == "category"
    assert profiles["method_POST"].column == "method"


def test_numeric_profile_matches_training_statistics():
    preprocessor, _X, frame = fitted()
    profile = build_profiles(preprocessor)["url_length"]

    assert abs(profile.mean - frame["url_length"].mean()) < 1e-6
    assert abs(profile.std - frame["url_length"].std(ddof=0)) < 1e-6


def test_explain_features_ranks_by_error_and_describes_values():
    preprocessor, X, _frame = fitted()
    profiles = build_profiles(preprocessor)
    names = list(preprocessor.get_feature_names_out())

    attack = extract_features("GET", "/shop/item?id=1&q=" + "A" * 900)
    original = preprocessor.transform(
        requests_to_dataframe([
            {"method": "GET", "url": "/shop/item?id=1&q=" + "A" * 900}
        ])
    )[0]
    restored = np.zeros_like(original)

    items = explain_features(original, restored, names, profiles, attack, top_k=3)

    assert len(items) == 3
    errors = [item["reconstruction_error"] for item in items]
    assert errors == sorted(errors, reverse=True)
    assert 0.0 < sum(item["error_share"] for item in items) <= 1.0 + 1e-9

    top = items[0]
    assert top["z_score"] > 3
    assert top["direction"] == "higher"
    assert "typical" in top["description"]
    assert str(top["raw_value"]) in top["description"].replace(",", "")


def test_explain_features_describes_categories():
    preprocessor, _X, _frame = fitted()
    profiles = build_profiles(preprocessor)
    names = list(preprocessor.get_feature_names_out())
    features = extract_features("PUT", "/shop/item?id=1")

    original = np.zeros(len(names))
    restored = np.zeros(len(names))
    index = names.index("method_GET")
    restored[index] = 1.0

    item = explain_features(original, restored, names, profiles, features, 1)[0]

    assert item["feature"] == "method_GET"
    assert "PUT" in item["description"]


def test_reasons_name_the_signature_field_and_evidence():
    request = {
        "method": "GET",
        "url": "/p?id=1' UNION SELECT a,b FROM c--",
        "user_agent": "sqlmap/1.7",
        "body": "",
    }
    features = extract_features(**request)

    reasons = build_reasons([SUSPICIOUS_PAYLOAD], features, request)

    assert reasons and all(set(r) == {
        "rule", "category", "signature", "field", "evidence", "description"
    } for r in reasons)
    assert {r["field"] for r in reasons} == {"url", "user_agent"}
    assert any(r["signature"] == "scanner_user_agent" for r in reasons)


def test_reasons_for_traversal_and_closed_world():
    vocabulary = Vocabulary(
        paths=frozenset({"/a"}),
        param_names=frozenset({"id"}),
        methods=frozenset({"GET"}),
    )
    request = {"method": "GET", "url": "/b/../../etc/x?zz=1", "user_agent": "", "body": ""}
    features = extract_features(**request)

    reasons = build_reasons(
        [PATH_TRAVERSAL, UNKNOWN_PATH], features, request, vocabulary
    )

    by_rule = {r["rule"]: r for r in reasons}
    assert "../" in by_rule[PATH_TRAVERSAL]["evidence"]
    assert by_rule[UNKNOWN_PATH]["evidence"].startswith("/b/")


def test_severity_levels():
    assert classify_severity([SUSPICIOUS_PAYLOAD], 0.1) == "high"
    assert classify_severity([PATH_TRAVERSAL], 0.1) == "high"
    assert classify_severity([UNKNOWN_PATH], 0.1) == "medium"
    assert classify_severity([], 2.5) == "medium"
    assert classify_severity([], 1.2) == "low"


def test_summary_prefers_reasons_and_falls_back_to_features():
    reasons = [{
        "rule": SUSPICIOUS_PAYLOAD, "field": "url",
        "description": "SQL injection: UNION SELECT",
        "evidence": "' UNION SELECT a", "category": "sql_injection",
    }]

    text = build_summary(reasons, [])
    assert "UNION SELECT" in text and "in URL" in text

    fallback = build_summary([], [{"description": "URL length is 900 chars"}])
    assert "URL length is 900 chars" in fallback


def test_build_explanation_for_normal_and_flagged_requests():
    preprocessor, X, _frame = fitted()
    profiles = build_profiles(preprocessor)
    names = list(preprocessor.get_feature_names_out())
    request = {"method": "GET", "url": "/shop/item?id=3", "user_agent": "Mozilla/5.0", "body": ""}
    features = extract_features(**request)

    common = dict(
        threshold=0.05, features=features, request=request,
        original=X[0], restored=X[0] * 0.9, feature_names=names,
        profiles=profiles, vocabulary=None,
    )

    normal = build_explanation(score=0.01, rules=[], flagged=False, with_features=False, **common)
    assert normal["severity"] == "none" and normal["reasons"] == []
    assert normal["top_features"] == [] and "normal range" in normal["summary"]

    flagged = build_explanation(score=0.2, rules=[], flagged=True, **common)
    assert flagged["severity"] == "medium"          # 4x threshold
    assert abs(flagged["score_ratio"] - 4.0) < 1e-9
    assert flagged["top_features"] and flagged["summary"].startswith("Unusual request shape")
