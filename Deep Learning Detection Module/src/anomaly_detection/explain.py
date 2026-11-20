"""
Warstwa wyjaśnialności (XAI): zamienia decyzję detektora na opis, który
administrator potrafi zrozumieć bez znajomości modelu.

Wyjaśnienie ma dwie części:

1. ``reasons`` – konkretne powody „twarde”: która sygnatura / reguła
   zadziałała, w którym polu żądania i na jakim fragmencie tekstu.
2. ``top_features`` – powody „statystyczne”: które cechy najbardziej
   odbiegają od tego, co autoencoder nauczył się uznawać za normalne.
   Dla każdej cechy: wartość surowa, typowa wartość z treningu,
   odchylenie w jednostkach σ oraz udział w całkowitym błędzie
   rekonstrukcji.

Moduł nie zależy od PyTorcha – operuje na tablicach numpy.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

import numpy as np

from anomaly_detection.features import find_signatures, find_traversal
from anomaly_detection.rules import (
    MALFORMED_REQUEST,
    PATH_TRAVERSAL,
    SUSPICIOUS_PAYLOAD,
    UNKNOWN_METHOD,
    UNKNOWN_PARAMETER,
    UNKNOWN_PATH,
    Vocabulary,
)


FEATURE_LABELS = {
    "url_length": "URL length",
    "path_length": "Path length",
    "path_depth": "Path depth",
    "query_param_count": "Number of query parameters",
    "query_length": "Query-string length",
    "special_char_ratio": "Share of special characters in URL",
    "has_encoded_chars": "Percent-encoded characters in URL",
    "has_path_traversal": "Path traversal sequence",
    "has_suspicious_keywords": "Attack signature",
    "user_agent_length": "User-Agent length",
    "body_length": "Request body length",
    "body_param_count": "Number of body parameters",
    "body_special_char_ratio": "Share of special characters in body",
    "method": "HTTP method",
    "user_agent_category": "User-Agent type",
}

UNITS = {
    "url_length": "chars",
    "path_length": "chars",
    "query_length": "chars",
    "user_agent_length": "chars",
    "body_length": "chars",
}

RATIO_FEATURES = {"special_char_ratio", "body_special_char_ratio"}

BINARY_FEATURES = {
    "has_encoded_chars",
    "has_path_traversal",
    "has_suspicious_keywords",
}

# Poziomy ważności (heurystyka – patrz classify_severity).
SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}

FIELD_NAMES = {
    "url": "URL",
    "body": "request body",
    "user_agent": "User-Agent",
}


@dataclass(frozen=True)
class FeatureProfile:
    """Opis cechy wejściowej modelu, potrzebny do czytelnego wyjaśnienia."""

    name: str
    column: str
    label: str
    kind: str  # "numeric" | "binary" | "category"
    mean: float = 0.0
    std: float = 1.0
    category: str | None = None


def build_profiles(preprocessor) -> dict[str, FeatureProfile]:
    """Buduje profile cech na podstawie dopasowanego preprocessora."""

    profiles: dict[str, FeatureProfile] = {}

    numeric = preprocessor.named_transformers_["numeric"]
    scaler = numeric.named_steps["scale"]
    kept = numeric.named_steps["remove_constant"].get_support()

    for name, mean, scale, keep in zip(
        scaler.feature_names_in_, scaler.mean_, scaler.scale_, kept
    ):
        if not keep:
            continue

        name = str(name)
        profiles[name] = FeatureProfile(
            name=name,
            column=name,
            label=FEATURE_LABELS.get(name, name),
            kind="binary" if name in BINARY_FEATURES else "numeric",
            mean=float(mean),
            std=float(scale),
        )

    encoder = preprocessor.named_transformers_["categorical"]

    for column, categories in zip(
        encoder.feature_names_in_, encoder.categories_
    ):
        for category in categories:
            name = f"{column}_{category}"
            profiles[name] = FeatureProfile(
                name=name,
                column=str(column),
                label=FEATURE_LABELS.get(str(column), str(column)),
                kind="category",
                category=str(category),
            )

    return profiles


def _format(column: str, value: float) -> str:
    if column in RATIO_FEATURES:
        return f"{value:.1%}"

    if float(value).is_integer() or abs(value) >= 100:
        text = f"{value:,.0f}"
    else:
        text = f"{value:.3g}"

    unit = UNITS.get(column)
    return f"{text} {unit}" if unit else text


def _describe(
    profile: FeatureProfile,
    scaled_value: float,
    raw_features: Mapping,
) -> dict:
    raw = raw_features.get(profile.column)

    if profile.kind == "category":
        if scaled_value > 0.5:
            text = f"{profile.label} is {profile.category}"
        else:
            text = f"{profile.label} is '{raw}', not {profile.category}"

        return {"raw_value": raw, "description": text}

    if profile.kind == "binary":
        rate = min(max(profile.mean, 0.0), 1.0)

        if raw:
            text = (
                f"{profile.label} is present "
                f"(seen in {rate:.1%} of normal requests)"
            )
        else:
            text = (
                f"{profile.label} is absent "
                f"(normally present in {rate:.1%} of requests)"
            )

        return {
            "raw_value": raw,
            "typical_value": profile.mean,
            "typical_std": profile.std,
            "z_score": scaled_value,
            "direction": "higher" if raw else "lower",
            "description": text,
        }

    direction = "higher" if scaled_value >= 0 else "lower"
    text = (
        f"{profile.label} is {_format(profile.column, raw)}, "
        f"typical is {_format(profile.column, profile.mean)} "
        f"± {_format(profile.column, profile.std)} "
        f"({scaled_value:+.1f}σ)"
    )

    # Autoencoder ocenia całość: wartość może być zwyczajna sama w sobie,
    # a mimo to nie pasować do pozostałych cech (np. 5 parametrów
    # w URL-u o długości 700 znaków). Mówimy to wprost.
    if abs(scaled_value) < 2.0:
        text += "; unusual in combination with the other features"

    return {
        "raw_value": raw,
        "typical_value": profile.mean,
        "typical_std": profile.std,
        "z_score": scaled_value,
        "direction": direction,
        "description": text,
    }


def explain_features(
    original: Sequence[float],
    restored: Sequence[float],
    feature_names: Sequence[str],
    profiles: Mapping[str, FeatureProfile],
    raw_features: Mapping,
    top_k: int = 5,
) -> list[dict]:
    """Cechy o największym błędzie rekonstrukcji wraz z opisem."""

    original = np.asarray(original, dtype=float).ravel()
    restored = np.asarray(restored, dtype=float).ravel()

    errors = np.square(original - restored)
    total = float(errors.sum())
    order = np.argsort(errors)[::-1][:top_k]

    items = []

    for index in order:
        name = str(feature_names[index])
        profile = profiles.get(name)

        item = {
            "feature": name,
            "label": profile.label if profile else name,
            "input_value": float(original[index]),
            "reconstructed_value": float(restored[index]),
            "reconstruction_error": float(errors[index]),
            "error_share": float(errors[index] / total) if total > 0 else 0.0,
        }

        if profile is not None:
            item.update(
                _describe(profile, float(original[index]), raw_features)
            )
        else:
            item["description"] = f"{name} deviates from its reconstruction"

        items.append(item)

    return items


def _clip(text: str, limit: int = 160) -> str:
    return text if len(text) <= limit else text[:limit] + "..."


def build_reasons(
    rules: Sequence[str],
    features: Mapping,
    request: Mapping,
    vocabulary: Vocabulary | None = None,
) -> list[dict]:
    """Konkretne, „twarde” powody zadziałania reguł."""

    url = request.get("url", "")
    body = request.get("body", "")
    user_agent = request.get("user_agent", "")

    reasons = []

    def add(rule, category, description, evidence, signature=None, field=None):
        reasons.append({
            "rule": rule,
            "category": category,
            "signature": signature,
            "field": field,
            "evidence": evidence,
            "description": description,
        })

    if SUSPICIOUS_PAYLOAD in rules:
        for match in find_signatures(url, body, user_agent):
            reasons.append({"rule": SUSPICIOUS_PAYLOAD, **match})

    if PATH_TRAVERSAL in rules:
        add(PATH_TRAVERSAL, "path_traversal",
            "Directory traversal sequence (../)",
            find_traversal(url, body) or "", "path_traversal", "url")

    if MALFORMED_REQUEST in rules:
        add(MALFORMED_REQUEST, "malformed",
            "Malformed URL or more than 1000 parameters",
            _clip(url), None, "url")

    if vocabulary is not None:
        if UNKNOWN_PARAMETER in rules:
            names = sorted(
                {n for n in features["param_names"]
                 if n not in vocabulary.param_names}
            )
            add(UNKNOWN_PARAMETER, "novelty",
                "Parameter name never seen in training data",
                ", ".join(names[:5]), None, "url")

        if UNKNOWN_PATH in rules:
            add(UNKNOWN_PATH, "novelty",
                "Path never seen in training data",
                _clip(features["path"]), None, "url")

        if UNKNOWN_METHOD in rules:
            add(UNKNOWN_METHOD, "novelty",
                "HTTP method never seen in training data",
                features["method"], None, None)

    return reasons


def classify_severity(
    rules: Sequence[str],
    score_ratio: float,
) -> str:
    """
    Heurystyczna ważność (to nie jest skalibrowane prawdopodobieństwo):

    * high   – trafiła sygnatura ataku lub path traversal,
    * medium – uszkodzone żądanie, reguła „novelty” albo wynik modelu
               przekracza próg co najmniej dwukrotnie,
    * low    – wyłącznie nieznacznie ponadprogowy wynik modelu.
    """

    if SUSPICIOUS_PAYLOAD in rules or PATH_TRAVERSAL in rules:
        return "high"

    if rules or score_ratio >= 2.0:
        return "medium"

    return "low"


def build_summary(reasons: Sequence[Mapping], top_features: Sequence[Mapping]) -> str:
    """Jedno zdanie do listy zgłoszeń w panelu administratora."""

    if reasons:
        first = reasons[0]
        where = FIELD_NAMES.get(first.get("field"), "")
        place = (
            f" in {where}"
            if where and where not in first["description"]
            else ""
        )
        evidence = f": {first['evidence']}" if first.get("evidence") else ""
        extra = f" (+{len(reasons) - 1} more)" if len(reasons) > 1 else ""

        return _clip(f"{first['description']}{place}{evidence}{extra}")

    if top_features:
        return _clip(f"Unusual request shape. {top_features[0]['description']}")

    return "Unusual request shape"


def build_explanation(
    *,
    score: float,
    threshold: float,
    rules: Sequence[str],
    features: Mapping,
    request: Mapping,
    original: Sequence[float],
    restored: Sequence[float],
    feature_names: Sequence[str],
    profiles: Mapping[str, FeatureProfile],
    vocabulary: Vocabulary | None,
    flagged: bool,
    with_features: bool = True,
    top_k: int = 5,
) -> dict:
    """Składa pełne wyjaśnienie jednej decyzji detektora."""

    score_ratio = float(score / threshold) if threshold > 0 else 0.0

    top_features = (
        explain_features(
            original, restored, feature_names, profiles, features, top_k
        )
        if with_features
        else []
    )

    if not flagged:
        return {
            "score_ratio": score_ratio,
            "severity": "none",
            "summary": f"Within normal range ({score_ratio:.0%} of threshold)",
            "reasons": [],
            "top_features": top_features,
        }

    reasons = build_reasons(rules, features, request, vocabulary)

    return {
        "score_ratio": score_ratio,
        "severity": classify_severity(rules, score_ratio),
        "summary": build_summary(reasons, top_features),
        "reasons": reasons,
        "top_features": top_features,
    }
