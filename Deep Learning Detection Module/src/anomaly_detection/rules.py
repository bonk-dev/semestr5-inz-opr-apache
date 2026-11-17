"""
Deterministyczna warstwa reguł działająca obok autoencodera.

Autoencoder uczy się wyłącznie na normalnym ruchu, więc nie potrafi
wykorzystać cech, które w tym ruchu nigdy się nie zmieniają (np.
``has_suspicious_keywords`` jest zawsze 0 – po standaryzacji cecha jest
stała i usuwana). Reguły pokrywają ten przypadek.

Dwa tryby:

* OPEN_WORLD_RULES (domyślny) – reguły oparte na wzorcach, niezależne od
  aplikacji: sygnatury ataków, path traversal, uszkodzone żądania.
  Nadają się do serwera Apache obsługującego dowolne domeny i ścieżki.
* CLOSED_WORLD_RULES (opcjonalny) – „nigdy nie widziana ścieżka /
  parametr / metoda”. Zakładają zamkniętą aplikację, w której dane
  treningowe obejmują wszystkie poprawne adresy. W otwartym środowisku
  (nowe strony, parametry marketingowe, identyfikatory w ścieżkach)
  generują lawinę fałszywych alarmów – dlatego są domyślnie wyłączone.
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

import pandas as pd


MALFORMED_REQUEST = "malformed_request"
PATH_TRAVERSAL = "path_traversal"
SUSPICIOUS_PAYLOAD = "suspicious_payload"
UNKNOWN_PARAMETER = "unknown_parameter"
UNKNOWN_PATH = "unknown_path"
UNKNOWN_METHOD = "unknown_method"

OPEN_WORLD_RULES = (
    MALFORMED_REQUEST,
    PATH_TRAVERSAL,
    SUSPICIOUS_PAYLOAD,
)

CLOSED_WORLD_RULES = (
    UNKNOWN_PARAMETER,
    UNKNOWN_PATH,
    UNKNOWN_METHOD,
)

ALL_RULES = OPEN_WORLD_RULES + CLOSED_WORLD_RULES

# Domyślnie tylko reguły niezależne od aplikacji.
ACTIVE_RULES = OPEN_WORLD_RULES


@dataclass(frozen=True)
class Vocabulary:
    """Zbiory ścieżek, nazw parametrów i metod widzianych w treningu."""

    paths: frozenset[str]
    param_names: frozenset[str]
    methods: frozenset[str]

    @classmethod
    def fit(cls, df: pd.DataFrame) -> "Vocabulary":
        return cls(
            paths=frozenset(df["path"]),
            param_names=frozenset(
                name for names in df["param_names"] for name in names
            ),
            methods=frozenset(df["method"]),
        )

    def save(self, path: str | Path) -> None:
        with Path(path).open("w", encoding="utf-8") as file:
            json.dump(
                {
                    "paths": sorted(self.paths),
                    "param_names": sorted(self.param_names),
                    "methods": sorted(self.methods),
                },
                file,
                indent=2,
                ensure_ascii=False,
            )

    @classmethod
    def load(cls, path: str | Path) -> "Vocabulary":
        with Path(path).open(encoding="utf-8") as file:
            data = json.load(file)

        return cls(
            paths=frozenset(data["paths"]),
            param_names=frozenset(data["param_names"]),
            methods=frozenset(data["methods"]),
        )


def triggered_rules(
    row: Mapping,
    vocabulary: Vocabulary | None = None,
    active: Iterable[str] = ACTIVE_RULES,
) -> list[str]:
    """Zwraca nazwy reguł wyzwolonych przez jedno żądanie."""

    active = set(active)
    hits = []

    if MALFORMED_REQUEST in active and row["is_malformed"]:
        hits.append(MALFORMED_REQUEST)

    if PATH_TRAVERSAL in active and row["has_path_traversal"]:
        hits.append(PATH_TRAVERSAL)

    if SUSPICIOUS_PAYLOAD in active and row["has_suspicious_keywords"]:
        hits.append(SUSPICIOUS_PAYLOAD)

    # Reguły „closed-world” wymagają słownika z treningu.
    if vocabulary is None:
        return hits

    if UNKNOWN_PARAMETER in active and any(
        name not in vocabulary.param_names
        for name in row["param_names"]
    ):
        hits.append(UNKNOWN_PARAMETER)

    if UNKNOWN_PATH in active and row["path"] not in vocabulary.paths:
        hits.append(UNKNOWN_PATH)

    if UNKNOWN_METHOD in active and (
        row["method"] not in vocabulary.methods
    ):
        hits.append(UNKNOWN_METHOD)

    return hits


def apply_rules(
    df: pd.DataFrame,
    vocabulary: Vocabulary | None = None,
    active: Iterable[str] = ACTIVE_RULES,
) -> list[list[str]]:
    """Zwraca listę wyzwolonych reguł dla każdego wiersza ramki."""

    active = tuple(active)

    return [
        triggered_rules(row, vocabulary, active)
        for row in df.to_dict("records")
    ]
