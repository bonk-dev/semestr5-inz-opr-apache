import json
from collections.abc import Sequence
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch

from anomaly_detection.autoencoder import Autoencoder
from anomaly_detection.explain import build_explanation, build_profiles
from anomaly_detection.features import (
    extract_features,
    FEATURE_COLUMNS,
)
from anomaly_detection.rules import (
    ALL_RULES,
    OPEN_WORLD_RULES,
    Vocabulary,
    triggered_rules,
)


class AnomalyDetector:
    def __init__(self, model_dir: str | Path, closed_world: bool = False):
        model_dir = Path(model_dir)

        self.preprocessor = joblib.load(
            model_dir / "preprocessor.joblib"
        )

        vocabulary_path = model_dir / "vocabulary.json"
        self.vocabulary = (
            Vocabulary.load(vocabulary_path)
            if vocabulary_path.exists()
            else None
        )

        if closed_world and self.vocabulary is None:
            raise FileNotFoundError(
                "Tryb closed-world wymaga pliku vocabulary.json."
            )

        self.closed_world = closed_world
        self.active_rules = ALL_RULES if closed_world else OPEN_WORLD_RULES

        checkpoint = torch.load(
            model_dir / "autoencoder.pt",
            map_location="cpu",
            weights_only=True,
        )

        self.model = Autoencoder(
            input_dim=checkpoint["input_dim"]
        )
        self.model.load_state_dict(checkpoint["state_dict"])
        self.model.eval()

        with (model_dir / "threshold.json").open(
            encoding="utf-8"
        ) as file:
            self.threshold = float(
                json.load(file)["threshold"]
            )

        self.feature_names = list(
            self.preprocessor.get_feature_names_out()
        )
        self.profiles = build_profiles(self.preprocessor)

    def predict(
        self,
        method: str,
        url: str,
        user_agent: str = "",
        body: str = "",
    ) -> dict:
        """Pojedyncze żądanie – wyjaśnienie zwracane zawsze (do testów)."""

        request = {
            "method": method,
            "url": url,
            "user_agent": user_agent,
            "body": body,
        }
        return self.predict_batch([request], explain_all=True)[0]

    def predict_batch(
        self,
        requests: Sequence[dict],
        explain_all: bool = False,
    ) -> list[dict]:
        """
        Ocenia wiele żądań jednym przebiegiem preprocessora i sieci
        (pojedyncze wywołanie sklearn kosztuje ~2,5 ms, partia 1000
        wierszy ~0,005 ms na żądanie). Wyjaśnienia budowane są tylko
        dla żądań oflagowanych, chyba że explain_all=True.
        """

        if not requests:
            return []

        features = [
            extract_features(
                method=request.get("method", ""),
                url=request.get("url", ""),
                user_agent=request.get("user_agent", ""),
                body=request.get("body", ""),
            )
            for request in requests
        ]

        frame = pd.DataFrame(features, columns=FEATURE_COLUMNS)
        X = self.preprocessor.transform(frame).astype("float32")

        if not np.isfinite(X).all():
            raise ValueError(
                "Preprocessing wygenerował nieprawidłowe wartości."
            )

        tensor = torch.from_numpy(np.ascontiguousarray(X))

        with torch.no_grad():
            reconstructed = self.model(tensor)
            scores = ((tensor - reconstructed) ** 2).mean(dim=1)

        originals = tensor.numpy()
        restored = reconstructed.numpy()
        scores = scores.numpy()

        results = []

        for index, request in enumerate(requests):
            score = float(scores[index])
            rules = triggered_rules(
                features[index], self.vocabulary, self.active_rules
            )
            flagged = bool(score > self.threshold or rules)

            explanation = build_explanation(
                score=score,
                threshold=self.threshold,
                rules=rules,
                features=features[index],
                request=request,
                original=originals[index],
                restored=restored[index],
                feature_names=self.feature_names,
                profiles=self.profiles,
                vocabulary=self.vocabulary if self.closed_world else None,
                flagged=flagged,
                with_features=flagged or explain_all,
            )

            results.append({
                "anomaly_score": score,
                "threshold": self.threshold,
                "is_anomaly": flagged,
                "triggered_rules": rules,
                **explanation,
            })

        return results
