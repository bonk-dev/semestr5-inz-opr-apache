import argparse
import json
import time
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import torch
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from anomaly_detection.features import (
    load_csic_file,
    requests_to_dataframe,
)
from anomaly_detection.preprocessing import transform_data
from anomaly_detection.autoencoder import Autoencoder
from anomaly_detection.baseline import anomaly_scores
from anomaly_detection.rules import ALL_RULES, Vocabulary, apply_rules


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "raw"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Ocena modeli na zbiorze testowym CSIC 2010."
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=ROOT / "models",
    )
    parser.add_argument(
        "--strip-body",
        action="store_true",
        help=(
            "Usuwa ciała żądań z danych testowych (symulacja logów "
            "dostępu Apache). Użyj z modelem wytrenowanym z --strip-body."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "reports" / "evaluation.json",
    )
    return parser.parse_args()


def score_autoencoder(model, X):
    model.eval()
    results = []

    with torch.no_grad():
        for start in range(0, len(X), 512):
            batch = torch.as_tensor(
                X[start:start + 512],
                dtype=torch.float32,
            )
            reconstructed = model(batch)
            errors = ((batch - reconstructed) ** 2).mean(dim=1)
            results.extend(errors.numpy().tolist())

    return np.asarray(results)


def report(name, y_true, y_pred, threshold=None, latency_ms=None):
    y_pred = np.asarray(y_pred).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    ).ravel()

    fpr = fp / max(fp + tn, 1)

    return {
        "model": name,
        "threshold": None if threshold is None else float(threshold),
        "precision": float(
            precision_score(y_true, y_pred, zero_division=0)
        ),
        "recall": float(
            recall_score(y_true, y_pred, zero_division=0)
        ),
        "f1": float(
            f1_score(y_true, y_pred, zero_division=0)
        ),
        "false_positive_rate": float(fpr),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
        "scoring_latency_ms_per_request": latency_ms,
    }


def main():
    args = parse_args()
    model_dir = args.model_dir

    preprocessor = joblib.load(model_dir / "preprocessor.joblib")

    vocabulary_path = model_dir / "vocabulary.json"
    vocabulary = (
        Vocabulary.load(vocabulary_path)
        if vocabulary_path.exists()
        else None
    )

    normal = load_csic_file(DATA_DIR / "normalTrafficTest.txt")
    anomalous = load_csic_file(DATA_DIR / "anomalousTrafficTest.txt")

    requests = normal + anomalous

    if args.strip_body:
        requests = [{**request, "body": ""} for request in requests]

    y_true = np.array(
        [0] * len(normal) + [1] * len(anomalous)
    )

    X_df = requests_to_dataframe(requests)
    X = transform_data(preprocessor, X_df)
    n_requests = max(len(X), 1)

    # --- Reguły open-world (domyślne) ------------------------------
    started = time.perf_counter()
    rule_hits = apply_rules(X_df)
    rules_ms = (time.perf_counter() - started) * 1000 / n_requests
    rule_flags = np.array([bool(hits) for hits in rule_hits])

    normal_hits, anomalous_hits = Counter(), Counter()
    for hits, label in zip(rule_hits, y_true):
        target = anomalous_hits if label else normal_hits
        target.update(hits)

    rule_breakdown = {
        rule: {
            "normal": normal_hits[rule],
            "anomalous": anomalous_hits[rule],
        }
        for rule in sorted(set(normal_hits) | set(anomalous_hits))
    }

    # --- Autoencoder ----------------------------------------------
    checkpoint = torch.load(
        model_dir / "autoencoder.pt",
        map_location="cpu",
        weights_only=True,
    )

    model = Autoencoder(
        input_dim=checkpoint["input_dim"]
    )
    model.load_state_dict(checkpoint["state_dict"])

    with open(
        model_dir / "threshold.json",
        encoding="utf-8",
    ) as file:
        threshold = json.load(file)["threshold"]

    started = time.perf_counter()
    scores = score_autoencoder(model, X)
    ae_ms = (time.perf_counter() - started) * 1000 / n_requests
    ae_pred = scores > threshold

    # --- Isolation Forest -----------------------------------------
    baseline_data = joblib.load(model_dir / "baseline.joblib")
    baseline = baseline_data["model"]
    baseline_threshold = baseline_data["threshold"]

    started = time.perf_counter()
    baseline_scores = anomaly_scores(baseline, X)
    if_ms = (time.perf_counter() - started) * 1000 / n_requests
    if_pred = baseline_scores > baseline_threshold

    results = [
        report("Rules only (open-world)", y_true, rule_flags,
               latency_ms=rules_ms),
        report("Autoencoder", y_true, ae_pred,
               threshold, ae_ms),
        report("Autoencoder + rules", y_true, ae_pred | rule_flags,
               threshold, ae_ms + rules_ms),
        report("Isolation Forest", y_true, if_pred,
               baseline_threshold, if_ms),
        report("Isolation Forest + rules", y_true,
               if_pred | rule_flags, baseline_threshold,
               if_ms + rules_ms),
    ]

    # Diagnostyka: ile dają reguły „closed-world”. CSIC to jedna,
    # zamknięta aplikacja, więc wynik jest zawyżony względem realnego
    # serwera Apache – nie używać do oceny trybu open-world.
    if vocabulary is not None:
        closed_hits = apply_rules(X_df, vocabulary, ALL_RULES)
        closed_flags = np.array([bool(hits) for hits in closed_hits])

        results.append(
            report(
                "[diagnostic] Autoencoder + closed-world rules",
                y_true,
                ae_pred | closed_flags,
                threshold,
            )
        )

    output = {
        "strip_body": args.strip_body,
        "results": results,
        "rule_hits": rule_breakdown,
    }

    print(json.dumps(output, indent=2, ensure_ascii=False))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as file:
        json.dump(output, file, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
