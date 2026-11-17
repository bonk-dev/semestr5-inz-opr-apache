import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.model_selection import train_test_split

from anomaly_detection.features import (
    load_apache_file,
    load_csic_file,
    requests_to_dataframe,
)
from anomaly_detection.preprocessing import (
    fit_preprocessor,
    transform_data,
)
from anomaly_detection.autoencoder import Autoencoder
from anomaly_detection.baseline import create_baseline, anomaly_scores
from anomaly_detection.rules import Vocabulary, apply_rules


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data" / "raw"

DEFAULT_TRAIN_FILE = DATA_DIR / "normalTrafficTraining.txt"
DEFAULT_MODEL_DIR = ROOT / "models"

LOADERS = {
    "csic": load_csic_file,
    "apache": load_apache_file,
}

EPOCHS = 50
BATCH_SIZE = 128
LEARNING_RATE = 1e-3
RANDOM_SEED = 42

# 0.999 = ok. 0,1% fałszywych alarmów na normalnym ruchu. Przy 50 tys.
# żądań dziennie to ~50 zgłoszeń do przejrzenia (0.99 dałoby ~500).
DEFAULT_THRESHOLD_QUANTILE = 0.999


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Trenuje autoencoder na NORMALNYM ruchu HTTP. "
            "Aby wykrywać anomalie w logach Apache, trenuj na "
            "własnych logach (--format apache), a nie na CSIC."
        )
    )
    parser.add_argument(
        "--train-file",
        type=Path,
        default=DEFAULT_TRAIN_FILE,
        help="Plik z normalnym ruchem (domyślnie: CSIC training).",
    )
    parser.add_argument(
        "--format",
        choices=sorted(LOADERS),
        default="csic",
        help="Format pliku treningowego: csic lub apache.",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=DEFAULT_MODEL_DIR,
        help="Katalog na artefakty modelu.",
    )
    parser.add_argument(
        "--threshold-quantile",
        type=float,
        default=DEFAULT_THRESHOLD_QUANTILE,
        help="Kwantyl błędu rekonstrukcji (walidacja) użyty jako próg.",
    )
    parser.add_argument(
        "--strip-body",
        action="store_true",
        help=(
            "Ignoruje ciała żądań (symuluje logi dostępu Apache, "
            "które nie zawierają body)."
        ),
    )
    return parser.parse_args()


def reconstruction_scores(model, X, batch_size=512):
    model.eval()
    scores = []

    with torch.no_grad():
        for start in range(0, len(X), batch_size):
            batch = torch.as_tensor(
                X[start:start + batch_size],
                dtype=torch.float32,
            )

            reconstructed = model(batch)
            errors = ((batch - reconstructed) ** 2).mean(dim=1)
            scores.extend(errors.cpu().numpy().tolist())

    return np.asarray(scores)


def main():
    args = parse_args()
    model_dir = args.model_dir
    quantile = args.threshold_quantile

    if not 0.5 < quantile < 1.0:
        raise ValueError("--threshold-quantile musi należeć do (0.5, 1).")

    torch.manual_seed(RANDOM_SEED)
    np.random.seed(RANDOM_SEED)

    model_dir.mkdir(parents=True, exist_ok=True)

    if not args.train_file.exists():
        raise FileNotFoundError(
            f"Nie znaleziono zbioru treningowego: {args.train_file}"
        )

    print(f"1. Wczytywanie normalnych żądań ({args.format})...")
    requests = LOADERS[args.format](args.train_file)

    if args.strip_body:
        requests = [{**request, "body": ""} for request in requests]

    if len(requests) < 100:
        raise ValueError(
            "Za mało żądań do trenowania "
            f"({len(requests)}). Sprawdź plik i format."
        )

    full_df = requests_to_dataframe(requests)

    # Logi „normalnego” ruchu z internetu zawsze zawierają skanery.
    # Żądania z oczywistymi sygnaturami ataków nie mogą uczyć modelu,
    # że atak jest normalny (ani trafić do słownika).
    clean = (
        (full_df["has_suspicious_keywords"] == 0)
        & (full_df["has_path_traversal"] == 0)
        & (full_df["is_malformed"] == 0)
    ).to_numpy()
    removed = int((~clean).sum())

    if removed:
        print(
            f"UWAGA: pominięto {removed} z {len(full_df)} żądań "
            "treningowych zawierających sygnatury ataków."
        )

    full_df = full_df[clean].reset_index(drop=True)

    train_df, val_df = train_test_split(
        full_df,
        test_size=0.15,
        random_state=RANDOM_SEED,
    )
    train_df = train_df.reset_index(drop=True)
    val_df = val_df.reset_index(drop=True)

    print(f"Żądania treningowe: {len(train_df)}")
    print(f"Żądania walidacyjne: {len(val_df)}")

    if len(val_df) * (1 - quantile) < 10:
        print(
            f"OSTRZEŻENIE: zbiór walidacyjny ({len(val_df)}) jest za mały, "
            f"by stabilnie wyznaczyć kwantyl {quantile}. "
            "Użyj większej liczby logów lub niższego kwantyla."
        )

    print("2. Dopasowanie preprocessingu i słownika reguł...")
    preprocessor, X_train = fit_preprocessor(train_df)
    X_val = transform_data(preprocessor, val_df)

    joblib.dump(
        preprocessor,
        model_dir / "preprocessor.joblib",
    )

    # Słownik służy tylko opcjonalnym regułom „closed-world”
    # (domyślnie wyłączonym – patrz rules.py).
    vocabulary = Vocabulary.fit(train_df)
    vocabulary.save(model_dir / "vocabulary.json")

    print(
        f"Słownik: {len(vocabulary.paths)} ścieżek, "
        f"{len(vocabulary.param_names)} nazw parametrów, "
        f"{len(vocabulary.methods)} metod"
    )

    val_rule_hits = apply_rules(val_df)
    rule_fpr = sum(bool(hits) for hits in val_rule_hits) / max(
        len(val_rule_hits), 1
    )
    print(
        "Reguły (open-world) – fałszywe alarmy na walidacji: "
        f"{rule_fpr:.2%}"
    )

    input_dim = X_train.shape[1]
    print(f"Liczba cech po preprocessingu: {input_dim}")

    print("3. Trenowanie autoencodera...")
    model = Autoencoder(input_dim=input_dim)
    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=LEARNING_RATE,
    )
    criterion = nn.MSELoss()

    dataset = TensorDataset(torch.from_numpy(X_train))
    generator = torch.Generator().manual_seed(RANDOM_SEED)

    loader = DataLoader(
        dataset,
        batch_size=BATCH_SIZE,
        shuffle=True,
        generator=generator,
    )

    for epoch in range(EPOCHS):
        model.train()
        total_loss = 0.0
        total_samples = 0

        for (batch,) in loader:
            optimizer.zero_grad()

            reconstructed = model(batch)
            loss = criterion(reconstructed, batch)

            loss.backward()
            optimizer.step()

            total_loss += loss.item() * len(batch)
            total_samples += len(batch)

        average_loss = total_loss / max(total_samples, 1)

        if (epoch + 1) % 5 == 0 or epoch == 0:
            print(
                f"Epoka {epoch + 1}/{EPOCHS}: "
                f"loss={average_loss:.6f}"
            )

    print("4. Dobór progu anomalii...")
    val_scores = reconstruction_scores(model, X_val)
    print("\nStatystyki błędu rekonstrukcji walidacji:")
    print(f"Min:    {val_scores.min():.6f}")
    print(f"Median: {np.median(val_scores):.6f}")
    print(f"Mean:   {val_scores.mean():.6f}")
    print(f"P95:    {np.quantile(val_scores, 0.95):.6f}")
    print(f"P99:    {np.quantile(val_scores, 0.99):.6f}")
    print(f"Max:    {val_scores.max():.6f}")

    threshold = float(np.quantile(val_scores, quantile))

    print(f"Próg autoencodera (kwantyl {quantile}): {threshold:.6f}")

    torch.save(
        {
            "state_dict": model.state_dict(),
            "input_dim": int(input_dim),
        },
        model_dir / "autoencoder.pt",
    )

    with (model_dir / "threshold.json").open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            {
                "threshold": threshold,
                "quantile": quantile,
                "strip_body": args.strip_body,
            },
            file,
            indent=2,
        )

    print("5. Trenowanie baseline Isolation Forest...")
    baseline = create_baseline()
    baseline.fit(X_train)

    baseline_val_scores = anomaly_scores(baseline, X_val)
    baseline_threshold = float(
        np.quantile(baseline_val_scores, quantile)
    )

    joblib.dump(
        {
            "model": baseline,
            "threshold": baseline_threshold,
        },
        model_dir / "baseline.joblib",
    )

    print(f"Zapisano artefakty w katalogu {model_dir}.")
    print("Możesz teraz uruchomić skrypt evaluate.py.")


if __name__ == "__main__":
    main()
