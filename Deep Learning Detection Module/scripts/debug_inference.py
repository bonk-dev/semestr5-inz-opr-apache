from pathlib import Path

import joblib
import pandas as pd

from anomaly_detection.features import (
    extract_features,
    FEATURE_COLUMNS,
)

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models"

preprocessor = joblib.load(
    MODEL_DIR / "preprocessor.joblib"
)

features = extract_features(
    method="GET",
    url="http://en.wikipedia.org/wiki/Sea_balls",
    user_agent="Mozilla/5.0",
)

frame = pd.DataFrame(
    [features],
    columns=FEATURE_COLUMNS,
)

print("Extracted features:")
print(frame.T)

transformed = preprocessor.transform(frame)
feature_names = preprocessor.get_feature_names_out()

print("\nTransformed features:")
for name, value in zip(feature_names, transformed[0]):
    print(f"{name}: {value:.6f}")