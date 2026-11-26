from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
preprocessor = joblib.load(
    ROOT / "models" / "preprocessor.joblib"
)

# "numeric" to Pipeline (scale -> remove_constant), a nie sam scaler.
numeric = preprocessor.named_transformers_["numeric"]
scaler = numeric.named_steps["scale"]
kept = numeric.named_steps["remove_constant"].get_support()

for name, mean, scale, variance, is_kept in zip(
    scaler.feature_names_in_,
    scaler.mean_,
    scaler.scale_,
    scaler.var_,
    kept,
):
    status = "kept" if is_kept else "DROPPED (constant)"
    print(
        f"{name:28s} "
        f"mean={mean:12.6f} "
        f"scale={scale:12.6f} "
        f"variance={variance:12.6f} "
        f"{status}"
    )
