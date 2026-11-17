import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException

from app.schemas import (
    BatchInput,
    BatchResponse,
    PredictionResponse,
    RequestInput,
)
from src.anomaly_detection.inference import AnomalyDetector


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = Path(
    os.getenv("MODEL_DIR", str(ROOT / "models"))
)

# Domyślnie tryb open-world. CLOSED_WORLD_RULES=1 włącza dodatkowo
# reguły „nieznana ścieżka / parametr / metoda” (tylko dla zamkniętych
# aplikacji – patrz rules.py).
CLOSED_WORLD = os.getenv("CLOSED_WORLD_RULES", "0") == "1"

REQUIRED_FILES = [
    "autoencoder.pt",
    "preprocessor.joblib",
    "threshold.json",
]

detector = None


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global detector

    if all((MODEL_DIR / name).exists() for name in REQUIRED_FILES):
        detector = AnomalyDetector(MODEL_DIR, closed_world=CLOSED_WORLD)

    yield


app = FastAPI(
    title="Apache Anomaly Detection API",
    version="0.3.0",
    lifespan=lifespan,
)


def require_detector() -> AnomalyDetector:
    if detector is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Model nie został załadowany. "
                "Najpierw uruchom scripts/train.py "
                "(po aktualizacji kodu model trzeba wytrenować ponownie)."
            ),
        )

    return detector


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": detector is not None,
        "threshold": detector.threshold if detector else None,
        "active_rules": list(detector.active_rules) if detector else [],
        "closed_world": CLOSED_WORLD,
    }


@app.post("/predict", response_model=PredictionResponse)
def predict(request: RequestInput):
    """Jedno żądanie; wyjaśnienie zwracane zawsze (wygodne do testów)."""

    model = require_detector()

    try:
        return model.predict(
            method=request.method,
            url=request.url,
            user_agent=request.user_agent,
            body=request.body,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc


@app.post("/predict/batch", response_model=BatchResponse)
def predict_batch(batch: BatchInput):
    """
    Do monitorowania na żywo: wyjaśnienia tylko dla oflagowanych żądań.
    Jedno wywołanie obsługuje do 1000 żądań.
    """

    model = require_detector()

    try:
        results = model.predict_batch(
            [item.model_dump() for item in batch.requests]
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    return {"results": results}
