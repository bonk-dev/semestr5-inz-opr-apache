
from sklearn.ensemble import IsolationForest


def create_baseline():
    return IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )


def anomaly_scores(model, X):
    # Wyższa wartość oznacza większą anomalię.
    return -model.decision_function(X)
