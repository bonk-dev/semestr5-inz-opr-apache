from pydantic import BaseModel, Field


class RequestInput(BaseModel):
    method: str = Field(min_length=1, max_length=20)
    url: str = Field(min_length=1, max_length=8192)
    user_agent: str = Field(default="", max_length=2048)
    # Ciało żądania w formacie application/x-www-form-urlencoded.
    body: str = Field(default="", max_length=65536)


class BatchInput(BaseModel):
    requests: list[RequestInput] = Field(min_length=1, max_length=1000)


class Reason(BaseModel):
    """Konkretny, „twardy” powód oflagowania (sygnatura / reguła)."""

    rule: str
    category: str
    signature: str | None = None
    field: str | None = None  # url | body | user_agent
    evidence: str = ""
    description: str


class FeatureExplanation(BaseModel):
    """Cecha, którą autoencoder najgorzej odtworzył."""

    feature: str
    label: str = ""
    input_value: float
    reconstructed_value: float
    reconstruction_error: float
    error_share: float = 0.0
    raw_value: float | int | str | None = None
    typical_value: float | None = None
    typical_std: float | None = None
    z_score: float | None = None
    direction: str | None = None  # higher | lower
    description: str = ""


class PredictionResponse(BaseModel):
    anomaly_score: float
    threshold: float
    score_ratio: float
    # True, jeśli wynik przekracza próg LUB zadziałała choć jedna reguła.
    is_anomaly: bool
    severity: str  # none | low | medium | high
    summary: str = ""
    triggered_rules: list[str] = Field(default_factory=list)
    reasons: list[Reason] = Field(default_factory=list)
    top_features: list[FeatureExplanation] = Field(default_factory=list)


class BatchResponse(BaseModel):
    results: list[PredictionResponse]
