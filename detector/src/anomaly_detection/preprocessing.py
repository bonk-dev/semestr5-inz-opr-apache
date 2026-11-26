import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.feature_selection import VarianceThreshold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


NUMERIC_COLUMNS = [
    "url_length",
    "path_length",
    "path_depth",
    "query_param_count",
    "query_length",
    "special_char_ratio",
    "has_encoded_chars",
    "has_path_traversal",
    "has_suspicious_keywords",
    "user_agent_length",
    "body_length",
    "body_param_count",
    "body_special_char_ratio",
]

CATEGORICAL_COLUMNS = [
    "method",
    "user_agent_category",
]


def create_preprocessor():
    # Cechy stałe w zbiorze treningowym (np. has_path_traversal przy
    # samym normalnym ruchu) są usuwane – model nie może się ich nauczyć.
    # Ich sygnał przejmuje warstwa reguł (rules.py).
    numeric_pipeline = Pipeline([
        ("scale", StandardScaler()),
        ("remove_constant", VarianceThreshold(threshold=0.0)),
    ])

    return ColumnTransformer(
        transformers=[
            ("numeric", numeric_pipeline, NUMERIC_COLUMNS),
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=False,
                ),
                CATEGORICAL_COLUMNS,
            ),
        ],
        remainder="drop",
        verbose_feature_names_out=False,
    )


def fit_preprocessor(train_df: pd.DataFrame):
    preprocessor = create_preprocessor()
    X_train = preprocessor.fit_transform(train_df)

    return preprocessor, X_train.astype("float32")


def transform_data(preprocessor, data_df: pd.DataFrame):
    return preprocessor.transform(data_df).astype("float32")
