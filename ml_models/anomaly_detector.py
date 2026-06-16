import os
from typing import Any, Dict, List, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


class AnomalyDetector:
    """
    Anomalous traffic detector using Isolation Forest.
    Features: bytes_sent, bytes_received, duration, packet_count.
    """

    def __init__(self, contamination: float = 0.05):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_trained = False
        self.features = ["bytes_sent", "bytes_received", "duration", "packet_count"]

    def train(self, df: pd.DataFrame):
        """
        Train the Isolation Forest model on flow features.
        Expects a DataFrame with features: bytes_sent, bytes_received, duration, packet_count.
        """
        if df.empty:
            raise ValueError("Training data is empty.")

        # Ensure all required features are present
        missing = [f for f in self.features if f not in df.columns]
        if missing:
            raise ValueError(f"Missing features in training data: {missing}")

        X = df[self.features]
        self.model.fit(X)
        self.is_trained = True

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        """
        Predict if flows are anomalous.
        Returns: 1 for normal, -1 for anomaly.
        """
        if not self.is_trained:
            raise ValueError("Model is not trained.")

        if df.empty:
            return np.array([])

        # Ensure all required features are present
        missing = [f for f in self.features if f not in df.columns]
        if missing:
            raise ValueError(f"Missing features in input data: {missing}")

        X = df[self.features]
        return self.model.predict(X)

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """
        Return anomaly scores. Lower values are more anomalous.
        """
        if not self.is_trained:
            raise ValueError("Model is not trained.")

        if df.empty:
            raise ValueError("Input DataFrame is empty.")

        # Ensure all required features are present
        missing = [f for f in self.features if f not in df.columns]
        if missing:
            raise ValueError(f"Missing features in input data: {missing}")

        X = df[self.features]
        return self.model.decision_function(X)

    def save(self, path: str):
        """Save the trained model to a file."""
        if not self.is_trained:
            raise ValueError("Cannot save an untrained model.")

        dirname = os.path.dirname(path)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        joblib.dump({"model": self.model, "features": self.features}, path)

    def load(self, path: str):
        """Load a trained model from a file."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found: {path}")

        data = joblib.load(path)

        if not isinstance(data, dict) or "model" not in data or "features" not in data:
            raise ValueError(f"Invalid model file structure at {path}")

        # Validate feature contract
        loaded_features = data["features"]
        if hasattr(self, "features") and self.features != loaded_features:
            raise ValueError(
                f"Feature mismatch: expected {self.features}, got {loaded_features}"
            )

        self.model = data["model"]
        self.features = loaded_features
        self.is_trained = True
