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

        X = df[self.features]
        return self.model.predict(X)

    def score(self, df: pd.DataFrame) -> np.ndarray:
        """
        Return anomaly scores. Lower values are more anomalous.
        """
        if not self.is_trained:
            raise ValueError("Model is not trained.")

        X = df[self.features]
        return self.model.decision_function(X)

    def save(self, path: str):
        """Save the trained model to a file."""
        if not self.is_trained:
            raise ValueError("Cannot save an untrained model.")

        os.makedirs(os.path.dirname(path), exist_ok=True)
        joblib.dump({"model": self.model, "features": self.features}, path)

    def load(self, path: str):
        """Load a trained model from a file."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found: {path}")

        data = joblib.load(path)
        self.model = data["model"]
        self.features = data["features"]
        self.is_trained = True
