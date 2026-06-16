import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Add the project root to sys.path to import AnomalyDetector
sys.path.append(str(Path(__file__).resolve().parents[2]))

from ml_models.anomaly_detector import AnomalyDetector


def generate_synthetic_data(
    n_samples: int = 1000, anomaly_ratio: float = 0.05, seed: int = 42
):
    """
    Generate synthetic network flow data.
    Normal: Low to medium bytes, short duration.
    Anomalous: Very high bytes or very long duration.
    """
    np.random.seed(seed)
    n_anomalies = int(n_samples * anomaly_ratio)
    n_normal = n_samples - n_anomalies

    # Normal data
    normal_data = {
        "bytes_sent": np.random.normal(500, 200, n_normal).clip(50, 2000),
        "bytes_received": np.random.normal(1000, 500, n_normal).clip(100, 5000),
        "duration": np.random.normal(5, 2, n_normal).clip(0.1, 20),
        "packet_count": np.random.normal(10, 5, n_normal).clip(1, 100),
    }

    # Anomalous data (High volume exfiltration)
    anomalous_data = {
        "bytes_sent": np.random.normal(100000, 20000, n_anomalies).clip(50000, 500000),
        "bytes_received": np.random.normal(5000, 1000, n_anomalies).clip(1000, 10000),
        "duration": np.random.normal(300, 100, n_anomalies).clip(60, 1000),
        "packet_count": np.random.normal(500, 100, n_anomalies).clip(100, 2000),
    }

    df_normal = pd.DataFrame(normal_data)
    df_anomalous = pd.DataFrame(anomalous_data)

    return pd.concat([df_normal, df_anomalous]).sample(frac=1).reset_index(drop=True)


def main():
    print("Generating synthetic training data...")
    df = generate_synthetic_data(2000)

    detector = AnomalyDetector(contamination=0.05)
    print("Training Isolation Forest model...")
    detector.train(df)

    model_path = os.path.join(
        os.path.dirname(__file__), "..", "saved_models", "anomaly_detector.joblib"
    )
    print(f"Saving model to {model_path}...")
    detector.save(model_path)

    # Verification
    test_normal = pd.DataFrame(
        {
            "bytes_sent": [600],
            "bytes_received": [1200],
            "duration": [6],
            "packet_count": [12],
        }
    )
    test_anomaly = pd.DataFrame(
        {
            "bytes_sent": [200000],
            "bytes_received": [5000],
            "duration": [500],
            "packet_count": [800],
        }
    )

    print(f"Normal test prediction: {detector.predict(test_normal)[0]} (Expected 1)")
    print(f"Anomaly test prediction: {detector.predict(test_anomaly)[0]} (Expected -1)")


if __name__ == "__main__":
    main()
