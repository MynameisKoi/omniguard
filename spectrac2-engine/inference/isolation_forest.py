"""Isolation Forest anomaly detection for flow metadata.

Uses statistical and spectral moments to identify anomalous beaconing patterns
without requiring labels (unsupervised).
"""

from __future__ import annotations

import os
from typing import Tuple
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class FlowIsolationForest:
    """Unsupervised Isolation Forest detector for network flow anomaly analysis."""

    def __init__(self, n_estimators: int = 100, contamination: float = 0.1, random_state: int = 42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray) -> FlowIsolationForest:
        """Fits scaler and Isolation Forest model.

        Args:
            X: 2D array of shape (n_samples, n_features).
        """
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_fitted = True
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Computes anomaly score in range [0, 1].

        Higher score indicates higher anomaly / beacon probability.
        """
        if not self.is_fitted:
            raise RuntimeError("Model has not been trained yet.")

        if X.ndim == 1:
            X = X.reshape(1, -1)

        X_scaled = self.scaler.transform(X)
        # raw decision_function returns negative values for outliers, positive for inliers
        raw_scores = self.model.decision_function(X_scaled)
        # Invert and scale to [0, 1] using sigmoid
        anomaly_prob = 1.0 / (1.0 + np.exp(raw_scores * 4.0))
        return anomaly_prob

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns 1 for anomalies (outliers), 0 for normal traffic."""
        scores = self.score_samples(X)
        return (scores >= 0.5).astype(int)

    def save(self, filepath: str) -> None:
        """Saves model and scaler bundle to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump({"scaler": self.scaler, "model": self.model, "is_fitted": self.is_fitted}, filepath)

    def load(self, filepath: str) -> FlowIsolationForest:
        """Loads model and scaler bundle from disk."""
        data = joblib.load(filepath)
        self.scaler = data["scaler"]
        self.model = data["model"]
        self.is_fitted = data.get("is_fitted", True)
        return self
