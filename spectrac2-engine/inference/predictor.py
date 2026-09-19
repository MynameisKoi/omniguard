"""Unified predictor for SpectraC2 beacon detection.

Combines FFT/PSD spectral density, temporal moments, LSTM sequence classification,
and Isolation Forest anomaly detection to produce calibrated threat scores and
normalized OmniGuard SOC alert payloads.
"""

from __future__ import annotations

import os
import sys
from typing import Sequence, Dict, Any, Optional
import numpy as np

current_dir = os.path.dirname(os.path.abspath(__file__))
engine_root = os.path.dirname(current_dir)
if engine_root not in sys.path:
    sys.path.insert(0, engine_root)

from feature_extraction.temporal import TemporalFeatureExtractor
from feature_extraction.spectral import SpectralFeatureExtractor

from inference.lstm_model import LSTMBeaconClassifier
from inference.isolation_forest import FlowIsolationForest


class SpectraC2Predictor:
    """Unified multi-modal beaconing inference engine."""

    def __init__(
        self,
        lstm_checkpoint: Optional[str] = None,
        iso_forest_checkpoint: Optional[str] = None,
        spectral_bin_size: float = 0.5,
        beacon_threshold: float = 0.65,
    ):
        self.spectral_extractor = SpectralFeatureExtractor(bin_size=spectral_bin_size)
        self.beacon_threshold = beacon_threshold

        # Automatically check for default saved model checkpoints if none passed
        models_dir = os.path.join(engine_root, "inference", "models")
        if lstm_checkpoint is None:
            default_lstm = os.path.join(models_dir, "spectrac2_lstm.pt")
            if os.path.exists(default_lstm):
                lstm_checkpoint = default_lstm

        if iso_forest_checkpoint is None:
            default_iso = os.path.join(models_dir, "isolation_forest.joblib")
            if os.path.exists(default_iso):
                iso_forest_checkpoint = default_iso

        # Initialize models
        self.lstm = LSTMBeaconClassifier(model_path=lstm_checkpoint)
        self.iso_forest: Optional[FlowIsolationForest] = None
        if iso_forest_checkpoint and os.path.exists(iso_forest_checkpoint):
            self.iso_forest = FlowIsolationForest().load(iso_forest_checkpoint)

    def analyze_flow(
        self,
        timestamps: Sequence[float],
        packet_sizes: Optional[Sequence[int]] = None,
        directions: Optional[Sequence[str]] = None,
        flow_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Runs end-to-end temporal, spectral, and neural inference on a flow.

        Args:
            timestamps: Packet arrival timestamps (epoch seconds).
            packet_sizes: Packet payload sizes in bytes.
            directions: Packet directions ('fwd' or 'bwd').
            flow_metadata: Network flow identifiers (host, src_ip, dst_ip, domain, user).

        Returns:
            Dictionary containing threat scores, spectral harmonics, and SOC alert.
        """
        meta = flow_metadata or {}
        n_packets = len(timestamps)

        # 1. Feature extraction
        temporal_metrics = TemporalFeatureExtractor.analyze_flow(timestamps, packet_sizes, directions)
        spectral_metrics = self.spectral_extractor.compute_fft(timestamps)

        # 2. LSTM Sequential Inference
        lstm_prob = self.lstm.predict_proba(timestamps, packet_sizes, directions)

        # 3. Isolation Forest Anomaly Scoring
        iso_prob = 0.0
        if self.iso_forest and self.iso_forest.is_fitted:
            feat_vec = np.concatenate([
                temporal_metrics.to_feature_vector(),
                spectral_metrics.to_feature_vector(),
            ])
            feat_vec = np.nan_to_num(feat_vec, nan=0.0, posinf=1.0, neginf=0.0)
            iso_prob = float(self.iso_forest.score_samples(feat_vec)[0])

        # 4. Ensemble Fusion
        # If LSTM is available and trained, weight: 0.50 LSTM, 0.30 FFT Periodicity, 0.20 Isolation Forest
        # If models are not trained yet, spectral periodicity and IAT metrics dominate
        if self.lstm.model is not None and lstm_prob > 0.0:
            if iso_prob > 0.0:
                ensemble_score = (0.50 * lstm_prob) + (0.30 * spectral_metrics.periodicity_score) + (0.20 * iso_prob)
            else:
                ensemble_score = (0.60 * lstm_prob) + (0.40 * spectral_metrics.periodicity_score)
        else:
            # Fallback to spectral periodicity and low IAT coefficient of variation
            cv_confidence = max(0.0, 1.0 - min(temporal_metrics.cv_iat, 1.0))
            ensemble_score = (0.65 * spectral_metrics.periodicity_score) + (0.35 * cv_confidence)

        ensemble_score = float(np.clip(ensemble_score, 0.0, 1.0))
        # Flag beacon if ensemble score exceeds threshold or if trained LSTM is strongly confident (>= 0.80)
        is_beacon = (ensemble_score >= self.beacon_threshold or (lstm_prob >= 0.80 and self.lstm.is_loaded)) and n_packets >= 6

        # Determine severity level
        if ensemble_score >= 0.80 or lstm_prob >= 0.90:
            severity = "critical"
        elif ensemble_score >= 0.65 or lstm_prob >= 0.75:
            severity = "high"
        elif ensemble_score >= 0.50 or lstm_prob >= 0.60:
            severity = "medium"
        else:
            severity = "low"

        # Build normalized SOC alert if detected
        alert = None
        if is_beacon:
            period_str = f"~{spectral_metrics.dominant_period:.1f}s" if spectral_metrics.dominant_period > 0 else "unknown"
            desc = (
                f"Encrypted C2 beacon loop detected on host {meta.get('host', 'UNKNOWN')} "
                f"targeting {meta.get('dst_ip', meta.get('domain', 'external listener'))}. "
                f"Dominant beacon interval: {period_str} with {temporal_metrics.mean_jitter:.2f}s mean jitter "
                f"(SpectraC2 confidence: {ensemble_score:.1%})."
            )
            alert = {
                "source": "spectrac2",
                "event_type": "c2_beacon_detected",
                "severity": severity,
                "host": meta.get("host", "HOST-UNKNOWN"),
                "user": meta.get("user"),
                "src_ip": meta.get("src_ip"),
                "domain": meta.get("domain"),
                "mitre_technique": "T1071",
                "status": "new",
                "description": desc,
            }

        return {
            "is_beacon": is_beacon,
            "threat_score": round(ensemble_score, 4),
            "severity": severity,
            "packet_count": n_packets,
            "temporal_metrics": temporal_metrics.to_dict(),
            "spectral_metrics": spectral_metrics.to_dict(),
            "model_scores": {
                "lstm_probability": round(lstm_prob, 4),
                "isolation_forest_anomaly": round(iso_prob, 4),
                "fft_periodicity": round(spectral_metrics.periodicity_score, 4),
            },
            "alert": alert,
        }
