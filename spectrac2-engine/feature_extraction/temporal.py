"""Temporal feature extraction for encrypted network flows.

Computes Inter-Arrival Time (IAT) statistics, timing jitter, and directional
packet/byte symmetry metrics for beacon detection.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, asdict
from typing import Sequence, Dict, Any
import numpy as np


@dataclass
class FlowMetrics:
    """Statistical summary of temporal and directional flow behavior."""
    packet_count: int
    duration: float
    fwd_packets: int
    bwd_packets: int
    fwd_bytes: int
    bwd_bytes: int
    total_bytes: int
    packet_ratio: float           # bwd_packets / max(1, fwd_packets)
    byte_ratio: float             # bwd_bytes / max(1, fwd_bytes)
    symmetry_index: float         # abs(fwd_bytes - bwd_bytes) / total_bytes
    mean_iat: float
    std_iat: float
    var_iat: float
    min_iat: float
    max_iat: float
    skew_iat: float
    kurt_iat: float
    cv_iat: float                 # std / mean (Coefficient of Variation)
    mean_jitter: float            # average absolute change in consecutive IATs
    bytes_per_sec: float
    packets_per_sec: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_feature_vector(self) -> np.ndarray:
        """Returns 1D feature vector for tabular anomaly detectors."""
        return np.array([
            self.packet_ratio,
            self.byte_ratio,
            self.symmetry_index,
            self.mean_iat,
            self.std_iat,
            self.var_iat,
            self.min_iat,
            self.max_iat,
            self.skew_iat,
            self.kurt_iat,
            self.cv_iat,
            self.mean_jitter,
            self.bytes_per_sec,
            self.packets_per_sec,
        ], dtype=np.float32)


class TemporalFeatureExtractor:
    """Extracts temporal moments and flow asymmetry from timestamped packet bursts."""

    @staticmethod
    def extract_iat(timestamps: Sequence[float]) -> np.ndarray:
        """Computes inter-arrival delta times Δt_i = t_i - t_{i-1}.

        Args:
            timestamps: Monotonically ordered packet arrival epoch timestamps.

        Returns:
            1D numpy array of delta times in seconds.
        """
        if len(timestamps) < 2:
            return np.array([], dtype=np.float64)
        ts = np.asarray(timestamps, dtype=np.float64)
        # Ensure non-negative deltas in case of out-of-order logs
        deltas = np.diff(ts)
        return np.maximum(deltas, 0.0)

    @classmethod
    def analyze_flow(
        cls,
        timestamps: Sequence[float],
        packet_sizes: Sequence[int] | None = None,
        directions: Sequence[str] | None = None,
    ) -> FlowMetrics:
        """Extracts complete temporal profile for a flow.

        Args:
            timestamps: Array of packet timestamps (seconds).
            packet_sizes: Sizes of packets in bytes. If None, assumes 0 for all.
            directions: Packet directions ('fwd' or 'bwd'). If None, treats all as 'fwd'.
        """
        n_pkts = len(timestamps)
        if n_pkts == 0:
            return FlowMetrics(
                packet_count=0, duration=0.0, fwd_packets=0, bwd_packets=0,
                fwd_bytes=0, bwd_bytes=0, total_bytes=0, packet_ratio=0.0,
                byte_ratio=0.0, symmetry_index=0.0, mean_iat=0.0, std_iat=0.0,
                var_iat=0.0, min_iat=0.0, max_iat=0.0, skew_iat=0.0,
                kurt_iat=0.0, cv_iat=0.0, mean_jitter=0.0,
                bytes_per_sec=0.0, packets_per_sec=0.0,
            )

        ts = np.asarray(timestamps, dtype=np.float64)
        duration = float(ts[-1] - ts[0]) if n_pkts > 1 else 0.0

        if packet_sizes is None:
            sizes = np.zeros(n_pkts, dtype=np.int64)
        else:
            sizes = np.asarray(packet_sizes, dtype=np.int64)

        if directions is None:
            dirs = np.array(["fwd"] * n_pkts)
        else:
            dirs = np.asarray(directions)

        # Directional packet & byte counts
        fwd_mask = dirs == "fwd"
        bwd_mask = ~fwd_mask

        fwd_packets = int(np.sum(fwd_mask))
        bwd_packets = int(np.sum(bwd_mask))

        fwd_bytes = int(np.sum(sizes[fwd_mask])) if fwd_packets > 0 else 0
        bwd_bytes = int(np.sum(sizes[bwd_mask])) if bwd_packets > 0 else 0
        total_bytes = fwd_bytes + bwd_bytes

        packet_ratio = float(bwd_packets / max(1, fwd_packets))
        byte_ratio = float(bwd_bytes / max(1, fwd_bytes))
        symmetry_index = float(abs(fwd_bytes - bwd_bytes) / max(1, total_bytes))

        # IAT calculations
        iat = cls.extract_iat(timestamps)
        if len(iat) > 0:
            mean_iat = float(np.mean(iat))
            var_iat = float(np.var(iat))
            std_iat = float(np.std(iat))
            min_iat = float(np.min(iat))
            max_iat = float(np.max(iat))

            # Skewness and Kurtosis
            if std_iat > 1e-9:
                centered = iat - mean_iat
                skew_iat = float(np.mean((centered / std_iat) ** 3))
                kurt_iat = float(np.mean((centered / std_iat) ** 4) - 3.0)  # Excess kurtosis
                cv_iat = float(std_iat / (mean_iat + 1e-9))
            else:
                skew_iat = 0.0
                kurt_iat = 0.0
                cv_iat = 0.0

            # Jitter: mean consecutive difference in IAT
            if len(iat) > 1:
                mean_jitter = float(np.mean(np.abs(np.diff(iat))))
            else:
                mean_jitter = 0.0
        else:
            mean_iat = std_iat = var_iat = min_iat = max_iat = 0.0
            skew_iat = kurt_iat = cv_iat = mean_jitter = 0.0

        eff_dur = max(duration, 0.001)
        bytes_per_sec = float(total_bytes / eff_dur)
        packets_per_sec = float(n_pkts / eff_dur)

        return FlowMetrics(
            packet_count=n_pkts,
            duration=duration,
            fwd_packets=fwd_packets,
            bwd_packets=bwd_packets,
            fwd_bytes=fwd_bytes,
            bwd_bytes=bwd_bytes,
            total_bytes=total_bytes,
            packet_ratio=packet_ratio,
            byte_ratio=byte_ratio,
            symmetry_index=symmetry_index,
            mean_iat=mean_iat,
            std_iat=std_iat,
            var_iat=var_iat,
            min_iat=min_iat,
            max_iat=max_iat,
            skew_iat=skew_iat,
            kurt_iat=kurt_iat,
            cv_iat=cv_iat,
            mean_jitter=mean_jitter,
            bytes_per_sec=bytes_per_sec,
            packets_per_sec=packets_per_sec,
        )
