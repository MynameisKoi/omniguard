"""Spectral feature extraction using Fast Fourier Transform (FFT) and PSD.

Analyzes periodicity, peak harmonic frequencies, spectral entropy, and
power distribution to detect jittered beaconing loops (e.g. Sliver, Cobalt Strike).
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Sequence, Dict, Any, List
import numpy as np


@dataclass
class SpectralMetrics:
    """Frequency-domain signature of flow packet arrivals."""
    dominant_frequency: float      # Primary beacon frequency in Hz (e.g., 0.1 Hz -> 10s beacon)
    dominant_period: float         # Estimated beacon interval in seconds (1 / dominant_frequency)
    dominant_power: float          # PSD magnitude at dominant frequency
    total_power: float             # Integrated spectral energy
    peak_to_average_ratio: float   # PAPR: dominant_power / mean_power
    spectral_entropy: float        # Normalized Shannon entropy (0 = pure tone, 1 = white noise)
    periodicity_score: float       # Confidence metric [0.0, 1.0] that flow is an automated beacon
    spectrum: List[Dict[str, float]] # Top points for dashboard visualization [{frequency, power}]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_feature_vector(self) -> np.ndarray:
        """Returns 1D feature vector for classification."""
        return np.array([
            self.dominant_frequency,
            self.dominant_period,
            self.dominant_power,
            self.peak_to_average_ratio,
            self.spectral_entropy,
            self.periodicity_score,
        ], dtype=np.float32)


class SpectralFeatureExtractor:
    """Performs FFT and Power Spectral Density (PSD) analysis on flow packet arrivals."""

    def __init__(
        self,
        bin_size: float = 0.5,
        max_duration: float = 300.0,
        max_spectrum_points: int = 64,
    ):
        """
        Args:
            bin_size: Time discretization resolution in seconds (sampling rate = 1 / bin_size).
            max_duration: Maximum window length in seconds to analyze.
            max_spectrum_points: Maximum spectrum points returned for UI rendering.
        """
        self.bin_size = bin_size
        self.max_duration = max_duration
        self.max_spectrum_points = max_spectrum_points
        self.sampling_rate = 1.0 / bin_size

    def _discretize_signal(self, timestamps: Sequence[float]) -> np.ndarray:
        """Bins continuous packet timestamps into uniform time intervals."""
        if len(timestamps) < 2:
            return np.zeros(16, dtype=np.float64)

        ts = np.asarray(timestamps, dtype=np.float64)
        ts_norm = ts - ts[0]
        ts_norm = ts_norm[ts_norm <= self.max_duration]

        duration = max(ts_norm[-1], self.bin_size * 4)
        num_bins = int(np.ceil(duration / self.bin_size))
        num_bins = max(num_bins, 16)

        counts, _ = np.histogram(ts_norm, bins=num_bins, range=(0, num_bins * self.bin_size))
        return counts.astype(np.float64)

    def compute_fft(self, timestamps: Sequence[float]) -> SpectralMetrics:
        """Computes FFT and PSD on discretized packet arrival counts.

        Args:
            timestamps: Ordered packet arrival epoch timestamps.

        Returns:
            SpectralMetrics with frequency analysis and periodicity scores.
        """
        if len(timestamps) < 4:
            return SpectralMetrics(
                dominant_frequency=0.0,
                dominant_period=0.0,
                dominant_power=0.0,
                total_power=0.0,
                peak_to_average_ratio=0.0,
                spectral_entropy=1.0,
                periodicity_score=0.0,
                spectrum=[],
            )

        signal = self._discretize_signal(timestamps)
        n = len(signal)

        # Remove DC component (mean) to focus on periodic oscillations
        signal_zero_mean = signal - np.mean(signal)

        # Apply Hanning window to reduce spectral leakage
        window = np.hanning(n)
        windowed_signal = signal_zero_mean * window

        # Compute Real FFT
        fft_vals = np.fft.rfft(windowed_signal)
        frequencies = np.fft.rfftfreq(n, d=self.bin_size)

        # Power Spectral Density
        psd = (np.abs(fft_vals) ** 2) / (n * self.sampling_rate + 1e-12)

        # Ignore DC component index 0
        if len(psd) > 1:
            freq_active = frequencies[1:]
            psd_active = psd[1:]
        else:
            freq_active = frequencies
            psd_active = psd

        total_power = float(np.sum(psd_active))
        mean_power = float(np.mean(psd_active)) if len(psd_active) > 0 else 1e-12

        if total_power > 1e-12 and len(psd_active) > 0:
            max_p = float(np.max(psd_active))
            # Harmonic signals (Dirac combs) have multiple equal harmonics.
            # Select the lowest non-zero candidate frequency as fundamental frequency f_0.
            candidate_indices = np.where(psd_active >= 0.85 * max_p)[0]
            fundamental_idx = int(candidate_indices[0])
            dominant_freq = float(freq_active[fundamental_idx])
            dominant_power = float(psd_active[fundamental_idx])
            papr = float(max_p / (mean_power + 1e-12))

            # Spectral entropy: probability distribution of normalized PSD
            prob_dist = psd_active / total_power
            prob_dist = prob_dist[prob_dist > 1e-12]
            entropy = float(-np.sum(prob_dist * np.log2(prob_dist)))
            max_entropy = float(np.log2(len(psd_active))) if len(psd_active) > 1 else 1.0
            norm_entropy = float(entropy / max_entropy) if max_entropy > 0 else 1.0

            # Beacon periodicity confidence score:
            # High PAPR and low entropy indicate a sharp harmonic peak (even with 10%-50% jitter)
            # Sigmoid scaling on (PAPR / 4) * (1 - norm_entropy)
            raw_score = (min(papr, 20.0) / 5.0) * (1.0 - 0.7 * norm_entropy)
            periodicity_score = float(1.0 / (1.0 + np.exp(-raw_score + 2.0)))
            dominant_period = float(1.0 / dominant_freq) if dominant_freq > 1e-5 else 0.0
        else:
            dominant_freq = 0.0
            dominant_period = 0.0
            dominant_power = 0.0
            papr = 0.0
            norm_entropy = 1.0
            periodicity_score = 0.0

        # Sample down spectrum points for dashboard visualization
        step = max(1, len(freq_active) // self.max_spectrum_points)
        spectrum = [
            {
                "frequency": round(float(f), 4),
                "power": round(float(p), 4),
            }
            for f, p in zip(freq_active[::step], psd_active[::step])
        ]

        return SpectralMetrics(
            dominant_frequency=dominant_freq,
            dominant_period=dominant_period,
            dominant_power=dominant_power,
            total_power=total_power,
            peak_to_average_ratio=papr,
            spectral_entropy=norm_entropy,
            periodicity_score=periodicity_score,
            spectrum=spectrum,
        )
