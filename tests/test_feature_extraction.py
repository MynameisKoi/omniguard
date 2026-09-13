"""Unit tests for SpectraC2 temporal and spectral feature extraction."""

import sys
import os
import numpy as np
import pytest

# Add spectrac2-engine to sys.path
engine_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "spectrac2-engine"))
if engine_root not in sys.path:
    sys.path.insert(0, engine_root)

import importlib
temporal_mod = importlib.import_module("feature-extraction.temporal")
spectral_mod = importlib.import_module("feature-extraction.spectral")
TemporalFeatureExtractor = temporal_mod.TemporalFeatureExtractor
SpectralFeatureExtractor = spectral_mod.SpectralFeatureExtractor


class TestTemporalFeatureExtraction:
    def test_empty_flow(self):
        metrics = TemporalFeatureExtractor.analyze_flow([])
        assert metrics.packet_count == 0
        assert metrics.mean_iat == 0.0
        assert metrics.duration == 0.0

    def test_single_packet(self):
        metrics = TemporalFeatureExtractor.analyze_flow([1000.0])
        assert metrics.packet_count == 1
        assert metrics.mean_iat == 0.0
        assert metrics.duration == 0.0

    def test_constant_iat(self):
        # 10 packets with exactly 5.0 seconds between each
        timestamps = [100.0 + i * 5.0 for i in range(10)]
        metrics = TemporalFeatureExtractor.analyze_flow(timestamps)
        assert metrics.packet_count == 10
        assert pytest.approx(metrics.mean_iat, 0.01) == 5.0
        assert pytest.approx(metrics.var_iat, 0.01) == 0.0
        assert pytest.approx(metrics.std_iat, 0.01) == 0.0
        assert pytest.approx(metrics.cv_iat, 0.01) == 0.0
        assert pytest.approx(metrics.mean_jitter, 0.01) == 0.0

    def test_directional_symmetry(self):
        timestamps = [100.0, 101.0, 102.0, 103.0]
        sizes = [100, 200, 100, 200]
        dirs = ["fwd", "bwd", "fwd", "bwd"]
        metrics = TemporalFeatureExtractor.analyze_flow(timestamps, sizes, dirs)
        assert metrics.fwd_packets == 2
        assert metrics.bwd_packets == 2
        assert metrics.fwd_bytes == 200
        assert metrics.bwd_bytes == 400
        assert metrics.packet_ratio == 1.0
        assert metrics.byte_ratio == 2.0
        assert pytest.approx(metrics.symmetry_index, 0.01) == (200 / 600)


class TestSpectralFeatureExtraction:
    def test_periodic_beacon_frequency(self):
        # Generate clean 5-second beacon -> frequency = 1 / 5 = 0.20 Hz
        timestamps = [i * 5.0 for i in range(30)]
        extractor = SpectralFeatureExtractor(bin_size=0.5)
        metrics = extractor.compute_fft(timestamps)

        # Dominant frequency should be close to 0.20 Hz (+/- 0.05 Hz binning error)
        assert abs(metrics.dominant_frequency - 0.20) < 0.05
        assert metrics.dominant_period > 0.0
        assert metrics.periodicity_score > 0.60
        assert metrics.spectral_entropy < 0.70

    def test_random_traffic_spectral(self):
        # Generate uniformly random packet arrival timestamps
        np.random.seed(42)
        timestamps = np.cumsum(np.random.exponential(scale=2.0, size=50)).tolist()
        extractor = SpectralFeatureExtractor(bin_size=0.5)
        metrics = extractor.compute_fft(timestamps)

        # High entropy and low periodicity score for Poisson/exponential noise
        assert metrics.spectral_entropy > 0.60
        assert metrics.periodicity_score < 0.60
