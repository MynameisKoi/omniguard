"""Unit tests for SpectraC2 inference models and predictor."""

import sys
import os
import tempfile
import numpy as np
import pytest

engine_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "spectrac2-engine"))
if engine_root not in sys.path:
    sys.path.insert(0, engine_root)

from inference.dataset_generator import SyntheticFlowGenerator
from inference.isolation_forest import FlowIsolationForest
from inference.lstm_model import BeaconLSTM, SequencePreprocessor, TORCH_AVAILABLE
from inference.predictor import SpectraC2Predictor


class TestDatasetGenerator:
    def test_c2_beacon_generation(self):
        gen = SyntheticFlowGenerator(random_seed=123)
        flow = gen.generate_c2_beacon(base_interval=5.0, jitter_pct=0.2, num_packets=20)
        assert flow["label"] == 1
        assert len(flow["timestamps"]) == 20
        # Check monotonic timestamps
        ts = flow["timestamps"]
        assert all(ts[i] < ts[i + 1] for i in range(len(ts) - 1))

    def test_benign_traffic_generation(self):
        gen = SyntheticFlowGenerator(random_seed=123)
        flow = gen.generate_benign_traffic(num_packets=25)
        assert flow["label"] == 0
        assert len(flow["timestamps"]) == 25
        ts = flow["timestamps"]
        assert all(ts[i] < ts[i + 1] for i in range(len(ts) - 1))


class TestIsolationForest:
    def test_train_and_score(self):
        np.random.seed(42)
        X = np.random.randn(100, 20).astype(np.float32)
        detector = FlowIsolationForest(n_estimators=20, contamination=0.1)
        detector.fit(X)

        scores = detector.score_samples(X[:5])
        assert len(scores) == 5
        assert all(0.0 <= s <= 1.0 for s in scores)

    def test_save_and_load(self):
        np.random.seed(42)
        X = np.random.randn(50, 10).astype(np.float32)
        detector = FlowIsolationForest(n_estimators=10)
        detector.fit(X)

        with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            detector.save(tmp_path)
            loaded = FlowIsolationForest().load(tmp_path)
            assert loaded.is_fitted
            original_scores = detector.score_samples(X[:3])
            loaded_scores = loaded.score_samples(X[:3])
            np.testing.assert_allclose(original_scores, loaded_scores, rtol=1e-5)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


class TestLSTMModel:
    def test_sequence_preprocessing(self):
        ts = [10.0, 15.0, 20.0, 25.0]
        sizes = [100, 200, 300, 400]
        dirs = ["fwd", "bwd", "fwd", "bwd"]
        seq = SequencePreprocessor.flow_to_sequence(ts, sizes, dirs, max_len=10)
        assert seq.shape == (10, 3)
        # First row is initial packet (delta=0)
        assert seq[0, 0] == 0.0
        # Second row: delta = 5.0 -> 5.0 / 60.0
        assert pytest.approx(seq[1, 0], 0.01) == (5.0 / 60.0)
        assert pytest.approx(seq[1, 1], 0.01) == (200 / 1500.0)
        assert seq[1, 2] == -1.0  # bwd

    @pytest.mark.skipif(not TORCH_AVAILABLE, reason="PyTorch not installed")
    def test_lstm_forward_pass(self):
        import torch
        model = BeaconLSTM(input_size=3, hidden_size=16, num_layers=1)
        x = torch.zeros((2, 20, 3), dtype=torch.float32)
        out = model(x)
        assert out.shape == (2, 1)
        probs = out.detach().numpy()
        assert all(0.0 <= p[0] <= 1.0 for p in probs)


class TestPredictor:
    def test_predictor_e2e_beacon(self):
        gen = SyntheticFlowGenerator(random_seed=42)
        beacon = gen.generate_c2_beacon(base_interval=10.0, jitter_pct=0.1, num_packets=30)

        predictor = SpectraC2Predictor()
        result = predictor.analyze_flow(
            timestamps=beacon["timestamps"],
            packet_sizes=beacon["packet_sizes"],
            directions=beacon["directions"],
            flow_metadata={"host": "SRV-TEST", "src_ip": "10.0.0.5", "dst_ip": "198.51.100.1"},
        )

        assert "threat_score" in result
        assert "severity" in result
        assert "spectral_metrics" in result
        assert result["packet_count"] == 30
        assert result["threat_score"] > 0.50
