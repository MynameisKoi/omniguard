"""PyTorch LSTM model for sequential C2 beacon classification.

Analyzes sequential packet inter-arrival times (IAT), directional flow, and
payload sizes to identify programmatic jittered beaconing loops.
"""

from __future__ import annotations

import os
from typing import Sequence, Tuple, Optional
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    nn = object  # type: ignore


if TORCH_AVAILABLE:
    class BeaconLSTM(nn.Module):
        """Bidirectional/Deep LSTM sequence classifier for flow packet timings."""

        def __init__(
            self,
            input_size: int = 3,      # [normalized_iat, normalized_size, direction]
            hidden_size: int = 64,
            num_layers: int = 2,
            dropout: float = 0.2,
        ):
            super().__init__()
            self.input_size = input_size
            self.hidden_size = hidden_size
            self.num_layers = num_layers

            self.lstm = nn.LSTM(
                input_size=input_size,
                hidden_size=hidden_size,
                num_layers=num_layers,
                batch_first=True,
                dropout=dropout if num_layers > 1 else 0.0,
                bidirectional=False,
            )
            self.fc1 = nn.Linear(hidden_size, 32)
            self.dropout = nn.Dropout(dropout)
            self.fc_out = nn.Linear(32, 1)

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            """
            Args:
                x: Tensor of shape (batch_size, seq_len, input_size)
            Returns:
                Beacon probability of shape (batch_size, 1) in range [0, 1]
            """
            # lstm_out: (batch_size, seq_len, hidden_size)
            lstm_out, (h_n, _) = self.lstm(x)
            # Use last layer hidden state: h_n[-1] has shape (batch_size, hidden_size)
            out = F.relu(self.fc1(h_n[-1]))
            out = self.dropout(out)
            prob = torch.sigmoid(self.fc_out(out))
            return prob
else:
    class BeaconLSTM:  # type: ignore
        def __init__(self, *args, **kwargs):
            raise RuntimeError("PyTorch is not installed in the environment.")


class SequencePreprocessor:
    """Prepares raw flow packet timestamps and metadata into standardized sequence tensors."""

    @staticmethod
    def flow_to_sequence(
        timestamps: Sequence[float],
        packet_sizes: Sequence[int] | None = None,
        directions: Sequence[str] | None = None,
        max_len: int = 60,
    ) -> np.ndarray:
        """Converts raw flow data into a (max_len, 3) matrix.

        Features per packet:
        1. normalized_iat: clamped to [0, 60] seconds and scaled to [0, 1]
        2. normalized_size: clamped to [0, 1500] bytes and scaled to [0, 1]
        3. direction: +1.0 for forward (egress), -1.0 for backward (ingress)
        """
        n = len(timestamps)
        seq = np.zeros((max_len, 3), dtype=np.float32)
        if n < 2:
            return seq

        ts = np.asarray(timestamps, dtype=np.float64)
        deltas = np.maximum(np.diff(ts), 0.0)
        # Pad deltas with 0.0 for initial packet
        iats = np.concatenate([[0.0], deltas])

        if packet_sizes is None:
            sizes = np.zeros(n, dtype=np.float32)
        else:
            sizes = np.asarray(packet_sizes, dtype=np.float32)

        if directions is None:
            dirs = np.ones(n, dtype=np.float32)
        else:
            dirs = np.array([1.0 if d == "fwd" else -1.0 for d in directions], dtype=np.float32)

        # Truncate or fit up to max_len
        valid_len = min(n, max_len)
        norm_iats = np.clip(iats[:valid_len] / 60.0, 0.0, 1.0)
        norm_sizes = np.clip(sizes[:valid_len] / 1500.0, 0.0, 1.0)
        norm_dirs = dirs[:valid_len]

        seq[:valid_len, 0] = norm_iats
        seq[:valid_len, 1] = norm_sizes
        seq[:valid_len, 2] = norm_dirs
        return seq


class LSTMBeaconClassifier:
    """Wrapper managing loading, inference, and serialization for BeaconLSTM."""

    def __init__(self, model_path: Optional[str] = None, device: str = "cpu"):
        self.device = device
        self.model: Optional[BeaconLSTM] = None
        self.is_loaded = False
        if TORCH_AVAILABLE:
            self.model = BeaconLSTM().to(device)
            if model_path and os.path.exists(model_path):
                self.load(model_path)

    def predict_proba(
        self,
        timestamps: Sequence[float],
        packet_sizes: Sequence[int] | None = None,
        directions: Sequence[str] | None = None,
    ) -> float:
        """Runs inference on a single flow, returning beacon probability [0.0, 1.0]."""
        if not TORCH_AVAILABLE or self.model is None or not self.is_loaded:
            return 0.0

        seq = SequencePreprocessor.flow_to_sequence(timestamps, packet_sizes, directions)
        x = torch.tensor(seq, dtype=torch.float32).unsqueeze(0).to(self.device)

        self.model.eval()
        with torch.no_grad():
            prob = self.model(x).item()
        return float(prob)

    def save(self, filepath: str) -> None:
        if not TORCH_AVAILABLE or self.model is None:
            return
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        torch.save(self.model.state_dict(), filepath)

    def load(self, filepath: str) -> None:
        if not TORCH_AVAILABLE:
            return
        self.model = BeaconLSTM().to(self.device)
        self.model.load_state_dict(torch.load(filepath, map_location=self.device, weights_only=True))
        self.model.eval()
        self.is_loaded = True

