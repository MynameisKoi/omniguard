"""SpectraC2 Inference Package

Provides dataset generation, model architectures (LSTM & Isolation Forest),
training loops, and unified prediction logic.
"""

from .dataset_generator import SyntheticFlowGenerator
from .isolation_forest import FlowIsolationForest
from .lstm_model import BeaconLSTM, LSTMBeaconClassifier, SequencePreprocessor
from .predictor import SpectraC2Predictor

__all__ = [
    "SyntheticFlowGenerator",
    "FlowIsolationForest",
    "BeaconLSTM",
    "LSTMBeaconClassifier",
    "SequencePreprocessor",
    "SpectraC2Predictor",
]
