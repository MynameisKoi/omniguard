"""Trainer for SpectraC2 beacon detection models (LSTM & Isolation Forest).

Trains models on jittered C2 beacons vs benign traffic, computes validation
metrics (Precision, Recall, F1), and saves production model checkpoints.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Dict, Any, Tuple
import numpy as np

# Ensure root paths are importable
current_dir = os.path.dirname(os.path.abspath(__file__))
engine_root = os.path.dirname(current_dir)
if engine_root not in sys.path:
    sys.path.insert(0, engine_root)

from feature_extraction.temporal import TemporalFeatureExtractor
from feature_extraction.spectral import SpectralFeatureExtractor

from inference.dataset_generator import SyntheticFlowGenerator
from inference.isolation_forest import FlowIsolationForest
from inference.lstm_model import BeaconLSTM, SequencePreprocessor, TORCH_AVAILABLE

if TORCH_AVAILABLE:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset


def extract_features_for_tabular(
    dataset: list[Dict[str, Any]],
    spectral_extractor: SpectralFeatureExtractor,
) -> Tuple[np.ndarray, np.ndarray]:
    """Converts raw dataset flows into tabular feature matrix X and labels y."""
    X_list = []
    y_list = []

    for item in dataset:
        ts = item["timestamps"]
        sizes = item.get("packet_sizes")
        dirs = item.get("directions")

        t_metrics = TemporalFeatureExtractor.analyze_flow(ts, sizes, dirs)
        s_metrics = spectral_extractor.compute_fft(ts)

        # Concatenate 14 temporal features + 6 spectral features = 20 features
        feat = np.concatenate([t_metrics.to_feature_vector(), s_metrics.to_feature_vector()])
        # Replace any potential NaN / Inf with 0.0
        feat = np.nan_to_num(feat, nan=0.0, posinf=1.0, neginf=0.0)

        X_list.append(feat)
        y_list.append(item["label"])

    return np.array(X_list, dtype=np.float32), np.array(y_list, dtype=np.int64)


def extract_sequences_for_lstm(
    dataset: list[Dict[str, Any]],
    max_len: int = 60,
) -> Tuple[np.ndarray, np.ndarray]:
    """Converts dataset flows into 3D sequence tensor (N, max_len, 3) and labels y."""
    X_seq = []
    y_list = []

    for item in dataset:
        seq = SequencePreprocessor.flow_to_sequence(
            item["timestamps"],
            item.get("packet_sizes"),
            item.get("directions"),
            max_len=max_len,
        )
        X_seq.append(seq)
        y_list.append(item["label"])

    return np.array(X_seq, dtype=np.float32), np.array(y_list, dtype=np.float32)


def train_models(
    n_samples: int = 2000,
    epochs: int = 15,
    batch_size: int = 32,
    lr: float = 0.001,
    output_dir: str = "models",
) -> Dict[str, Any]:
    """Trains both Isolation Forest and PyTorch LSTM models and outputs metrics."""
    os.makedirs(output_dir, exist_ok=True)
    print(f"[*] Generating {n_samples} synthetic network flows...")
    gen = SyntheticFlowGenerator()
    dataset = gen.generate_dataset(n_samples=n_samples, packets_per_flow=50)

    # 80/20 train/validation split
    split_idx = int(len(dataset) * 0.8)
    train_data = dataset[:split_idx]
    val_data = dataset[split_idx:]

    spectral_ext = SpectralFeatureExtractor()

    # 1. Train Isolation Forest
    print("[*] Training Isolation Forest model on temporal + spectral features...")
    X_train_tab, y_train_tab = extract_features_for_tabular(train_data, spectral_ext)
    X_val_tab, y_val_tab = extract_features_for_tabular(val_data, spectral_ext)

    iso_forest = FlowIsolationForest(n_estimators=120, contamination=0.5)
    # Train Isolation Forest on normal background flows (unsupervised) or full set
    iso_forest.fit(X_train_tab)
    iso_scores = iso_forest.score_samples(X_val_tab)
    iso_preds = (iso_scores >= 0.5).astype(int)

    iso_acc = float(np.mean(iso_preds == y_val_tab))
    iso_save_path = os.path.join(output_dir, "isolation_forest.joblib")
    iso_forest.save(iso_save_path)
    print(f"[+] Isolation Forest saved to {iso_save_path} (Validation Accuracy: {iso_acc:.2%})")

    # 2. Train PyTorch LSTM Classifier
    lstm_metrics = {}
    if TORCH_AVAILABLE:
        print(f"[*] Training PyTorch BeaconLSTM for {epochs} epochs...")
        X_train_seq, y_train_seq = extract_sequences_for_lstm(train_data)
        X_val_seq, y_val_seq = extract_sequences_for_lstm(val_data)

        train_tensor_x = torch.tensor(X_train_seq, dtype=torch.float32)
        train_tensor_y = torch.tensor(y_train_seq, dtype=torch.float32).unsqueeze(1)
        val_tensor_x = torch.tensor(X_val_seq, dtype=torch.float32)
        val_tensor_y = torch.tensor(y_val_seq, dtype=torch.float32).unsqueeze(1)

        train_loader = DataLoader(
            TensorDataset(train_tensor_x, train_tensor_y),
            batch_size=batch_size,
            shuffle=True,
        )

        device = "cuda" if torch.cuda.is_available() else "cpu"
        model = BeaconLSTM(input_size=3, hidden_size=64, num_layers=2, dropout=0.2).to(device)
        criterion = nn.BCELoss()
        optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)

        for epoch in range(1, epochs + 1):
            model.train()
            total_loss = 0.0
            for batch_x, batch_y in train_loader:
                batch_x, batch_y = batch_x.to(device), batch_y.to(device)
                optimizer.zero_grad()
                preds = model(batch_x)
                loss = criterion(preds, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item() * len(batch_x)

            epoch_loss = total_loss / len(train_data)
            if epoch % 5 == 0 or epoch == epochs:
                # Validation evaluation
                model.eval()
                with torch.no_grad():
                    val_preds = model(val_tensor_x.to(device)).cpu().numpy()
                    val_pred_labels = (val_preds >= 0.5).astype(int)
                    accuracy = np.mean(val_pred_labels == y_val_seq.reshape(-1, 1))
                print(f"    Epoch {epoch}/{epochs} | Loss: {epoch_loss:.4f} | Val Acc: {accuracy:.2%}")

        # Final metrics
        model.eval()
        with torch.no_grad():
            final_probs = model(val_tensor_x.to(device)).cpu().numpy().flatten()
            final_preds = (final_probs >= 0.5).astype(int)
            y_true = y_val_seq.astype(int)

            tp = np.sum((final_preds == 1) & (y_true == 1))
            fp = np.sum((final_preds == 1) & (y_true == 0))
            fn = np.sum((final_preds == 0) & (y_true == 1))

            precision = float(tp / (tp + fp + 1e-9))
            recall = float(tp / (tp + fn + 1e-9))
            f1 = float(2 * precision * recall / (precision + recall + 1e-9))

        lstm_save_path = os.path.join(output_dir, "spectrac2_lstm.pt")
        torch.save(model.state_dict(), lstm_save_path)
        print(f"[+] PyTorch BeaconLSTM saved to {lstm_save_path}")
        print(f"[+] Precision: {precision:.2%} | Recall: {recall:.2%} | F1: {f1:.2%}")
        lstm_metrics = {"precision": precision, "recall": recall, "f1": f1}

    return {
        "isolation_forest_acc": iso_acc,
        "lstm_metrics": lstm_metrics,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SpectraC2 beacon detection models")
    parser.add_argument("--samples", type=int, default=1200, help="Number of synthetic samples")
    parser.add_argument("--epochs", type=int, default=12, help="LSTM training epochs")
    parser.add_argument("--output", type=str, default="spectrac2-engine/inference/models", help="Model directory")
    args = parser.parse_args()

    train_models(n_samples=args.samples, epochs=args.epochs, output_dir=args.output)
