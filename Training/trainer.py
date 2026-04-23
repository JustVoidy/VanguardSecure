"""
DDoS Detection — FFNN (PyTorch + CUDA)
=======================================
Training data  : CIC-DDoS2019
  - Syn.csv   (TCP SYN flood attacks + benign traffic)
  - UDP.csv   (UDP flood attacks + benign traffic)

Only features that Scapy can derive at runtime are used:

  PACKET-COUNT / SIZE (17)
    Total Fwd Packets, Total Backward Packets
    Total Length of Fwd Packets, Total Length of Bwd Packets
    Fwd Packet Length {Max, Min, Mean, Std}
    Bwd Packet Length {Max, Min, Mean, Std}
    Min/Max/Mean/Std/Variance Packet Length

  RATE (4)
    Flow Bytes/s, Flow Packets/s, Fwd Packets/s, Bwd Packets/s

  INTER-ARRIVAL TIME (15)
    Flow IAT {Mean, Std, Max, Min}
    Fwd IAT  {Total, Mean, Std, Max, Min}
    Bwd IAT  {Total, Mean, Std, Max, Min}

  HEADER / FLAGS (11)
    Fwd/Bwd Header Length
    FIN, SYN, RST, PSH, ACK, URG Flag Count
    Destination Port
    Init_Win_bytes_forward, Init_Win_bytes_backward
    Down/Up Ratio

Total: 47 features
"""

import argparse
import json
import os
import pathlib
import warnings

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

MODEL_PATH   = "ddos_ffnn.pt"
SCALER_PATH  = "ddos_scaler.pkl"
FEATURE_PATH = "ddos_features.pkl"

ATTACK_LABELS = {
    "syn",
    "udp",
}

# Fixed feature order — must match capture.py and server.py exactly
SCAPY_FEATURES = [
    "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "Flow Bytes/s", "Flow Packets/s", "Fwd Packets/s", "Bwd Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd Header Length", "Bwd Header Length",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Destination Port", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "Down/Up Ratio",
]

# Model must be at least 85% confident before flagging a flow as an attack
ALERT_THRESHOLD = 0.85


# ─────────────────────────────────────────────────────────────────────────────
# DEVICE SETUP
# ─────────────────────────────────────────────────────────────────────────────

def get_device() -> torch.device:
    if torch.cuda.is_available():
        device = torch.device("cuda")
        props  = torch.cuda.get_device_properties(0)
        print(f"[GPU] {props.name} | {props.total_memory // 1024**2} MB VRAM")
    else:
        device = torch.device("cpu")
        print("[GPU] No CUDA device found — running on CPU")
    return device


# ─────────────────────────────────────────────────────────────────────────────
# MODEL ARCHITECTURE
# ─────────────────────────────────────────────────────────────────────────────

class DDoSDetector(nn.Module):
    """
    Feed-forward neural network for binary DDoS detection.
    Architecture: 256 → 128 → 64 → 1
    Each hidden layer uses BatchNorm → ReLU → Dropout.
    Output is a single sigmoid neuron (probability of attack).
    """

    def __init__(self, input_dim: int):
        super().__init__()
        self.network = nn.Sequential(
            # Block 1
            nn.Linear(input_dim, 256, bias=False),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.3),

            # Block 2
            nn.Linear(256, 128, bias=False),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),

            # Block 3
            nn.Linear(128, 64, bias=False),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),

            # Output
            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x).squeeze(1)


# ─────────────────────────────────────────────────────────────────────────────
# DATA LOADING
# ─────────────────────────────────────────────────────────────────────────────

def load_csvs(syn_path: str, udp_path: str) -> pd.DataFrame:
    """
    Load Syn.csv and UDP.csv from CIC-DDoS2019.
    Both files contain a mix of attack traffic and BENIGN traffic.
    Labels are normalised to lowercase and stripped of whitespace.
    Only syn, udp, and benign rows are kept — everything else is dropped.
    """
    frames = []
    for path, tag in [(syn_path, "Syn"), (udp_path, "UDP")]:
        print(f"  Reading {tag}: {path}")
        df = pd.read_csv(path, low_memory=False, na_values=["Infinity", "inf"])
        df.columns = df.columns.str.strip()
        frames.append(df)

    df = pd.concat(frames, ignore_index=True)

    # Normalise label column — handle both "Label" and " Label"
    label_col = "Label" if "Label" in df.columns else " Label"
    raw = df[label_col].str.strip().str.lower()

    # Drop everything that isn't syn, udp, or benign
    df = df[raw.isin(["syn", "udp", "benign"])].reset_index(drop=True)

    # Redefine raw after filtering so it stays in sync with df
    raw = df[label_col].str.strip().str.lower()

    df["_is_attack"] = raw.apply(
        lambda l: 1.0 if any(a in l for a in ATTACK_LABELS) else 0.0
    )

    print("\n[+] Label distribution in loaded data:")
    print(raw.value_counts().to_string())
    print()

    return df
56 → 128 → 64 → 1

# ─────────────────────────────────────────────────────────────────────────────
# TRAINING LOOP
# ─────────────────────────────────────────────────────────────────────────────

def train_epoch(
    model:      nn.Module,
    loader:     DataLoader,
    criterion:  nn.Module,
    optimizer:  torch.optim.Optimizer,
    device:     torch.device,
) -> float:
    """Run one full training epoch, return average loss."""
    model.train()
    total_loss = 0.0

    for X_batch, y_batch in loader:
        X_batch = X_batch.to(device)
        y_batch = y_batch.to(device)

        optimizer.zero_grad()
        preds = model(X_batch)
        loss  = criterion(preds, y_batch)
        loss.backward()
        optimizer.step()

        total_loss += loss.item() * len(y_batch)

    return total_loss / len(loader.dataset)


@torch.no_grad()
def eval_epoch(
    model:     nn.Module,
    loader:    DataLoader,
    criterion: nn.Module,
    device:    torch.device,
) -> tuple[float, np.ndarray]:
    """Run evaluation, return (avg_loss, probabilities array)."""
    model.eval()
    total_loss = 0.0
    all_probs  = []

    for X_batch, y_batch in loader:
        X_batch = X_batch.to(device)
        y_batch = y_batch.to(device)

        preds = model(X_batch)
        loss  = criterion(preds, y_batch)

        total_loss += loss.item() * len(y_batch)
        all_probs.append(preds.cpu().numpy())

    avg_loss = total_loss / len(loader.dataset)
    probs    = np.concatenate(all_probs)
    return avg_loss, probs


# ─────────────────────────────────────────────────────────────────────────────
# MAIN TRAIN FUNCTION
# ─────────────────────────────────────────────────────────────────────────────

def train(
    syn_path:   str,
    udp_path:   str,
    epochs:     int   = 30,
    batch_size: int   = 2048,
    lr:         float = 1e-3,
):
    device = get_device()

    # ── Load and preprocess data ───────────────────────────────────────────────
    df = load_csvs(syn_path, udp_path)

    for col in SCAPY_FEATURES:
        if col not in df.columns:
            print(f"  [!] Column '{col}' not found — filling with 0")
            df[col] = 0.0

    X = df[SCAPY_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0).values.astype(np.float32)
    y = df["_is_attack"].values.astype(np.float32)

    # log1p transform — must match server.py exactly
    X = np.log1p(np.clip(X, 0, None))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    scaler  = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    # ── Class weights ──────────────────────────────────────────────────────────
    n_benign = int((y_train == 0).sum())
    n_attack = int((y_train == 1).sum())
    total    = n_benign + n_attack
    print(f"[+] Train set — benign: {n_benign:,}, attack: {n_attack:,}")

    # pos_weight for BCEWithLogitsLoss: weight applied to the positive (attack) class
    # We use ratio of benign to attack so the loss penalises missing attacks more
    # when attacks are underrepresented, and vice versa
    weight_attack = torch.tensor([n_benign / max(n_attack, 1)], dtype=torch.float32).to(device)
    print(f"[+] Positive class weight (attack): {weight_attack.item():.3f}")

    # ── DataLoaders ────────────────────────────────────────────────────────────
    X_train_t = torch.tensor(X_train, dtype=torch.float32)
    y_train_t = torch.tensor(y_train, dtype=torch.float32)
    X_test_t  = torch.tensor(X_test,  dtype=torch.float32)
    y_test_t  = torch.tensor(y_test,  dtype=torch.float32)

    train_loader = DataLoader(
        TensorDataset(X_train_t, y_train_t),
        batch_size=batch_size,
        shuffle=True,
        num_workers=4,
        pin_memory=True,
    )
    test_loader = DataLoader(
        TensorDataset(X_test_t, y_test_t),
        batch_size=batch_size,
        shuffle=False,
        num_workers=4,
        pin_memory=True,
    )

    # ── Model, loss, optimizer, scheduler ─────────────────────────────────────
    model = DDoSDetector(input_dim=X_train.shape[1]).to(device)
    print(f"\n[+] Model architecture:\n{model}\n")

    # BCELoss since model outputs sigmoid. pos_weight handles class imbalance.
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=3
    )

    # ── Training loop ──────────────────────────────────────────────────────────
    best_val_loss  = float("inf")
    patience_count = 0
    patience_limit = 5

    print(f"[+] Training for up to {epochs} epochs (early stopping patience={patience_limit})\n")
    print(f"{'Epoch':>6} {'Train Loss':>12} {'Val Loss':>10} {'LR':>10}")
    print("-" * 45)

    for epoch in range(1, epochs + 1):
        train_loss          = train_epoch(model, train_loader, criterion, optimizer, device)
        val_loss, val_probs = eval_epoch(model, test_loader, criterion, device)

        current_lr = optimizer.param_groups[0]["lr"]
        print(f"{epoch:>6} {train_loss:>12.6f} {val_loss:>10.6f} {current_lr:>10.2e}")

        scheduler.step(val_loss)

        # Save best model
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), MODEL_PATH)
            patience_count = 0
        else:
            patience_count += 1
            if patience_count >= patience_limit:
                print(f"\n[+] Early stopping at epoch {epoch} (no improvement for {patience_limit} epochs)")
                break

    # ── Evaluation ─────────────────────────────────────────────────────────────
    # Load best checkpoint for final evaluation
    model.load_state_dict(torch.load(MODEL_PATH, map_location=device))
    _, probs = eval_epoch(model, test_loader, criterion, device)
    preds    = (probs > ALERT_THRESHOLD).astype(int)

    report = classification_report(
        y_test.astype(int), preds,
        target_names=["benign", "attack"],
        output_dict=True,
    )
    cm  = confusion_matrix(y_test.astype(int), preds).tolist()
    tn  = cm[0][0]
    fp  = cm[0][1]
    fn  = cm[1][0]
    tp  = cm[1][1]
    fpr = fp / max(tn + fp, 1)
    fnr = fn / max(fn + tp, 1)

    print("\n" + "=" * 60)
    print(classification_report(
        y_test.astype(int), preds, target_names=["benign", "attack"]
    ))
    print("Confusion matrix:")
    print(f"  TN={tn:,}  FP={fp:,}")
    print(f"  FN={fn:,}  TP={tp:,}")
    print(f"\n  False positive rate: {fpr:.4f}")
    print(f"  False negative rate: {fnr:.4f}")
    print("=" * 60)

    # Save metrics
    metrics_path = pathlib.Path(MODEL_PATH).with_name("ddos_metrics.json")
    metrics_path.write_text(json.dumps({
        "threshold":             ALERT_THRESHOLD,
        "classification_report": report,
        "confusion_matrix":      cm,
        "false_positive_rate":   fpr,
        "false_negative_rate":   fnr,
    }, indent=2))
    print(f"[+] Metrics saved to {metrics_path}")

    # Save all artifacts — these three files must be deployed to the server
    joblib.dump(scaler,         SCALER_PATH)
    joblib.dump(SCAPY_FEATURES, FEATURE_PATH)
    print(f"[+] Saved: {MODEL_PATH}, {SCALER_PATH}, {FEATURE_PATH}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Train DDoS detection FFNN (PyTorch) on CIC-DDoS2019"
    )
    parser.add_argument(
        "--syn", required=True,
        help="Path to Syn.csv from CIC-DDoS2019 03-11 folder (TCP SYN flood traffic)"
    )
    parser.add_argument(
        "--udp", required=True,
        help="Path to UDP.csv from CIC-DDoS2019 03-11 folder (UDP flood traffic)"
    )
    parser.add_argument("--epochs",     type=int,   default=30)
    parser.add_argument("--batch-size", type=int,   default=2048)
    parser.add_argument("--lr",         type=float, default=1e-3)
    args = parser.parse_args()

    train(args.syn, args.udp, args.epochs, args.batch_size, args.lr)


if __name__ == "__main__":
    main()