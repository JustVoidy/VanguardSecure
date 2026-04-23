import os
import joblib
import numpy as np
import torch
import torch.nn as nn


class DDoSDetector(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 256, bias=False),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(0.3),

            nn.Linear(256, 128, bias=False),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(0.3),

            nn.Linear(128, 64, bias=False),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),

            nn.Linear(64, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.network(x).squeeze(1)


class PredictorService:
    def __init__(self, model_path="Training/ddos_ffnn.pt", scaler_path="Training/ddos_scaler.pkl"):
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
        m_path = os.path.join(root, model_path)
        s_path = os.path.join(root, scaler_path)

        if not os.path.exists(m_path) or not os.path.exists(s_path):
            raise FileNotFoundError(f"Model or Scaler not found at {m_path}")

        print(f"[Predictor] Loading model from {m_path}")
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = DDoSDetector(input_dim=47)
        self.model.load_state_dict(torch.load(m_path, map_location=self.device))
        self.model.to(self.device)
        self.model.eval()
        self.scaler = joblib.load(s_path)
        print("[Predictor] Model and Scaler loaded successfully.")

    def _preprocess(self, arr: np.ndarray) -> torch.Tensor:
        arr = np.log1p(np.clip(np.nan_to_num(arr, nan=0.0), 0, None))
        arr = self.scaler.transform(arr).astype(np.float32)
        return torch.tensor(arr, device=self.device)

    @torch.no_grad()
    def predict(self, vector: list) -> float:
        vec = np.array([vector], dtype=np.float32)
        t = self._preprocess(vec)
        return float(self.model(t).cpu().item())

    @torch.no_grad()
    def predict_batch(self, vectors: list) -> list:
        if not vectors:
            return []
        vecs = np.array(vectors, dtype=np.float32)
        t = self._preprocess(vecs)
        probs = self.model(t).cpu().numpy()
        return [float(p) for p in probs]


predictor = None
try:
    predictor = PredictorService()
except Exception as e:
    print("\n" + "!" * 50)
    print("CRITICAL ERROR: Failed to initialize PredictorService")
    print(f"Reason: {e}")
    print("The API will start, but /predict will return 503 Service Unavailable.")
    print("!" * 50 + "\n")
