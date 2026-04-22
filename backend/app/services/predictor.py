import os
import joblib
import numpy as np
import tensorflow as tf
from tensorflow import keras

class PredictorService:
    def __init__(self, model_path="ddos_ffnn.keras", scaler_path="ddos_scaler.pkl"):
        # Absolute paths based on project root
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
        m_path = os.path.join(root, model_path)
        s_path = os.path.join(root, scaler_path)

        if not os.path.exists(m_path) or not os.path.exists(s_path):
            raise FileNotFoundError(f"Model or Scaler not found at {m_path}")

        print(f"[Predictor] Loading model from {m_path}")
        self.model = keras.models.load_model(m_path)
        self.scaler = joblib.load(s_path)
        print("[Predictor] Model and Scaler loaded successfully.")

    def predict(self, vector: list):
        """
        Takes a 47-feature vector and returns the attack probability.
        """
        vec = np.array([vector], dtype=np.float32)
        
        vec = np.log1p(np.clip(np.nan_to_num(vec, nan=0.0), 0, None))
        
        scaled = self.scaler.transform(vec).astype(np.float32)
        prob = self.model.predict(scaled, verbose=0)[0][0]
        
        return float(prob)

    def predict_batch(self, vectors: list):
        """
        Takes a list of vectors and returns a list of probabilities.
        """
        if not vectors:
            return []
        vecs = np.array(vectors, dtype=np.float32)
        vecs = np.log1p(np.clip(np.nan_to_num(vecs, nan=0.0), 0, None))
        
        scaled = self.scaler.transform(vecs).astype(np.float32)


        probs = self.model.predict(scaled, batch_size=len(scaled), verbose=0).flatten()
        
        return [float(p) for p in probs]

# Singleton instance with robust error handling
predictor = None
try:
    predictor = PredictorService()
except Exception as e:
    print("\n" + "!"*50)
    print(f"CRITICAL ERROR: Failed to initialize PredictorService")
    print(f"Reason: {e}")
    print("The API will start, but /predict will return 503 Service Unavailable.")
    print("!"*50 + "\n")
