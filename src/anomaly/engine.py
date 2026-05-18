import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import logging

logging.basicConfig(level=logging.INFO)

class AnomalyEngine:
    def __init__(self, model_path="models/isolation_forest.pkl"):
        self.model_path = model_path
        self.model = None
        self.expected_features = ["length", "src_port", "dst_port", "protocol"]
        self._load_or_init_model()

    def _load_or_init_model(self):
        """
        Loads the pre-trained Isolation Forest model, or initializes a random blank one.
        """
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            logging.info(f"Loaded Isolation Forest model from {self.model_path}")
        else:
            logging.warning(f"No trained model found at {self.model_path}. Initializing empty model. It needs training.")
            self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)

    def train(self, data_csv):
        """
        Trains the model on a provided CSV of normal network traffic features.
        """
        logging.info(f"Training Anomaly Engine using {data_csv}...")
        df = pd.read_csv(data_csv)
        X = df[self.expected_features]
        # Fit model
        self.model.fit(X)
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        logging.info("Model training complete and saved.")

    def evaluate(self, packet_features: dict) -> dict:
        """
        Evaluates extracted flow features to determine if they are anomalous.
        """
        if getattr(self.model, "estimators_", None) is None:
            # Model not fitted yet
            return None
            
        try:
            # Extract numerical features for the model
            vector = [
                packet_features.get("length", 0),
                packet_features.get("src_port", 0),
                packet_features.get("dst_port", 0),
                packet_features.get("protocol", 0)
            ]
            X = np.array([vector])
            
            # Isolation forest returns 1 for normal, -1 for anomaly
            prediction = self.model.predict(X)[0]
            
            if prediction == -1:
                # Get anomaly score distance
                score = float(self.model.decision_function(X)[0])
                return {
                    "alert_type": "anomaly",
                    "description": "Unusual network behavior detected (Isolation Forest)",
                    "severity": "MEDIUM",
                    "confidence": score,
                    "src_ip": packet_features.get("src_ip"),
                    "dst_ip": packet_features.get("dst_ip")
                }
        except Exception as e:
            logging.error(f"Error evaluating anomaly: {e}")
            
        return None
