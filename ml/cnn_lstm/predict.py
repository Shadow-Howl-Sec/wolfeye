"""
Production inference script for running predictions on raw network-flow samples using the saved 1D Conv1D-LSTM model.
"""

import os
os.environ['KERAS_BACKEND'] = 'torch'

import json
import joblib
import numpy as np
import pandas as pd
import keras

from ml.cnn_lstm.config import (
    MODEL_PATH, SCALER_PATH, LABEL_ENCODER_PATH, PREPROCESSING_INFO_PATH
)
from ml.cnn_lstm.preprocess import reshape_for_1d_cnn
from ml.cnn_lstm.build_model import CategoricalFocalLoss

class IntrusionPredictor:
    """
    Production inference class for the Hybrid 1D Conv1D-LSTM Intrusion Detection Model.
    """
    def __init__(self):
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Train model first.")
        if not os.path.exists(SCALER_PATH) or not os.path.exists(LABEL_ENCODER_PATH) or not os.path.exists(PREPROCESSING_INFO_PATH):
            raise FileNotFoundError("Preprocessing artifacts missing in outputs directory.")

        print(f"Loading model from: {MODEL_PATH} ...")
        custom_objects = {"CategoricalFocalLoss": CategoricalFocalLoss}
        self.model = keras.models.load_model(MODEL_PATH, custom_objects=custom_objects)
        self.scaler = joblib.load(SCALER_PATH)
        self.encoder = joblib.load(LABEL_ENCODER_PATH)

        with open(PREPROCESSING_INFO_PATH, 'r') as f:
            self.prep_info = json.load(f)

        self.feature_names = self.prep_info["feature_names"]
        self.label_mapping = {int(k): v for k, v in self.prep_info["label_mapping"].items()}
        print("Inference predictor initialized successfully.")

    def predict_sample(self, flow_data) -> dict:
        """
        Accepts a dictionary, pandas Series, 1D array, or DataFrame containing flow features.
        Applies feature ordering verification, StandardScaler, 1D sequence expansion (1, 52, 1),
        and model inference.

        Returns prediction dictionary containing predicted class name, confidence, and top-3 probabilities.
        """
        if isinstance(flow_data, dict):
            features_dict = {}
            for name in self.feature_names:
                features_dict[name] = flow_data.get(name, 0.0)
            df_input = pd.DataFrame([features_dict])
            X_raw = df_input[self.feature_names].values
        elif isinstance(flow_data, pd.DataFrame):
            df_input = flow_data[self.feature_names]
            X_raw = df_input.values
        elif isinstance(flow_data, (list, np.ndarray)):
            X_arr = np.array(flow_data)
            if X_arr.ndim == 1:
                X_arr = X_arr.reshape(1, -1)
            if X_arr.shape[1] != len(self.feature_names):
                raise ValueError(f"Expected {len(self.feature_names)} features, got {X_arr.shape[1]}")
            X_raw = X_arr
        else:
            raise TypeError("flow_data must be a dict, list, numpy array, or pandas DataFrame.")

        # 1. Standard Scaling (using pre-fitted scaler)
        X_scaled = self.scaler.transform(X_raw)

        # 2. Reshape to 1D sequence tensor (N, 52, 1)
        X_1d = reshape_for_1d_cnn(X_scaled)

        # 3. Model Predict
        probs = self.model.predict(X_1d, verbose=0)[0]
        pred_class_idx = int(np.argmax(probs))
        confidence = float(probs[pred_class_idx]) * 100.0
        predicted_class_name = self.label_mapping.get(pred_class_idx, f"Class {pred_class_idx}")

        # Top-3 Predictions
        top3_indices = np.argsort(probs)[::-1][:3]
        top3_predictions = []
        for idx in top3_indices:
            top3_predictions.append({
                "class_id": int(idx),
                "class_name": self.label_mapping.get(int(idx), f"Class {idx}"),
                "probability": float(probs[idx]),
                "confidence_pct": round(float(probs[idx]) * 100.0, 2)
            })

        return {
            "prediction": predicted_class_name,
            "confidence_pct": round(confidence, 2),
            "predicted_class_id": pred_class_idx,
            "top_3_predictions": top3_predictions
        }

if __name__ == "__main__":
    predictor = IntrusionPredictor()
    
    # Generate mock sample flow with zero values for demonstration
    mock_sample = {name: 0.0 for name in predictor.feature_names}
    mock_sample["Destination Port"] = 80.0
    mock_sample["Flow Duration"] = 12000.0
    mock_sample["Total Fwd Packets"] = 5.0
    mock_sample["Total Length of Fwd Packets"] = 450.0

    print("\n--- SAMPLE INFERENCE TEST ---")
    result = predictor.predict_sample(mock_sample)
    print(f"Prediction:     {result['prediction']}")
    print(f"Confidence:     {result['confidence_pct']}%")
    print("Top-3 Probabilities:")
    for item in result["top_3_predictions"]:
        print(f"  - {item['class_name']:20s}: {item['confidence_pct']:.2f}%")
