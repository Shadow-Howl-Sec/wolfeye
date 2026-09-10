"""
Model evaluation script for generating classification report, confusion matrix, ROC-AUC curves, and comparative metrics.
"""

import os
os.environ['KERAS_BACKEND'] = 'torch'

import json
import joblib
import numpy as np
import pandas as pd
import keras
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

from ml.cnn_lstm.config import (
    DEFAULT_CSV_PATH, MODEL_PATH, SCALER_PATH, LABEL_ENCODER_PATH,
    PREPROCESSING_INFO_PATH, METRICS_PATH, CONFUSION_MATRIX_PATH,
    ROC_CURVE_PATH, CLASSIFICATION_REPORT_PATH, RANDOM_SEED
)
from ml.cnn_lstm.utils import plot_confusion_matrix, plot_multiclass_roc
from ml.cnn_lstm.preprocess import (
    discover_and_load_data, audit_and_clean_data, prepare_features_and_target,
    split_and_scale_data, reshape_for_1d_cnn
)
from ml.cnn_lstm.build_model import CategoricalFocalLoss

def evaluate_model(data_path: str = DEFAULT_CSV_PATH):
    print("=" * 70)
    print("      CICIDS2017 MODEL EVALUATION & METRICS EXTRACTION      ")
    print("=" * 70)

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Saved model file not found at: {MODEL_PATH}. Run train.py first.")
    if not os.path.exists(SCALER_PATH) or not os.path.exists(LABEL_ENCODER_PATH):
        raise FileNotFoundError(f"Preprocessing objects missing in outputs directory. Run train.py first.")

    # 1. Load Data & Preprocessing Objects
    df_raw = discover_and_load_data(data_path)
    df_cleaned = audit_and_clean_data(df_raw)
    X, y, encoder, label_mapping, feature_names = prepare_features_and_target(df_cleaned)

    # Re-create train/test split to isolate held-out test set
    _, _, (X_test_flat, y_test), _, _, _ = split_and_scale_data(
        X, y, feature_names, encoder, label_mapping
    )

    # Reshape test set into 1D sequence tensor (N, 52, 1)
    X_test_1d = reshape_for_1d_cnn(X_test_flat)

    # Load Saved Model with custom loss handler
    print(f"\nLoading trained Hybrid 1D Conv1D-LSTM model from: {MODEL_PATH}")
    custom_objects = {"CategoricalFocalLoss": CategoricalFocalLoss}
    model = keras.models.load_model(MODEL_PATH, custom_objects=custom_objects)

    # Model Predictions & Probabilities
    print("Executing model inference on held-out test set...")
    y_prob = model.predict(X_test_1d, batch_size=2048, verbose=1)
    y_pred = np.argmax(y_prob, axis=1)

    # 2. EVALUATION METRICS COMPUTATION
    acc = accuracy_score(y_test, y_pred)
    prec_weighted = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    rec_weighted = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)

    prec_macro = precision_score(y_test, y_pred, average='macro', zero_division=0)
    rec_macro = recall_score(y_test, y_pred, average='macro', zero_division=0)
    f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)

    # MULTICLASS ROC-AUC SCORE (One-vs-Rest)
    num_classes = len(label_mapping)
    y_test_onehot = np.eye(num_classes)[y_test]
    try:
        roc_auc_ovr_macro = roc_auc_score(y_test_onehot, y_prob, multi_class='ovr', average='macro')
        roc_auc_ovr_weighted = roc_auc_score(y_test_onehot, y_prob, multi_class='ovr', average='weighted')
    except Exception as e:
        print(f"Warning: Could not compute ROC-AUC score ({e})")
        roc_auc_ovr_macro = 0.0
        roc_auc_ovr_weighted = 0.0

    print("\n" + "=" * 50)
    print("      NEW 1D Conv1D-LSTM TEST PERFORMANCE SUMMARY      ")
    print("=" * 50)
    print(f"Accuracy:                {acc * 100:.4f}%")
    print(f"Precision (Weighted):    {prec_weighted * 100:.4f}%")
    print(f"Recall (Weighted):       {rec_weighted * 100:.4f}%")
    print(f"F1-Score (Weighted):     {f1_weighted * 100:.4f}%")
    print(f"Precision (Macro):       {prec_macro * 100:.4f}%")
    print(f"Recall (Macro):          {rec_macro * 100:.4f}%")
    print(f"F1-Score (Macro):        {f1_macro * 100:.4f}%")
    print(f"ROC-AUC (Macro OVR):     {roc_auc_ovr_macro:.4f}")
    print(f"ROC-AUC (Weighted OVR):  {roc_auc_ovr_weighted:.4f}")

    # Generate & Save Classification Report
    target_names = [label_mapping[i] for i in range(num_classes)]
    cls_report_str = classification_report(y_test, y_pred, target_names=target_names, digits=4, zero_division=0)
    
    print("\nClassification Report:")
    print(cls_report_str)
    
    with open(CLASSIFICATION_REPORT_PATH, 'w') as f:
        f.write("CICIDS2017 Optimized 1D Conv1D-LSTM Classification Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(cls_report_str)
    print(f"Saved classification report text to: {CLASSIFICATION_REPORT_PATH}")

    # CONFUSION MATRIX
    cm = confusion_matrix(y_test, y_pred)
    print("\nConfusion Matrix:")
    print(cm)
    plot_confusion_matrix(cm, target_names, CONFUSION_MATRIX_PATH)

    # Save ROC Curve Plot
    if roc_auc_ovr_macro > 0:
        plot_multiclass_roc(y_test_onehot, y_prob, target_names, ROC_CURVE_PATH)

    # Update Metrics JSON artifact
    existing_metrics = {}
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, 'r') as f:
            existing_metrics = json.load(f)

    # Record OLD metrics vs NEW metrics for comparison
    old_acc = existing_metrics.get("cnn_lstm_accuracy", 0.4324)
    old_f1_macro = existing_metrics.get("cnn_lstm_f1_macro", 0.2738)

    existing_metrics.update({
        "old_cnn_lstm_accuracy": float(old_acc),
        "old_cnn_lstm_f1_macro": float(old_f1_macro),
        "new_cnn_lstm_accuracy": float(acc),
        "new_cnn_lstm_precision_weighted": float(prec_weighted),
        "new_cnn_lstm_recall_weighted": float(rec_weighted),
        "new_cnn_lstm_f1_weighted": float(f1_weighted),
        "new_cnn_lstm_precision_macro": float(prec_macro),
        "new_cnn_lstm_recall_macro": float(rec_macro),
        "new_cnn_lstm_f1_macro": float(f1_macro),
        "new_cnn_lstm_roc_auc_ovr_macro": float(roc_auc_ovr_macro),
        "new_cnn_lstm_roc_auc_ovr_weighted": float(roc_auc_ovr_weighted),
        "test_sample_count": len(y_test)
    })

    with open(METRICS_PATH, 'w') as f:
        json.dump(existing_metrics, f, indent=4)
    print(f"\nUpdated metrics saved to: {METRICS_PATH}")

if __name__ == "__main__":
    evaluate_model()
