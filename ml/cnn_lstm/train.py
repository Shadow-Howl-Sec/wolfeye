"""
Training pipeline script for Random Forest baseline and Hybrid 1D Conv1D-LSTM Intrusion Detection Model.
"""

import os
os.environ['KERAS_BACKEND'] = 'torch'

import sys
import time
import argparse
import joblib
import json
import numpy as np
import keras
from keras import callbacks
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score

from ml.cnn_lstm.config import (
    DEFAULT_CSV_PATH, MODEL_PATH, SAVED_MODEL_DIR, METRICS_PATH,
    TRAINING_HISTORY_PATH, BATCH_SIZE, EPOCHS, LEARNING_RATE, RANDOM_SEED
)
from ml.cnn_lstm.utils import set_seed, detect_gpu, plot_training_history
from ml.cnn_lstm.preprocess import (
    discover_and_load_data, audit_and_clean_data, prepare_features_and_target,
    split_and_scale_data, reshape_for_1d_cnn
)
from ml.cnn_lstm.build_model import build_hybrid_1d_cnn_lstm, build_random_forest_baseline

def run_training(
    data_path: str = DEFAULT_CSV_PATH,
    batch_size: int = BATCH_SIZE,
    epochs: int = EPOCHS,
    lr: float = LEARNING_RATE,
    smoke_test: bool = False
):
    print("=" * 70)
    print("   CICIDS2017 HYBRID 1D Conv1D-LSTM MODEL TRAINING PIPELINE   ")
    print("=" * 70)

    start_time = time.time()
    set_seed(RANDOM_SEED)
    detect_gpu()

    # 1. Load Data
    df_raw = discover_and_load_data(data_path)

    # 2. Audit & Clean Data
    df_cleaned = audit_and_clean_data(df_raw)

    if smoke_test:
        print("\n[SMOKE TEST MODE]: Subsampling dataset to 50,000 samples for rapid validation...")
        df_cleaned = df_cleaned.sample(n=min(50000, len(df_cleaned)), random_state=RANDOM_SEED)

    # 3. Extract Features & Target Label
    X, y, encoder, label_mapping, feature_names = prepare_features_and_target(df_cleaned)

    # 4. Stratified Split, Scaling & Moderated Class Weights
    (X_train_flat, y_train), (X_val_flat, y_val), (X_test_flat, y_test), class_weights, scaler, encoder = split_and_scale_data(
        X, y, feature_names, encoder, label_mapping
    )

    # 5. STEP 18 — BASELINE MODEL (Random Forest)
    print("\n--- STEP 18: TRAINING RANDOM FOREST BASELINE MODEL ---")
    rf_baseline = build_random_forest_baseline(random_state=RANDOM_SEED)
    rf_start = time.time()
    rf_baseline.fit(X_train_flat, y_train)
    rf_train_time = time.time() - rf_start

    rf_preds = rf_baseline.predict(X_test_flat)
    rf_acc = accuracy_score(y_test, rf_preds)
    rf_prec = precision_score(y_test, rf_preds, average='weighted', zero_division=0)
    rf_rec = recall_score(y_test, rf_preds, average='weighted', zero_division=0)
    rf_f1 = f1_score(y_test, rf_preds, average='weighted', zero_division=0)

    print(f"Random Forest Baseline Results:")
    print(f"  - Accuracy:  {rf_acc * 100:.2f}%")
    print(f"  - Precision: {rf_prec * 100:.2f}%")
    print(f"  - Recall:    {rf_rec * 100:.2f}%")
    print(f"  - F1-Score:  {rf_f1 * 100:.2f}%")
    print(f"  - Training Time: {rf_train_time:.2f}s")

    # 6. Reshape Features into 1D Sequence Tensor (N, 52, 1) for Conv1D
    print("\n--- 1D CNN FEATURE SEQUENCE RESHAPING ---")
    X_train_1d = reshape_for_1d_cnn(X_train_flat)
    X_val_1d = reshape_for_1d_cnn(X_val_flat)
    X_test_1d = reshape_for_1d_cnn(X_test_flat)
    print(f"1D sequence tensor dimensions: Train {X_train_1d.shape}, Val {X_val_1d.shape}, Test {X_test_1d.shape}")

    # 7. BUILD & INSPECT 1D Conv1D-LSTM ARCHITECTURE
    num_classes = len(label_mapping)
    model = build_hybrid_1d_cnn_lstm(
        input_shape=(X_train_1d.shape[1], 1),
        num_classes=num_classes,
        learning_rate=lr,
        use_focal_loss=True
    )

    print("\n--- HYBRID 1D Conv1D-LSTM MODEL SUMMARY ---")
    model.summary()

    # 8. MODEL TRAINING WITH CALLBACKS & BEST MODEL SAVING
    print("\n--- HYBRID 1D Conv1D-LSTM MODEL TRAINING ---")
    os.makedirs(SAVED_MODEL_DIR, exist_ok=True)

    callback_list = [
        callbacks.EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True, verbose=1),
        callbacks.ModelCheckpoint(filepath=MODEL_PATH, monitor='val_loss', save_best_only=True, verbose=1),
        callbacks.ReduceLROnPlateau(monitor='val_loss', factor=0.5, patience=2, min_lr=1e-6, verbose=1)
    ]

    fit_epochs = 2 if smoke_test else epochs
    cnn_start = time.time()
    history = model.fit(
        X_train_1d, y_train,
        validation_data=(X_val_1d, y_val),
        epochs=fit_epochs,
        batch_size=batch_size,
        class_weight=class_weights,
        callbacks=callback_list,
        verbose=1
    )
    cnn_train_time = time.time() - cnn_start

    print(f"\n1D Conv1D-LSTM Training Completed in {cnn_train_time:.2f} seconds.")

    # Save best model checkpoint
    model.save(MODEL_PATH)
    print(f"Saved trained best model to: {MODEL_PATH}")

    # Plot & save training curves
    plot_training_history(history, TRAINING_HISTORY_PATH)

    # Save baseline metrics
    baseline_metrics = {
        "rf_accuracy": float(rf_acc),
        "rf_precision": float(rf_prec),
        "rf_recall": float(rf_rec),
        "rf_f1": float(rf_f1),
        "rf_train_time_sec": float(rf_train_time),
        "cnn_train_time_sec": float(cnn_train_time),
        "total_pipeline_time_sec": float(time.time() - start_time)
    }
    with open(METRICS_PATH, 'w') as f:
        json.dump(baseline_metrics, f, indent=4)

    print("\nTraining completed successfully! Run evaluate.py to calculate final test metrics.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CICIDS2017 Hybrid 1D Conv1D-LSTM Model")
    parser.add_argument("--data_path", type=str, default=DEFAULT_CSV_PATH, help="Path to raw CSV or directory")
    parser.add_argument("--batch_size", type=int, default=BATCH_SIZE, help="Batch size for training")
    parser.add_argument("--epochs", type=int, default=EPOCHS, help="Number of training epochs")
    parser.add_argument("--lr", type=float, default=LEARNING_RATE, help="Learning rate")
    parser.add_argument("--smoke_test", action="store_true", help="Run 2-epoch test on 50k subsample")
    args = parser.parse_args()

    run_training(
        data_path=args.data_path,
        batch_size=args.batch_size,
        epochs=args.epochs,
        lr=args.lr,
        smoke_test=args.smoke_test
    )
