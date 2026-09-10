"""
Configuration parameters for CICIDS2017 Hybrid 1D CNN-LSTM Intrusion Detection Model.
"""

import os

# Base Directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)

# Dataset Paths
DATA_DIR = os.path.join(PROJECT_ROOT, "data", "cicids2017")
DEFAULT_CSV_PATH = os.path.join(PROJECT_ROOT, "cicids2017_cleaned.csv")

# Output Directories
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
SAVED_MODEL_DIR = os.path.join(BASE_DIR, "cnn_lstm", "saved_model")

# File Artifact Paths
MODEL_PATH = os.path.join(SAVED_MODEL_DIR, "cnn_lstm.keras")
SCALER_PATH = os.path.join(OUTPUT_DIR, "scaler.joblib")
LABEL_ENCODER_PATH = os.path.join(OUTPUT_DIR, "label_encoder.joblib")
PREPROCESSING_INFO_PATH = os.path.join(OUTPUT_DIR, "preprocessing_info.json")
METRICS_PATH = os.path.join(OUTPUT_DIR, "metrics.json")
CONFUSION_MATRIX_PATH = os.path.join(OUTPUT_DIR, "confusion_matrix.png")
ROC_CURVE_PATH = os.path.join(OUTPUT_DIR, "roc_curve.png")
TRAINING_HISTORY_PATH = os.path.join(OUTPUT_DIR, "training_history.png")
CLASSIFICATION_REPORT_PATH = os.path.join(OUTPUT_DIR, "classification_report.txt")

# Target Column Name
TARGET_COLUMN = "Attack Type"

# Data Preprocessing & Model Hyperparameters
RANDOM_SEED = 42
TEST_SIZE = 0.20
VAL_SIZE = 0.15

# Reshaping Hyperparameters (1D Sequence Representation)
NUM_ORIGINAL_FEATURES = 52
CNN_1D_INPUT_SHAPE = (52, 1)

# Training Hyperparameters
BATCH_SIZE = 2048
EPOCHS = 15
LEARNING_RATE = 0.001

# Framework Backend
OS_KERAS_BACKEND = "torch"
