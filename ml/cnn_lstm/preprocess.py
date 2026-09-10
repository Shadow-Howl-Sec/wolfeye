"""
Data preprocessing, cleaning, feature scaling, label encoding, and 1D CNN reshaping pipeline.
"""

import os
import glob
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_class_weight
from ml.cnn_lstm.config import (
    TARGET_COLUMN, RANDOM_SEED, TEST_SIZE, VAL_SIZE,
    NUM_ORIGINAL_FEATURES, CNN_1D_INPUT_SHAPE,
    SCALER_PATH, LABEL_ENCODER_PATH, PREPROCESSING_INFO_PATH
)

def discover_and_load_data(data_path: str) -> pd.DataFrame:
    """
    Discovers and safely loads CICIDS2017 CSV files from a file path or directory.
    Combines multiple traffic CSV files into a single pandas DataFrame.
    """
    print(f"\n--- STEP 1: DATA LOADING FROM: {data_path} ---")
    if not os.path.exists(data_path):
        raise FileNotFoundError(f"Specified data path does not exist: {data_path}")

    csv_files = []
    if os.path.isfile(data_path) and data_path.endswith('.csv'):
        csv_files.append(data_path)
    elif os.path.isdir(data_path):
        csv_files = glob.glob(os.path.join(data_path, "*.csv"))
        if not csv_files:
            csv_files = glob.glob(os.path.join(data_path, "**", "*.csv"), recursive=True)

    if not csv_files:
        raise FileNotFoundError(f"No CSV files discovered at path: {data_path}")

    print(f"Discovered {len(csv_files)} CSV file(s):")
    for f in csv_files:
        print(f"  - {os.path.basename(f)}")

    df_list = []
    for f in csv_files:
        print(f"Loading {os.path.basename(f)}...")
        df_chunk = pd.read_csv(f, low_memory=False)
        df_chunk.columns = df_chunk.columns.str.strip()
        df_list.append(df_chunk)

    df_raw = pd.concat(df_list, ignore_index=True)
    print(f"Successfully loaded combined dataset.")
    print(f"Raw dataset shape: {df_raw.shape[0]} rows, {df_raw.shape[1]} columns")
    return df_raw

def audit_and_clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans dataset by handling NaNs, Inf values, whitespace, duplicates, and checking data leakage.
    """
    print("\n--- STEP 2: DATA INSPECTION & CLEANING ---")
    df = df.copy()
    
    if TARGET_COLUMN not in df.columns:
        possible_cols = [c for c in df.columns if 'label' in c.lower() or 'attack' in c.lower()]
        if possible_cols:
            df.rename(columns={possible_cols[0]: TARGET_COLUMN}, inplace=True)
        else:
            raise KeyError(f"Target column '{TARGET_COLUMN}' not found in dataset columns: {df.columns.tolist()}")

    df[TARGET_COLUMN] = df[TARGET_COLUMN].astype(str).str.strip()

    # Drop identifier columns to prevent data leakage
    identifier_cols = ['Flow ID', 'Source IP', 'Src IP', 'Destination IP', 'Dst IP', 'Timestamp', 'Unnamed: 0']
    cols_to_drop = [c for c in identifier_cols if c in df.columns]
    
    if cols_to_drop:
        print(f"Data Leakage Check: Dropping identifier column(s) {cols_to_drop} to ensure model generalization.")
        df.drop(columns=cols_to_drop, inplace=True)
    else:
        print("Data Leakage Check: No explicit IP/Timestamp identifier columns found. All features are numerical traffic flow metrics.")

    # Drop duplicates
    dup_count = df.duplicated().sum()
    if dup_count > 0:
        print(f"Duplicate Row Handling: Dropping {dup_count} duplicate rows.")
        df.drop_duplicates(inplace=True)

    # Numerical feature infinity and NaN handling
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)
    nan_counts = df[num_cols].isnull().sum()
    nan_cols = nan_counts[nan_counts > 0]
    
    if len(nan_cols) > 0:
        print(f"Imputing NaNs in {len(nan_cols)} columns with feature medians...")
        for col in nan_cols.index:
            median_val = df[col].median()
            df[col].fillna(median_val, inplace=True)

    print(f"Cleaned dataset shape: {df.shape[0]} rows, {df.shape[1]} columns")
    return df

def prepare_features_and_target(df: pd.DataFrame):
    """
    Separates network flow features X from target labels y.
    Encodes multiclass labels into integer indices.
    """
    print("\n--- STEP 3 & 4: TARGET LABEL & ENCODING ---")
    y_raw = df[TARGET_COLUMN].values
    X_raw = df.drop(columns=[TARGET_COLUMN])

    print("Target Label Distribution:")
    unique_labels, counts = np.unique(y_raw, return_counts=True)
    total_samples = len(y_raw)
    for lbl, count in zip(unique_labels, counts):
        pct = (count / total_samples) * 100
        print(f"  - {lbl:20s}: {count:10d} ({pct:6.2f}%)")

    encoder = LabelEncoder()
    y_encoded = encoder.fit_transform(y_raw)
    label_mapping = {int(i): str(cls) for i, cls in enumerate(encoder.classes_)}
    
    feature_names = X_raw.columns.tolist()
    return X_raw.values, y_encoded, encoder, label_mapping, feature_names

def split_and_scale_data(X: np.ndarray, y: np.ndarray, feature_names: list, encoder, label_mapping: dict):
    """
    Performs stratified 80/20 train/test split, fits StandardScaler strictly on training set,
    and calculates square-root moderated class weights to prevent probability calibration collapse.
    """
    print("\n--- STEP 5, 6 & 7: TRAIN/TEST SPLIT, SCALING & MODERATED CLASS WEIGHTS ---")
    
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_SEED, stratify=y
    )

    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=VAL_SIZE, random_state=RANDOM_SEED, stratify=y_train_val
    )

    print(f"Train set size:      {X_train.shape[0]} samples ({(X_train.shape[0]/len(X))*100:.1f}%)")
    print(f"Validation set size: {X_val.shape[0]} samples ({(X_val.shape[0]/len(X))*100:.1f}%)")
    print(f"Test set size:       {X_test.shape[0]} samples ({(X_test.shape[0]/len(X))*100:.1f}%)")

    # Fit StandardScaler ONLY on X_train to avoid data leakage
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)
    X_test_scaled = scaler.transform(X_test)

    # Class Imbalance Handling: Compute moderated (square-root) class weights
    classes, counts = np.unique(y_train, return_counts=True)
    total_train = len(y_train)
    n_classes = len(classes)
    
    # Square-root smoothed weight formula: w_i = sqrt(total / (n_classes * count_i))
    raw_weights = total_train / (n_classes * counts)
    moderated_weights = np.sqrt(raw_weights)
    
    class_weight_dict = {int(c): float(w) for c, w in zip(classes, moderated_weights)}
    print("\nCalculated Moderated (Square-Root) Class Weights:")
    for c_id, w_val in class_weight_dict.items():
        print(f"  Class {c_id} ({label_mapping[c_id]}): {w_val:.4f} (Raw linear weight was: {raw_weights[c_id]:.2f})")

    # Save preprocessing objects
    os.makedirs(os.path.dirname(SCALER_PATH), exist_ok=True)
    joblib.dump(scaler, SCALER_PATH)
    joblib.dump(encoder, LABEL_ENCODER_PATH)

    prep_info = {
        "num_features": len(feature_names),
        "feature_names": feature_names,
        "label_mapping": label_mapping,
        "num_classes": len(label_mapping),
        "cnn_1d_input_shape": list(CNN_1D_INPUT_SHAPE)
    }
    with open(PREPROCESSING_INFO_PATH, 'w') as f:
        json.dump(prep_info, f, indent=4)

    return (X_train_scaled, y_train), (X_val_scaled, y_val), (X_test_scaled, y_test), class_weight_dict, scaler, encoder

def reshape_for_1d_cnn(X_matrix: np.ndarray) -> np.ndarray:
    """
    Reshapes flat tabular feature matrix (N, 52) into 1D sequence tensor (N, 52, 1).
    This represents the 52 continuous flow telemetry features as a 1D sequence for Conv1D filters.
    """
    return np.expand_dims(X_matrix, axis=-1)
