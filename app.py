"""
Streamlit Web Interface for Threat Intelligence Aggregator — Track B: CICIDS2017 Hybrid CNN-LSTM Intrusion Detection Platform.
"""

import os
import sys

# Set Keras backend to PyTorch before loading any ML modules
os.environ['KERAS_BACKEND'] = 'torch'

import json
import random
import numpy as np
import pandas as pd
import streamlit as st

# Add current directory to python path for package imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from ml.cnn_lstm.predict import IntrusionPredictor
from ml.cnn_lstm.config import (
    DEFAULT_CSV_PATH, METRICS_PATH, PREPROCESSING_INFO_PATH,
    CLASSIFICATION_REPORT_PATH, CONFUSION_MATRIX_PATH, ROC_CURVE_PATH
)

# Set Page Config
st.set_page_config(
    page_title="Threat Intelligence Aggregator — Intrusion Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark Cyber Theme)
st.markdown("""
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 800;
        color: #1E88E5;
        text-align: center;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #B0BEC5;
        text-align: center;
        margin-bottom: 1.5rem;
    }
    .card-correct {
        background-color: #064E3B;
        color: #34D399;
        padding: 15px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 1.2rem;
        text-align: center;
        border: 2px solid #059669;
    }
    .card-incorrect {
        background-color: #7F1D1D;
        color: #F87171;
        padding: 15px;
        border-radius: 8px;
        font-weight: bold;
        font-size: 1.2rem;
        text-align: center;
        border: 2px solid #DC2626;
    }
    </style>
""", unsafe_allow_html=True)

@st.cache_resource
def load_predictor():
    """Instantiates and caches the production IntrusionPredictor."""
    try:
        return IntrusionPredictor()
    except Exception as e:
        st.error(f"Error initializing IntrusionPredictor: {e}")
        return None

@st.cache_data(show_spinner="Loading real dataset sample pools from cicids2017_cleaned.csv...")
def load_real_sample_pools(csv_path=DEFAULT_CSV_PATH):
    """
    Loads real dataset rows from cicids2017_cleaned.csv and caches sample pools for all 7 attack classes.
    """
    if not os.path.exists(csv_path):
        return None
    
    chunks = []
    # Read chunked to quickly obtain sample pools for all classes
    for chunk in pd.read_csv(csv_path, chunksize=100000, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        if 'Attack Type' in chunk.columns:
            chunk['Attack Type'] = chunk['Attack Type'].astype(str).str.strip()
            chunks.append(chunk)
            combined = pd.concat(chunks, ignore_index=True)
            counts = combined['Attack Type'].value_counts()
            if len(counts) >= 7 and min(counts) >= 200:
                break
    
    if not chunks:
        return None

    df_pool = pd.concat(chunks, ignore_index=True)
    df_pool['Attack Type'] = df_pool['Attack Type'].astype(str).str.strip()
    
    sample_pools = {}
    for cls_name in df_pool['Attack Type'].unique():
        sample_pools[cls_name] = df_pool[df_pool['Attack Type'] == cls_name]
    return sample_pools

predictor = load_predictor()
sample_pools = load_real_sample_pools()

# App Header
st.markdown("<div class='main-header'>🛡️ Threat Intelligence Aggregator — Track B</div>", unsafe_allow_html=True)
st.markdown("<div class='sub-header'>Supervised Hybrid 1D Conv1D-LSTM Intrusion Detection Platform (CICIDS2017 Telemetry)</div>", unsafe_allow_html=True)

# Sidebar — Model Status & Controls
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=70)
st.sidebar.title("Dashboard Control")
st.sidebar.markdown("---")

if predictor is not None:
    st.sidebar.success("Model Checkpoint Loaded")
    st.sidebar.info(f"Features: {len(predictor.feature_names)} Continuous Metrics")
    st.sidebar.info(f"Target Classes: {len(predictor.label_mapping)} Attack Types")
else:
    st.sidebar.error("Failed to load ML artifacts")

if sample_pools is not None:
    st.sidebar.success("Real Dataset Sample Pools Cached")
else:
    st.sidebar.warning("Dataset CSV not found for presets")

# Main Navigation Tabs
tab1, tab2, tab3 = st.tabs(["🚀 Real Sample Presets & Inference", "📊 Model Evaluation & Metrics", "ℹ️ System Context (Track A vs B)"])

with tab1:
    st.subheader("🎯 Real Dataset Attack Presets & Quick Test")
    st.markdown("Select a ground-truth attack class to extract a **real network flow telemetry sample** from `cicids2017_cleaned.csv` and pass it through the CNN-LSTM model.")

    if predictor is None:
        st.error("Predictor model is unavailable. Please verify saved artifacts in ml/cnn_lstm/saved_model/")
    else:
        # Map User-Friendly Display Names to exact dataset class names in cicids2017_cleaned.csv
        CLASS_MAPPING = {
            "Normal Traffic": "Normal Traffic",
            "DDoS Attack": "DDoS",
            "DoS Attack": "DoS",
            "Port Scanning": "Port Scanning",
            "Web Attack": "Web Attacks",
            "Brute Force": "Brute Force",
            "Bot": "Bots"
        }

        preset_cols = st.columns(len(CLASS_MAPPING))
        selected_preset = st.selectbox(
            "Select Attack Class Preset:",
            list(CLASS_MAPPING.keys()),
            index=0
        )

        actual_class_name = CLASS_MAPPING[selected_preset]
        btn_col1, btn_col2 = st.columns([1, 1])
        
        test_preset_clicked = btn_col1.button(f"⚡ Test Sample from: {selected_preset}", type="primary", use_container_width=True)
        random_sample_clicked = btn_col2.button(f"🎲 Random Sample ({selected_preset})", use_container_width=True)

        if "current_sample" not in st.session_state:
            st.session_state["current_sample"] = None
            st.session_state["ground_truth"] = None

        if (test_preset_clicked or random_sample_clicked or st.session_state["current_sample"] is None) and sample_pools:
            if actual_class_name in sample_pools:
                pool = sample_pools[actual_class_name]
                # Pick a random real row from the dataset pool
                sample_row = pool.sample(n=1).iloc[0]
                
                # Extract ground truth and exact 52 features
                st.session_state["ground_truth"] = sample_row["Attack Type"]
                sample_dict = {}
                for feat in predictor.feature_names:
                    sample_dict[feat] = float(sample_row[feat]) if feat in sample_row else 0.0
                st.session_state["current_sample"] = sample_dict

        # Display Prediction & Verification for Current Sample
        if st.session_state["current_sample"] is not None:
            gt_label = st.session_state["ground_truth"]
            sample_dict = st.session_state["current_sample"]

            # Run prediction through existing IntrusionPredictor
            result = predictor.predict_sample(sample_dict)
            pred_label = result["prediction"]
            confidence = result["confidence_pct"]
            top3 = result["top_3_predictions"]
            is_correct = (pred_label == gt_label)

            st.write("")
            res_box_col1, res_box_col2 = st.columns([1, 1])

            with res_box_col1:
                st.markdown(f"**Ground-Truth Class (Actual):** `{gt_label}`")
                st.markdown(f"**CNN-LSTM Prediction:** `{pred_label}`")
                st.markdown(f"**Prediction Confidence:** `{confidence:.2f}%`")

            with res_box_col2:
                if is_correct:
                    st.markdown(f"<div class='card-correct'>✅ PREDICTION CORRECT<br>Actual: {gt_label} | Predicted: {pred_label}</div>", unsafe_allow_html=True)
                else:
                    st.markdown(f"<div class='card-incorrect'>❌ PREDICTION INCORRECT<br>Actual: {gt_label} | Predicted: {pred_label}</div>", unsafe_allow_html=True)

            st.write("")
            st.write("**Top-3 Prediction Probabilities:**")
            top_cols = st.columns(3)
            for idx, item in enumerate(top3):
                with top_cols[idx]:
                    st.write(f"**{idx+1}. {item['class_name']}**")
                    st.write(f"{item['confidence_pct']:.2f}%")
                    st.progress(min(max(float(item['confidence_pct']) / 100.0, 0.0), 1.0))

        st.markdown("---")
        st.subheader("📝 Manual Telemetry Form (52 Features)")
        st.markdown("The form below is auto-filled with the selected real dataset sample values. You can manually tweak any feature value to perform custom what-if analysis.")

        with st.form("manual_inference_form"):
            input_values = {}
            current_vals = st.session_state["current_sample"] if st.session_state["current_sample"] else {name: 0.0 for name in predictor.feature_names}

            with st.expander("1. Flow Basic & Packet Statistics", expanded=True):
                sec1_features = predictor.feature_names[0:14]
                f_cols1 = st.columns(3)
                for idx, feat in enumerate(sec1_features):
                    col = f_cols1[idx % 3]
                    input_values[feat] = col.number_input(
                        feat, value=float(current_vals.get(feat, 0.0)), key=f"inp_{feat}"
                    )

            with st.expander("2. Inter-Arrival Times (IAT)", expanded=False):
                sec2_features = predictor.feature_names[14:28]
                f_cols2 = st.columns(3)
                for idx, feat in enumerate(sec2_features):
                    col = f_cols2[idx % 3]
                    input_values[feat] = col.number_input(
                        feat, value=float(current_vals.get(feat, 0.0)), key=f"inp_{feat}"
                    )

            with st.expander("3. Header Lengths, Packet Sizes & Variance", expanded=False):
                sec3_features = predictor.feature_names[28:42]
                f_cols3 = st.columns(3)
                for idx, feat in enumerate(sec3_features):
                    col = f_cols3[idx % 3]
                    input_values[feat] = col.number_input(
                        feat, value=float(current_vals.get(feat, 0.0)), key=f"inp_{feat}"
                    )

            with st.expander("4. Flags, Window Sizes & Active/Idle Statistics", expanded=False):
                sec4_features = predictor.feature_names[42:52]
                f_cols4 = st.columns(3)
                for idx, feat in enumerate(sec4_features):
                    col = f_cols4[idx % 3]
                    input_values[feat] = col.number_input(
                        feat, value=float(current_vals.get(feat, 0.0)), key=f"inp_{feat}"
                    )

            submit_manual_btn = st.form_submit_button("⚡ Analyze Custom Form Values", type="primary", use_container_width=True)

        if submit_manual_btn:
            st.markdown("---")
            st.subheader("🔍 Custom Flow Analysis Result")
            try:
                res_manual = predictor.predict_sample(input_values)
                p_label = res_manual["prediction"]
                p_conf = res_manual["confidence_pct"]
                p_top3 = res_manual["top_3_predictions"]

                if p_label == "Normal Traffic":
                    st.success(f"✅ BENIGN TRAFFIC DETECTED ({p_conf:.2f}% Confidence)")
                else:
                    st.error(f"🚨 INTRUSION ALERT: {p_label.upper()} DETECTED ({p_conf:.2f}% Confidence)")

                m_col1, m_col2 = st.columns([1, 2])
                with m_col1:
                    st.metric("Predicted Class", p_label)
                    st.metric("Confidence", f"{p_conf:.2f}%")

                with m_col2:
                    st.write("**Top-3 Predictions:**")
                    for item in p_top3:
                        st.write(f"**{item['class_name']}**: {item['confidence_pct']:.2f}%")
                        st.progress(min(max(float(item['confidence_pct']) / 100.0, 0.0), 1.0))
            except Exception as e:
                st.error(f"Manual prediction failed: {e}")

with tab2:
    st.subheader("📊 Empirical Test Metrics & Model Artifacts")
    
    if os.path.exists(METRICS_PATH):
        with open(METRICS_PATH, 'r') as f:
            metrics = json.load(f)

        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        m_col1.metric("Test Accuracy", f"{metrics.get('new_cnn_lstm_accuracy', 0)*100:.2f}%")
        m_col2.metric("Weighted F1-Score", f"{metrics.get('new_cnn_lstm_f1_weighted', 0)*100:.2f}%")
        m_col3.metric("Macro F1-Score", f"{metrics.get('new_cnn_lstm_f1_macro', 0)*100:.2f}%")
        m_col4.metric("Weighted ROC-AUC", f"{metrics.get('new_cnn_lstm_roc_auc_ovr_weighted', 0):.4f}")

    st.markdown("---")
    img_col1, img_col2 = st.columns(2)

    with img_col1:
        st.subheader("Confusion Matrix")
        if os.path.exists(CONFUSION_MATRIX_PATH):
            st.image(CONFUSION_MATRIX_PATH, use_container_width=True)
        else:
            st.warning("Confusion matrix image not found.")

    with img_col2:
        st.subheader("Multiclass One-vs-Rest ROC Curve")
        if os.path.exists(ROC_CURVE_PATH):
            st.image(ROC_CURVE_PATH, use_container_width=True)
        else:
            st.warning("ROC curve image not found.")

    st.markdown("---")
    st.subheader("Classification Report Text")
    if os.path.exists(CLASSIFICATION_REPORT_PATH):
        with open(CLASSIFICATION_REPORT_PATH, 'r') as f:
            report_text = f.read()
        st.code(report_text, language="text")

with tab3:
    st.subheader("ℹ️ Project Scope & Architecture Rationale")
    st.markdown(r"""
    ### Threat Intelligence Aggregator Architecture
    This system implements two distinct machine learning tracks for cybersecurity telemetry:
    
    - **Track A (Isolation Forest):** Unsupervised anomaly detection on live, unlabeled Indicators of Compromise (IOC feeds, IP frequency, ASN spread).
    - **Track B (Supervised Hybrid CNN-LSTM):** Deep learning intrusion detection trained on 2.52 million network flows from **CICIDS2017**.
    
    ### Why 1D Conv1D + LSTM?
    1. **Conv1D:** Learns local feature interaction filters across continuous network metrics (packet statistics, window sizes, IAT metrics).
    2. **LSTM:** Captures sequential relationships across feature blocks.
    3. **Categorical Focal Loss ($\gamma=2.0$):** Focuses loss gradients on hard minority attack samples (`Bots`, `Brute Force`, `Web Attacks`) without degrading prediction calibration for majority `Normal Traffic`.
    """)
