"""
Utility functions for seed initialization, GPU detection, metrics logging, and plotting.
"""

import os
import random
import json
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import roc_curve, auc
import torch

def set_seed(seed: int = 42):
    """
    Sets random seed across python, numpy, torch, and environment variables for reproducibility.
    """
    random.seed(seed)
    np.random.seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False

def detect_gpu() -> bool:
    """
    Detects GPU hardware availability.
    Prints status and returns True if GPU is available, else False.
    """
    gpu_available = torch.cuda.is_available()
    if gpu_available:
        device_name = torch.cuda.get_device_name(0)
        print(f"GPU available: YES ({device_name})")
    else:
        print("GPU available: NO (Falling back to CPU execution)")
    return gpu_available

def plot_training_history(history, save_path: str):
    """
    Plots training and validation Accuracy and Loss over epochs and saves plot image.
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    
    # Keras history dict can contain 'accuracy' / 'acc' or 'loss'
    acc = history.history.get('accuracy', history.history.get('acc', []))
    val_acc = history.history.get('val_accuracy', history.history.get('val_acc', []))
    loss = history.history.get('loss', [])
    val_loss = history.history.get('val_loss', [])
    epochs_range = range(1, len(loss) + 1)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Loss plot
    ax1.plot(epochs_range, loss, 'b-o', label='Training Loss')
    if val_loss:
        ax1.plot(epochs_range, val_loss, 'r-s', label='Validation Loss')
    ax1.set_title('Loss Trajectory', fontsize=12, fontweight='bold')
    ax1.set_xlabel('Epochs')
    ax1.set_ylabel('Loss')
    ax1.legend(loc='upper right')
    ax1.grid(True, linestyle='--', alpha=0.6)

    # Accuracy plot
    if acc:
        ax2.plot(epochs_range, acc, 'b-o', label='Training Accuracy')
        if val_acc:
            ax2.plot(epochs_range, val_acc, 'r-s', label='Validation Accuracy')
        ax2.set_title('Accuracy Trajectory', fontsize=12, fontweight='bold')
        ax2.set_xlabel('Epochs')
        ax2.set_ylabel('Accuracy')
        ax2.legend(loc='lower right')
        ax2.grid(True, linestyle='--', alpha=0.6)

    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()
    print(f"Saved training history plot to: {save_path}")

def plot_confusion_matrix(cm, labels, save_path: str):
    """
    Plots readable seaborn heatmap of confusion matrix (actual vs predicted) and saves to file.
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=labels, yticklabels=labels)
    plt.title('CICIDS2017 Intrusion Detection - Confusion Matrix', fontsize=13, fontweight='bold')
    plt.ylabel('Actual Label', fontsize=11)
    plt.xlabel('Predicted Label', fontsize=11)
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()
    print(f"Saved confusion matrix plot to: {save_path}")

def plot_multiclass_roc(y_true_onehot, y_prob, labels, save_path: str):
    """
    Computes One-vs-Rest ROC curve and ROC-AUC score for each attack class and saves ROC plot.
    """
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    n_classes = len(labels)
    plt.figure(figsize=(10, 8))

    fpr = dict()
    tpr = dict()
    roc_auc = dict()

    for i in range(n_classes):
        fpr[i], tpr[i], _ = roc_curve(y_true_onehot[:, i], y_prob[:, i])
        roc_auc[i] = auc(fpr[i], tpr[i])
        plt.plot(fpr[i], tpr[i], lw=2, label=f'Class: {labels[i]} (AUC = {roc_auc[i]:.4f})')

    plt.plot([0, 1], [0, 1], 'k--', lw=2, label='Chance (AUC = 0.50)')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate (1 - Specificity)', fontsize=11)
    plt.ylabel('True Positive Rate (Sensitivity)', fontsize=11)
    plt.title('Multiclass One-vs-Rest ROC Curves', fontsize=13, fontweight='bold')
    plt.legend(loc='lower right', fontsize=9)
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300)
    plt.close()
    print(f"Saved ROC curve plot to: {save_path}")
