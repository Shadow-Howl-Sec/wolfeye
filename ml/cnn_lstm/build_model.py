"""
1D Conv1D-LSTM Hybrid Architecture and Categorical Focal Loss definition for CICIDS2017 tabular classification.
"""

import os
os.environ['KERAS_BACKEND'] = 'torch'

import keras
from keras import layers, models, optimizers, ops

@keras.saving.register_keras_serializable(package="ml.cnn_lstm.build_model")
class CategoricalFocalLoss(keras.losses.Loss):
    """
    Categorical Focal Loss for multi-class classification on highly imbalanced data.
    FL(p_t) = - (1 - p_t)^gamma * log(p_t + epsilon)
    Down-weights easy-to-classify samples (gamma=2.0) and focuses gradients on hard minority attack samples.
    """
    def __init__(self, gamma: float = 2.0, name: str = "categorical_focal_loss", reduction: str = "sum_over_batch_size", **kwargs):
        super().__init__(name=name, reduction=reduction, **kwargs)
        self.gamma = gamma

    def call(self, y_true, y_pred):
        eps = 1e-7
        y_pred = ops.clip(y_pred, eps, 1.0 - eps)
        
        # Check if y_true is integer-encoded or one-hot encoded
        if len(ops.shape(y_true)) == 1 or (len(ops.shape(y_true)) == 2 and ops.shape(y_true)[1] == 1):
            num_classes = ops.shape(y_pred)[1]
            y_true_onehot = ops.one_hot(ops.cast(y_true, "int32"), num_classes)
        else:
            y_true_onehot = ops.cast(y_true, "float32")

        # Compute cross entropy and focal term
        cross_entropy = -y_true_onehot * ops.log(y_pred)
        focal_weight = ops.power(1.0 - y_pred, self.gamma)
        focal_loss = focal_weight * cross_entropy
        
        return ops.sum(focal_loss, axis=-1)

    def get_config(self):
        config = super().get_config()
        config.update({"gamma": self.gamma})
        return config

def build_hybrid_1d_cnn_lstm(
    input_shape: tuple = (52, 1),
    num_classes: int = 7,
    learning_rate: float = 0.001,
    use_focal_loss: bool = True
) -> keras.Model:
    """
    Constructs and compiles the Hybrid 1D Conv1D-LSTM Intrusion Detection Model.

    Architecture Flow:
    Input (52, 1) - 52 continuous numerical metrics as 1D sequence tensor
        ↓
    Conv1D(32 filters, kernel_size=3, padding='same', activation='relu')
        ↓
    BatchNormalization()
        ↓
    MaxPooling1D(pool_size=2) -> Output shape: (26, 32)
        ↓
    Conv1D(64 filters, kernel_size=3, padding='same', activation='relu')
        ↓
    BatchNormalization()
        ↓
    MaxPooling1D(pool_size=2) -> Output shape: (13, 64)
        ↓
    LSTM(128 units, return_sequences=False) -> Temporal sequence representation over 13 slots
        ↓
    Dropout(0.3)
        ↓
    Dense(64, activation='relu')
        ↓
    Dense(num_classes, activation='softmax')
    """
    input_layer = layers.Input(shape=input_shape, name="flow_1d_sequence_input")

    # Block 1: Conv1D + BatchNorm + MaxPool1D
    x = layers.Conv1D(32, kernel_size=3, padding='same', activation='relu', name="conv1d_1")(input_layer)
    x = layers.BatchNormalization(name="bn_1")(x)
    x = layers.MaxPooling1D(pool_size=2, name="maxpool1d_1")(x)  # (26, 32)

    # Block 2: Conv1D + BatchNorm + MaxPool1D
    x = layers.Conv1D(64, kernel_size=3, padding='same', activation='relu', name="conv1d_2")(x)
    x = layers.BatchNormalization(name="bn_2")(x)
    x = layers.MaxPooling1D(pool_size=2, name="maxpool1d_2")(x)  # (13, 64)

    # Recurrent Temporal Representation
    x = layers.LSTM(128, return_sequences=False, name="lstm_128")(x)  # (128,)

    # Regularization & Classification
    x = layers.Dropout(0.3, name="dropout_0.3")(x)
    x = layers.Dense(64, activation='relu', name="dense_64")(x)
    output_layer = layers.Dense(num_classes, activation='softmax', name="softmax_output")(x)

    model = models.Model(inputs=input_layer, outputs=output_layer, name="Hybrid_1D_Conv1D_LSTM")

    optimizer = optimizers.Adam(learning_rate=learning_rate)
    loss_fn = CategoricalFocalLoss(gamma=2.0) if use_focal_loss else 'sparse_categorical_crossentropy'

    model.compile(
        optimizer=optimizer,
        loss=loss_fn,
        metrics=['accuracy']
    )
    return model

def build_random_forest_baseline(random_state: int = 42) -> RandomForestClassifier:
    """
    Constructs Random Forest baseline classifier for comparative evaluation.
    """
    from sklearn.ensemble import RandomForestClassifier

    return RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=random_state,
        n_jobs=-1
    )
