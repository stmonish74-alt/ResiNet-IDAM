
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "datasets" / "processed_dataset.csv"
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "intrusion_model.joblib"


def train_intrusion_model():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            "Processed dataset not found. Upload a CSV dataset first."
        )

    df = pd.read_csv(DATASET_PATH)

    if df.empty:
        raise ValueError("The dataset is empty.")

    # Identify the target column
    label_column = next(
        (col for col in df.columns if col.strip().lower() == "label"),
        None
    )

    if label_column is None:
        raise ValueError(
            "The dataset must contain a target column named 'label'."
        )

    df = df.dropna(subset=[label_column])

    if df[label_column].nunique() < 2:
        raise ValueError(
            "Training requires at least two different label classes."
        )

    X = df.drop(columns=[label_column])
    y = df[label_column].astype(str)

    # Identify numeric and categorical columns
    numeric_columns = X.select_dtypes(include=["number"]).columns.tolist()
    categorical_columns = X.select_dtypes(
        exclude=["number"]
    ).columns.tolist()

    if not numeric_columns and not categorical_columns:
        raise ValueError("No usable input features were found.")

    transformers = []

    if numeric_columns:
        numeric_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="median"))
        ])

        transformers.append(
            ("numeric", numeric_pipeline, numeric_columns)
        )

    if categorical_columns:
        categorical_pipeline = Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("encoder", OneHotEncoder(handle_unknown="ignore"))
        ])

        transformers.append(
            ("categorical", categorical_pipeline, categorical_columns)
        )

    preprocessing = ColumnTransformer(
        transformers=transformers
    )

    model = Pipeline([
        ("preprocessing", preprocessing),
        ("classifier", RandomForestClassifier(
            n_estimators=150,
            random_state=42,
            class_weight="balanced"
        ))
    ])

    # Split data for evaluation
    class_counts = y.value_counts()

    if class_counts.min() < 2:
        raise ValueError(
            "Each label class needs at least two records for training "
            "and evaluation. Add more samples to your dataset."
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    # Train model
    model.fit(X_train, y_train)

    # Evaluate model on held-out test data
    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test, predictions, average="weighted", zero_division=0
    )
    recall = recall_score(
        y_test, predictions, average="weighted", zero_division=0
    )
    f1 = f1_score(
        y_test, predictions, average="weighted", zero_division=0
    )

    # Save trained model
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)

    return {
        "status": "success",
        "message": "Intrusion detection model trained successfully.",
        "algorithm": "Random Forest Classifier",
        "training_records": len(X_train),
        "testing_records": len(X_test),
        "total_records": len(df),
        "classes": sorted(y.unique().tolist()),
        "accuracy": round(float(accuracy) * 100, 2),
        "precision": round(float(precision) * 100, 2),
        "recall": round(float(recall) * 100, 2),
        "f1_score": round(float(f1) * 100, 2),
        "confusion_matrix": confusion_matrix(
            y_test, predictions, labels=sorted(y.unique())
        ).tolist(),
        "classification_report": classification_report(
            y_test, predictions, zero_division=0, output_dict=True
        ),
        "model_path": str(MODEL_PATH)
    }


def predict_intrusion(record):
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "AI model not found. Train the model first."
        )

    if not isinstance(record, dict) or not record:
        raise ValueError("Provide a valid network activity record.")

    model = joblib.load(MODEL_PATH)

    input_data = pd.DataFrame([record])
    prediction = model.predict(input_data)[0]

    probabilities = model.predict_proba(input_data)[0]
    classes = model.named_steps["classifier"].classes_

    confidence = max(probabilities) * 100

    return {
        "prediction": str(prediction),
        "confidence": round(float(confidence), 2),
        "class_probabilities": {
            str(label): round(float(probability) * 100, 2)
            for label, probability in zip(classes, probabilities)
        }
    }
