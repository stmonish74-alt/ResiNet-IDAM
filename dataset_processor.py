
import pandas as pd
from pathlib import Path

UPLOAD_FOLDER = Path(__file__).resolve().parent.parent / "datasets"
UPLOAD_FOLDER.mkdir(exist_ok=True)


def process_dataset(file):
    if not file or not file.filename.lower().endswith(".csv"):
        raise ValueError("Please upload a valid CSV file.")

    # Read uploaded CSV safely
    df = pd.read_csv(file)

    if df.empty:
        raise ValueError("The uploaded dataset is empty.")

    if len(df.columns) < 2:
        raise ValueError("Dataset must contain at least two columns.")

    # Basic dataset information
    total_rows = len(df)
    total_columns = len(df.columns)

    missing_values = int(df.isnull().sum().sum())
    duplicate_rows = int(df.duplicated().sum())

    # Clean column names
    df.columns = (
        df.columns.astype(str)
        .str.strip()
        .str.replace(" ", "_")
    )

    # Replace infinite values and handle missing values
    df = df.replace([float("inf"), float("-inf")], pd.NA)
    df = df.drop_duplicates()

    for column in df.columns:
        if pd.api.types.is_numeric_dtype(df[column]):
            df[column] = df[column].fillna(df[column].median())
        else:
            df[column] = df[column].fillna("Unknown")

    # Save processed dataset
    output_path = UPLOAD_FOLDER / "processed_dataset.csv"
    df.to_csv(output_path, index=False)

    return {
        "filename": file.filename,
        "total_rows": total_rows,
        "total_columns": total_columns,
        "missing_values": missing_values,
        "duplicate_rows": duplicate_rows,
        "processed_rows": len(df),
        "columns": df.columns.tolist(),
        "preview": df.head(10).to_dict(orient="records")
    }
