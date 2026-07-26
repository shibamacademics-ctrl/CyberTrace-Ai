#!/usr/bin/env python
"""
explore.py — Level 2: Data Exploration

Was referenced in the project's documented file structure but missing
from the uploaded codebase. Added to match: dataset shape, column list,
label distribution, missing values, dtypes.
"""

import pandas as pd

DATA_PATH = "data/cicids2017.csv"


def explore(filepath=DATA_PATH):
    df = pd.read_csv(filepath, low_memory=False)
    df.columns = df.columns.str.strip()

    print("Row, Column:", df.shape)
    print("\nColumn list:", df.columns.tolist())

    label_col = "Label" if "Label" in df.columns else " Label"
    print(f"\nLabel distribution ({label_col}):")
    print(df[label_col].value_counts())

    print("\nMissing values per column (non-zero only):")
    nulls = df.isnull().sum()
    print(nulls[nulls > 0] if nulls.sum() > 0 else "None")

    print("\nData types:")
    print(df.dtypes.value_counts())

    return df


if __name__ == "__main__":
    explore()
