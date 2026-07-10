#!/usr/bin/env python
# coding: utf-8




import pandas as pd
import numpy as np
def load_and_clean(filepath):
    print("Loading data...")
    df = pd.read_csv(filepath,low_memory = False)

    df.columns = df.columns.str.strip()

    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    before = len(df)
    df.dropna(inplace = True)#Drop rows with Missing values
    after = len(df)
    print(f"Dropped {before - after} rows with null")



    mapping = {
        "DoS Hulk": "DDoS",
        "DoS GoldenEye": "DDoS",
        "DoS slowloris": "DDoS",
        "DoS Slowhttptest": "DDoS",
        "Web Attack_Brute Force": "Web Attack",
        "Web Attack_XSS": "Web Attack",
        "Web Attack_Sql Injection": "Web Attack"
    }

    df["Label"] = df["Label"].replace(mapping)

    allowed = ['BENIGN', 'DDoS', 'PortScan', 'Bot', 'Infiltration', 'Web Attack',]
    df = df[df["Label"].isin(allowed)]

    print("Final label counts: ",df["Label"].value_counts())
    print("Clean data shape: ",df.shape)
    return df

df = pd.read_csv("data/cicids2017.csv",low_memory = False)
print("Row,Column: ",df.shape)
df.rename(columns={" Label": "Label"}, inplace=True)
print(df["Label"].value_counts())
df = load_and_clean("data/cicids2017.csv")





