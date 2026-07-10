#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
import json
from sklearn.preprocessing import LabelEncoder,StandardScaler

SELECTED_FEATURES = [
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Total Length of Fwd Packets',
    'Total Length of Bwd Packets',
    'Fwd Packet Length Max',
    'Fwd Packet Length Mean',
    'Fwd Packet Length Std',
    'Bwd Packet Length Max',
    'Bwd Packet Length Mean',
    'Bwd Packet Length Std',
    'Min Packet Length',
    'Max Packet Length',
    'Packet Length Mean',
    'Packet Length Std',
    'Packet Length Variance',
    'Average Packet Size',
    'Avg Fwd Segment Size',
    'Avg Bwd Segment Size',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Packets/s',
    'Bwd Packets/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'FIN Flag Count',
    'SYN Flag Count',
    'RST Flag Count',
    'PSH Flag Count',
    'ACK Flag Count',
    'URG Flag Count',
    'ECE Flag Count',
    'Init_Win_bytes_forward',
    'Init_Win_bytes_backward',
    'Active Mean',
    'Active Std',
    'Active Max',
    'Active Min',
    'Idle Mean',
    'Idle Std',
    'Idle Max',
    'Idle Min',
    'Subflow Fwd Packets',
    'Subflow Fwd Bytes',
    'Subflow Bwd Packets',
    'Subflow Bwd Bytes',
    'Down/Up Ratio',
]

def scaling_features(df):
    scaling_list = [i for i in SELECTED_FEATURES if i in df.columns]
    df = df[scaling_list + ["Label"]].copy()#it merge scaling_list with Label if any copy exist then fix the bug

    le = LabelEncoder()
    df["Label"] = le.fit_transform(df["Label"])

    x = df[scaling_list]
    y = df["Label"]

    sc = StandardScaler()
    x_scaled = pd.DataFrame(
        sc.fit_transform(x),
        columns = scaling_list
    )

    return x_scaled,y,le,sc

df = pd.read_csv("data/cleaned.csv")
x,y,le,sc = scaling_features(df)
print("Features shape: ",x.shape)
print("Label value counts: ",y.value_counts())


# In[ ]:




