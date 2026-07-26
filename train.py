#!/usr/bin/env python
# coding: utf-8

# In[4]:


import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE
from preprocess import load_and_clean
from features import scaling_features

def train(filepath):
    df = load_and_clean(filepath)

    x,y,le,sc = scaling_features(df)

    x_train,x_test,y_train,y_test = train_test_split(x,y,test_size=0.2,random_state=42,stratify=y)

    print("Class counts before SMOTE:", y_train.value_counts().to_dict())
    def get_multiplier(count):
        if count < 100:
            return 20      # Infiltration-tier: needs heavy synthetic help
        elif count < 5000:
            return 3        # Bot/Web Attack-tier: modest boost is enough
        else:
            return 1        # don't touch it

    y_train_counts = y_train.value_counts()
    sampling_strategy = {
    label: min(count * get_multiplier(count), 50000)
    for label, count in y_train_counts.items()
    if count < 50000
    }

    smote = SMOTE(random_state=42, k_neighbors=2, sampling_strategy=sampling_strategy)
    x_train, y_train = smote.fit_resample(x_train, y_train)
    print(f"Train size: {len(x_train)} | Test size: {len(x_test)}")
    print("Class counts after SMOTE:", y_train.value_counts().to_dict())

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=20,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42
    )
    model.fit(x_train,y_train)
    print("Model Training complete")

    print("Saving important files for person2")
    joblib.dump(model,'model/model.pkl')
    joblib.dump(sc,'model/scaler.pkl')
    joblib.dump(le,'model/le_encoder.pkl')

    x_test.to_csv('model/x_test.csv',index=False)
    y_test.to_csv('model/y_test.csv',index=False)
    print("\nSaved:")
    print("  model/model.pkl")
    print("  model/scaler.pkl")
    print("  model/label_encoder.pkl")
    print("  model/x_test.csv")

    return model, x_test, y_test, le

train("data/cleaned.csv")


# In[ ]:




