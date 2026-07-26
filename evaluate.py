#!/usr/bin/env python
# coding: utf-8

# In[3]:


import joblib
import pandas as pd
from sklearn.metrics import classification_report,accuracy_score,confusion_matrix
# ADDED: confusion_matrix + plotting — the project's file structure lists
# model/confusion_matrix.png as evaluate.py's output, but nothing generated it.
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns


# In[5]:


def evaluate():
    model = joblib.load('model/model.pkl')
    le = joblib.load('model/le_encoder.pkl')
    x_test = pd.read_csv('model/x_test.csv')
    y_test = pd.read_csv('model/y_test.csv')

    y_pred = model.predict(x_test)

    acc = accuracy_score(y_test,y_pred)

    print(f"Model Accuracy score is: {acc*100:.2f}%")

    print("\nClassification report:")
    print(classification_report(y_test,y_pred,target_names=le.classes_))

    # ADDED: save confusion matrix heatmap to model/confusion_matrix.png
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=le.classes_, yticklabels=le.classes_)
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.title('Confusion Matrix — CyberTrace AI')
    plt.tight_layout()
    plt.savefig('model/confusion_matrix.png', dpi=120)
    print("\nSaved model/confusion_matrix.png")

evaluate()



# In[ ]:




