#!/usr/bin/env python
# coding: utf-8

# In[3]:


import joblib
import pandas as pd
from sklearn.metrics import classification_report,accuracy_score


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

evaluate()



# In[ ]:




