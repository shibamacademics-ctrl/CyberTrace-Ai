# 🔍 CyberTrace AI: Explainable AI Intrusion Detection System

An intrusion detection system that doesn't just detect network attacks — it **explains why** using SHAP (SHapley Additive exPlanations). Instead of a black-box "Attack Detected" alert, analysts get a full **Reasoning Certificate**:

> "Flagged as DDoS because packet rate spiked 80%, inter-arrival time dropped sharply, and average packet size was unusually small."

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Dataset](#dataset)
- [Installation](#installation)
- [Team Roles](#team-roles)
- [How It Works](#how-it-works)
- [Running the Project](#running-the-project)
- [API Reference](#api-reference)
- [Screenshots](#screenshots)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

Traditional Intrusion Detection Systems (IDS) tell you *that* something bad happened, but not *why*. This makes it hard for security analysts to trust and act on AI-driven alerts.

**CyberTrace AI solves this** by combining:
1. A **Random Forest classifier** trained on real network traffic to detect attacks
2. **SHAP explainability** to identify exactly which features drove each decision
3. A **Reasoning Certificate** that translates SHAP values into plain English
4. An interactive **dashboard** so analysts can inspect every alert visually

---

## ✨ Features

- 🚨 Multi-class attack detection (DDoS, PortScan, Brute Force, Web Attack, Bot, BENIGN)
- 📊 SHAP-based feature importance for every single prediction
- 📄 Auto-generated human-readable "Reasoning Certificates"
- 🖥️ Interactive dashboard with live alert feed, SHAP charts, and certificate cards
- 🔍 Filterable by attack type, confidence threshold, and time range
- ⚡ REST API (FastAPI) for integration with other security tools
- 💾 Optional SQLite database for alert history

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Data Processing | pandas, numpy |
| Machine Learning | scikit-learn (Random Forest) |
| Explainability | SHAP |
| Backend API | FastAPI, Uvicorn, Pydantic |
| Database | SQLite + SQLAlchemy |
| Frontend (Option A) | Streamlit |
| Frontend (Option B) | HTML, CSS, JavaScript (Chart.js) |

---

## 📁 Project Structure

```
cybertrace_ai/
│
├── data/
│   ├── cicids2017_full/          ← raw dataset files (downloaded, see below)
│   └── cleaned.csv                ← output of preprocess.py
│
├── model/
│   ├── model.pkl                  ← trained Random Forest classifier
│   ├── scaler.pkl                 ← fitted StandardScaler
│   ├── label_encoder.pkl          ← fitted LabelEncoder
│   ├── feature_names.json         ← list of selected features
│   ├── X_test.csv / y_test.csv    ← held-out test set
│   └── confusion_matrix.png       ← evaluation output
│
├── api/
│   └── main.py                    ← FastAPI server (Person 2)
│
├── components/
│   ├── shap_bar_chart.py          ← SHAP visualization (Person 3a)
│   ├── shap_force_plot.py         ← SHAP visualization (Person 3a)
│   ├── certificate_card.py        ← Certificate UI (Person 3b)
│   └── alert_feed.py              ← Dashboard alert list (Person 4)
│
├── explore.py                     ← Level 2: data exploration
├── preprocess.py                  ← Level 3: data cleaning
├── features.py                    ← Level 4: feature engineering
├── train_model.py                 ← Level 5: model training
├── evaluate.py                    ← Level 6: model evaluation
├── explainer.py                   ← SHAP wrapper (Person 2)
├── certificate_generator.py       ← Certificate text logic (Person 2)
├── database.py                    ← SQLite models (optional)
│
├── app.py                         ← Streamlit dashboard entry point
├── index.html                     ← Standalone HTML/CSS/JS dashboard
│
├── requirements.txt
└── README.md
```

---

## 📦 Dataset

This project uses **CICIDS2017 (Full, Modified, All 8 Files)** — a cleaned and merged version of the Canadian Institute for Cybersecurity's intrusion detection dataset, containing labeled benign and attack network traffic (DDoS, PortScan, Brute Force, Web Attack, Bot, Infiltration, DoS).

### 🔗 Download Link

**Kaggle:** [https://www.kaggle.com/datasets/sweety18/cicids2017-full-modified-all-8-files](https://www.kaggle.com/datasets/sweety18/cicids2017-full-modified-all-8-files)

### How to Download

**Option A — Manual download (easiest)**
1. Go to the link above
2. Sign in to Kaggle (free account)
3. Click **Download** (top right) to get the ZIP file
4. Extract it into `cybertrace_ai/data/cicids2017_full/`

**Option B — Kaggle CLI**
```bash
pip install kaggle

# Place your kaggle.json API token in ~/.kaggle/ first
# (Kaggle Account → Create New API Token)

kaggle datasets download -d sweety18/cicids2017-full-modified-all-8-files -p data/ --unzip
```

### After Downloading

Verify the files landed in the right place:

```bash
python -c "import os; print(os.listdir('data/cicids2017_full'))"
```

You should see all 8 CSV files listed. Then update the path in `preprocess.py` / `explore.py` to point at this folder:

```python
DATA_FOLDER = 'data/cicids2017_full'
```

> ⚠️ **Note:** This dataset is several GB in size. If you have limited RAM, sample it down before training:
> ```python
> df = df.sample(frac=0.3, random_state=42)
> ```

---

## ⚙️ Installation

### Prerequisites
- Python 3.9+
- pip
- (Optional) Kaggle account for CLI dataset download

### Setup

```bash
# Clone the repo
git clone <your-repo-url>
cd cybertrace_ai

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate      # Mac/Linux
venv\Scripts\activate         # Windows

# Install dependencies
pip install -r requirements.txt
```

### `requirements.txt`

```
pandas
numpy
scikit-learn
joblib
matplotlib
seaborn
shap
fastapi
uvicorn
pydantic
sqlalchemy
streamlit
requests
```

---

## 👥 Team Roles

| Person | Role | Deliverable |
|--------|------|-------------|
| **1** | Data Engineer / ML Trainer | `model.pkl`, cleaned dataset, evaluation report |
| **2** | SHAP + API Engineer | Running FastAPI `/predict` endpoint with SHAP explanations |
| **3a** | SHAP Visualization Developer | Bar chart + force plot components |
| **3b** | Certificate Text Developer | Human-readable Reasoning Certificates |
| **4** | Dashboard Developer | Full frontend (Streamlit or HTML/CSS/JS) |

See `COMPLETE_PROJECT_SYLLABUS.md` for the full week-by-week breakdown per role.

---

## 🧠 How It Works

```
Raw Network Traffic (CICIDS2017)
        ↓
Data Cleaning + Feature Engineering  (Person 1)
        ↓
Random Forest Classifier             (Person 1)
        ↓
SHAP TreeExplainer                   (Person 2)
        ↓
Reasoning Certificate Generator      (Person 2 / 3b)
        ↓
FastAPI /predict Endpoint            (Person 2)
        ↓
   ┌────────────┬─────────────┐
   ↓            ↓             ↓
Alert Feed   SHAP Charts   Certificate Card
 (Person 4)   (Person 3a)    (Person 3b)
   └────────────┴─────────────┘
        ↓
     Dashboard (Person 4)
```

---

## ▶️ Running the Project

### 1. Train the model (Person 1's pipeline)

```bash
python explore.py
python preprocess.py
python features.py
python train_model.py
python evaluate.py
```

### 2. Start the API (Person 2)

```bash
cd api
uvicorn main:app --reload --port 8000
```

Verify it's running:
```bash
curl http://localhost:8000/health
```

### 3. Launch the dashboard

**Option A — Streamlit**
```bash
streamlit run app.py
```
Open `http://localhost:8501`

**Option B — Standalone HTML/CSS/JS**
```bash
# Just open the file directly, or serve it locally:
python -m http.server 8080
```
Open `http://localhost:8080/index.html`

---

## 📡 API Reference

### `GET /health`
Returns API and model status.

### `GET /features`
Returns the list of expected feature names.

### `POST /predict`
Runs prediction + SHAP explanation on a single traffic sample.

**Request:**
```json
{
  "features": {
    "Flow Duration": 100000,
    "Total Fwd Packets": 500,
    "...": "..."
  }
}
```

**Response:**
```json
{
  "attack_type": "DDoS",
  "confidence": 94.0,
  "is_attack": true,
  "summary": "Flagged as DDoS because packet rate spiked...",
  "context": "A DDoS attack floods the network...",
  "reasons": [
    {"phrase": "packet rate spiked abnormally", "impact_level": "high"}
  ],
  "top_shap_values": [
    {"feature": "Flow Packets/s", "shap_value": 0.4521, "impact": "positive"}
  ]
}
```

### `GET /alerts?limit=50`
Returns recent alerts from the database (if enabled).

---

## 🗺️ Roadmap

- [x] Data preprocessing pipeline
- [x] Random Forest model training + evaluation
- [x] SHAP explainability integration
- [x] Reasoning certificate generation
- [x] FastAPI backend
- [x] Streamlit dashboard prototype
- [x] Standalone HTML/CSS/JS dashboard
- [ ] Live packet capture integration (real-time traffic)
- [ ] Deploy API + dashboard to cloud
- [ ] Add authentication for analyst logins
- [ ] LLM-enhanced certificate generation (optional)

---

## 🤝 Contributing

This is a student/team project built across 5 roles. If extending it:
1. Follow the folder structure above
2. Keep the JSON contract between API and frontend consistent
3. Document any new features in this README

---

## 📄 License

This project is for educational purposes, built using the CICIDS2017 dataset (Canadian Institute for Cybersecurity, University of New Brunswick). Refer to the [official CIC dataset terms](https://www.unb.ca/cic/datasets/ids-2018.html) for usage restrictions on the underlying data.

---

**Built with:** scikit-learn · SHAP · FastAPI · Streamlit · Chart.js
