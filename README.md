# 🛡️ PhishGuard

## AI-Powered Phishing Detection & Security Analysis System

PhishGuard is a multi-layer AI security analyzer designed to identify suspicious digital content before users interact with it.

It analyses:

- 🔗 URLs
- 💬 Messages
- ✉️ Emails
- 🌐 Webpages and look-alike websites
- 📱 APK files
- 🔗 APK download links

PhishGuard combines machine-learning models and security analysis rules to generate a risk score and explain detected security signals.

---

## 🚀 Key Features

### 🔗 URL Analysis
Analyses URLs using a trained machine-learning model to identify suspicious URL patterns.

### 💬 Message & Email Analysis
Scans messages and email content for suspicious or phishing-related language.

### 🌐 Webpage Analysis
Analyses webpage structure and content for suspicious indicators, including look-alike website signals.

### 📱 APK Static Analysis
Performs static security analysis of APK files without installing or executing them.

### 📊 Risk Scoring
Each scan produces a risk score and risk level:

- 🟢 Low
- 🟡 Medium
- 🔴 High

### 📄 Security Reports
Suspicious scan results can be converted into security reports and stored in Report History.

---

## 🤖 AI & Machine Learning

PhishGuard currently uses machine-learning models for URL and text classification.

### URL Model

- Character-level TF-IDF
- Logistic Regression
- Trained using a labelled URL dataset

### Text Model

- Word-level TF-IDF
- Logistic Regression
- Trained using a labelled text dataset

Webpage and APK analysis currently use security rules and static analysis techniques.

---

## 🏗️ System Architecture

```text
                    ┌──────────────────┐
                    │   PhishGuard UI  │
                    └────────┬─────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
           URL         Email / Message     Webpage
            │                │                │
            ▼                ▼                ▼
      URL ML Model      Text ML Model    Web Analyzer
            │                │                │
            └────────────────┼────────────────┘
                             │
                      Risk Analysis
                             │
                             ▼
                   Risk Score + Reasons
                             │
                             ▼
                    Report Assistant
