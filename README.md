# 🔐 PrivacyGuard

### Digital Privacy Risk Analyzer

PrivacyGuard is a Flask-based cybersecurity project that analyzes documents for potentially sensitive information before they are shared.

It detects common privacy risks such as email addresses, phone numbers, IP addresses, passwords, API keys, tokens and other secrets.

---

## ✨ Features

- 🔎 Privacy risk scanning
- 📊 Privacy risk score
- 🚦 Shareability verdict
- 📋 Risk breakdown
- 🧠 Risk explanations
- 🛡️ Privacy recommendations
- 🔒 Smart redaction
- 📄 Downloadable privacy report
- 🕘 Scan history
- 📑 PDF support
- 📝 DOCX support
- 📄 TXT support
- 🎨 Responsive cybersecurity-themed interface

---

## 🛠️ Tech Stack

- Python
- Flask
- HTML5
- CSS3
- Regular Expressions
- PyPDF
- python-docx

---

## 🔍 Information Detected

PrivacyGuard currently checks for:

| Category | Example |
|---|---|
| 📧 Email | user@example.com |
| 📱 Phone | 9876543210 |
| 🌐 IP Address | 192.168.1.25 |
| 🔐 Credentials | Password, API key, token |

---

## ⚙️ How It Works

```text
Upload Document
       ↓
Extract Text
       ↓
Detect Sensitive Information
       ↓
Calculate Privacy Risk
       ↓
Generate Shareability Verdict
       ↓
Show Recommendations
       ↓
Optional Smart Redaction
       ↓
Download Clean File / Report