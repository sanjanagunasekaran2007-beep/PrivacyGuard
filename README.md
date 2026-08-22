🛡️ PrivacyGuard — Digital Privacy Risk Analyzer

«Scan. Detect. Understand. Protect.»

PrivacyGuard is an intelligent Digital Privacy Risk Analyzer that helps users identify sensitive and personally identifiable information (PII) hidden inside documents and images before they share them.

It analyzes multiple file formats, extracts text using normal parsing and OCR when required, detects sensitive information, calculates privacy risk, explains the findings, and provides actionable recommendations to help users protect their data.

---

✨ Why PrivacyGuard?

Sharing a document without checking its contents can accidentally expose sensitive information such as:

- 📧 Email addresses
- 📱 Phone numbers
- 💳 Credit card numbers
- 🌐 IP addresses
- 🔐 Credentials and passwords
- 🪪 Personal identification information
- 📍 Other potentially sensitive information

PrivacyGuard provides a simple workflow:

Upload → Scan → Detect → Analyze Risk → Protect → Download

---

🚀 Key Features

📂 Multi-Format Document Scanner

PrivacyGuard supports multiple types of files:

Format| Support
".TXT"| ✅
".PDF"| ✅
Scanned/Image PDF| ✅ OCR
".DOCX"| ✅
DOCX embedded images| ✅ OCR
".XLSX" / Excel| ✅
".PPTX" / PowerPoint| ✅
".JPG / .JPEG"| ✅ OCR
".PNG"| ✅ OCR
Screenshots| ✅ OCR
Photos| ✅ OCR

This allows PrivacyGuard to analyze both digital text and text contained inside images.

---

🔍 Intelligent PII Detection

PrivacyGuard searches uploaded content for potentially sensitive information including:

- 📧 Email Addresses
- 📱 Phone Numbers
- 💳 Credit Card Numbers
- 🌐 IP Addresses
- 🔑 Passwords / Credentials
- 🪪 Sensitive Personal Information
- 🔐 Other configurable sensitive patterns

The detection engine uses pattern-based analysis and document text extraction to identify potential privacy risks.

---

👁️ OCR-Based Scanning

PrivacyGuard can analyze documents where the information isn't available as normal selectable text.

Using OCR technology, it can extract text from:

- 📸 Photos
- 🖼️ PNG/JPG images
- 📄 Scanned PDFs
- 📑 DOCX embedded images
- 📱 Screenshots

This makes PrivacyGuard useful even when sensitive information exists only as an image.

---

🚨 Risk & Severity Analysis

Every detected finding is analyzed and assigned a severity level.

Severity Levels

Severity| Meaning
🟢 Low| Limited privacy concern
🟡 Medium| Moderate privacy risk
🟠 High| Significant sensitive information
🔴 Critical| Highly sensitive information requiring immediate attention

PrivacyGuard also provides an overall privacy risk assessment based on the findings.

---

📊 Risk Breakdown

Instead of simply showing detected information, PrivacyGuard provides a detailed breakdown of the privacy risk.

Users can understand:

- Total findings
- Finding categories
- Severity levels
- Overall risk
- Most dangerous exposed information
- Recommended actions

This makes the scanner more useful than a simple regex-based detection tool.

---

🧠 Explainable Privacy Analysis

PrivacyGuard doesn't just say "risk detected."

It helps users understand:

«What was detected → Why it matters → How serious it is → What you should do»

This makes the system easier to understand for users who may not have a cybersecurity background.

---

🛡️ Smart Redaction

PrivacyGuard can help protect detected sensitive information through smart redaction.

Instead of manually searching through a document, users can identify sensitive information and create a safer version before sharing it.

Example:

Original:
Email: sanjana@example.com
Phone: 9876543210

Protected:
Email: [REDACTED]
Phone: [REDACTED]

---

📤 Shareability Verdict

PrivacyGuard provides a clear assessment of whether a document is suitable for sharing.

Example:

🔴 NOT SAFE TO SHARE

Critical sensitive information detected.

Recommendation: Redact sensitive information before sharing.

This gives users an easy-to-understand final decision instead of forcing them to interpret technical results.

---

💡 Privacy Recommendations

After scanning, PrivacyGuard provides actionable recommendations based on detected risks.

Examples include:

- Remove exposed credentials
- Redact personal information
- Hide financial information
- Remove unnecessary contact information
- Review the document before sharing
- Avoid uploading sensitive files to untrusted platforms

---

📈 Privacy Dashboard

The interface provides a visual overview of the scan results, including:

- Total findings
- Risk score
- Severity distribution
- Detected categories
- Shareability status
- Recommended actions

The goal is to make privacy analysis fast, visual, and easy to understand.

---

🏗️ System Workflow

                ┌─────────────────────┐
                │     Upload File     │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │  File Type Detection│
                └──────────┬──────────┘
                           │
             ┌─────────────┴─────────────┐
             │                           │
             ▼                           ▼
      Normal Text                    Image Content
      Extraction                         │
             │                           ▼
             │                     OCR Processing
             │                           │
             └─────────────┬─────────────┘
                           ▼
                ┌─────────────────────┐
                │  PII Detection      │
                └──────────┬──────────┘
                           ▼
                ┌─────────────────────┐
                │ Risk Classification │
                └──────────┬──────────┘
                           ▼
                ┌─────────────────────┐
                │ Risk & Explanation  │
                └──────────┬──────────┘
                           ▼
                ┌─────────────────────┐
                │ Shareability Verdict│
                └──────────┬──────────┘
                           ▼
                ┌─────────────────────┐
                │ Protection / Report │
                └─────────────────────┘

---

🧰 Technology Stack

Backend

- 🐍 Python
- 🌶️ Flask
- Regular Expressions
- OCR processing
- Document parsing libraries

Document Processing

- PyPDF — PDF text extraction
- python-docx — DOCX processing
- openpyxl — Excel/XLSX processing
- python-pptx — PowerPoint/PPTX processing
- Pillow — Image processing
- Tesseract OCR / pytesseract — OCR text extraction

Frontend

- HTML5
- CSS3
- JavaScript
- Responsive UI

---

📁 Project Structure

PrivacyGuard/
│
├── app.py
│
├── scanner/
│   ├── ...
│
├── templates/
│   ├── index.html
│   └── ...
│
├── static/
│   ├── css/
│   ├── js/
│   └── ...
│
├── uploads/
│
├── outputs/
│
├── requirements.txt
├── .gitignore
└── README.md

«The exact structure may vary depending on the current implementation.»

---

⚙️ Installation

1. Clone the repository

git clone https://github.com/YOUR-USERNAME/PrivacyGuard.git

cd PrivacyGuard

---

2. Create a virtual environment

Windows

python -m venv venv

Activate it:

venv\Scripts\activate

Linux / macOS

python3 -m venv venv

source venv/bin/activate

---

3. Install dependencies

pip install -r requirements.txt

---

🔎 OCR Setup

PrivacyGuard uses Tesseract OCR for extracting text from images and scanned documents.

Make sure Tesseract OCR is installed on your system.

The application can be configured with the local Tesseract executable path when required.

Example Windows path:

C:\Program Files\Tesseract-OCR\tesseract.exe

---

▶️ Run the Application

Start the Flask application:

python app.py

Then open:

http://127.0.0.1:5000

---

🧪 Example Detection

Input:

Name: Sanjana
Email: sanjana@example.com
Phone: 9876543210
Card: 4111 1111 1111 1111
IP: 192.168.1.10

PrivacyGuard can identify the sensitive information and generate findings such as:

Email Address      → High
Phone Number       → High
Credit Card        → Critical
IP Address         → Medium

The system then calculates the overall privacy risk and provides recommendations.

---

🔐 Privacy First

PrivacyGuard is designed around the principle:

«Your documents should be checked before they are shared.»

Users should avoid uploading real confidential information while testing or demonstrating the application.

For production deployment, additional security controls should be implemented, including:

- Secure file handling
- File size restrictions
- Malware scanning
- Authentication and authorization
- Secure temporary storage
- Automatic deletion of uploaded files
- HTTPS
- Rate limiting
- Input validation
- Secure deployment configuration

---

🎯 Use Cases

PrivacyGuard can be useful for:

👨‍🎓 Students

Check assignments, resumes, screenshots, and project documents before sharing them.

🏢 Organizations

Identify sensitive information before documents are distributed.

👨‍💻 Developers

Integrate privacy scanning into document-processing workflows.

📄 General Users

Check whether a document or image accidentally contains personal information.

---

🌟 Future Improvements

Potential future enhancements include:

- 🤖 AI-powered contextual PII detection
- 🌍 Multi-language OCR
- 🔐 Password-protected reports
- ☁️ Secure cloud deployment
- 👤 User authentication
- 📜 Scan history
- 📊 Advanced analytics
- 🔄 Batch file scanning
- 🧩 Custom detection rules
- 🔒 Automatic secure file deletion
- 📱 Progressive Web App support
- 🌐 Browser extension for privacy checking

---

⚠️ Disclaimer

PrivacyGuard is an informational privacy analysis tool.

Detection results may contain false positives or false negatives and should not be considered a guarantee that a document contains no sensitive information.

Always manually review important documents before sharing them.

---

👩‍💻 Author

Sanjana

B.E. Computer Science & Engineering Student
Cybersecurity & Blue Team Enthusiast

---

⭐ Support

If you find PrivacyGuard useful, consider giving the repository a ⭐ on GitHub.

---

🛡️ PrivacyGuard

Scan it. Understand it. Protect it. Share safely.