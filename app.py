from flask import Flask, render_template, request, send_file, make_response

from scanner import (
    scan_text,
    calculate_risk,
    get_recommendations,
    redact_text,
    get_shareability,
    get_risk_explanations,
    get_risk_severity
)

import os
import json

from pypdf import PdfReader
from docx import Document


app = Flask(__name__)


# ========================================
# FOLDERS AND FILES
# ========================================

UPLOAD_FOLDER = "uploads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

HISTORY_FILE = "scan_history.json"


# ========================================
# SCAN HISTORY FUNCTIONS
# ========================================

def save_scan_history(filename, score, level, share_status):

    history = []

    if os.path.exists(HISTORY_FILE):

        try:

            with open(
                HISTORY_FILE,
                "r",
                encoding="utf-8"
            ) as file:

                history = json.load(file)

        except (json.JSONDecodeError, FileNotFoundError):

            history = []


    # Add newest scan at the beginning

    history.insert(
        0,
        {
            "filename": filename,
            "score": score,
            "level": level,
            "share_status": share_status
        }
    )


    # Keep only latest 5 scans

    history = history[:5]


    # Save history

    with open(
        HISTORY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            history,
            file,
            indent=4
        )


def get_scan_history():

    if not os.path.exists(HISTORY_FILE):

        return []


    try:

        with open(
            HISTORY_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (json.JSONDecodeError, FileNotFoundError):

        return []


# ========================================
# HOME PAGE
# ========================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ========================================
# SCAN FILE
# ========================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    uploaded_file = request.files["file"]


    # --------------------------------
    # FILE NAME
    # --------------------------------

    filename = uploaded_file.filename

    lower_filename = filename.lower()


    # --------------------------------
    # READ PDF
    # --------------------------------

    if lower_filename.endswith(".pdf"):

        reader = PdfReader(
            uploaded_file
        )

        file_content = ""

        for page in reader.pages:

            text = page.extract_text()

            if text:

                file_content += (
                    text + "\n"
                )


    # --------------------------------
    # READ WORD DOCUMENT
    # --------------------------------

    elif lower_filename.endswith(".docx"):

        document = Document(
            uploaded_file
        )

        file_content = ""

        for paragraph in document.paragraphs:

            file_content += (
                paragraph.text + "\n"
            )


    # --------------------------------
    # READ TEXT FILE
    # --------------------------------

    else:

        file_content = uploaded_file.read().decode(
            "utf-8",
            errors="ignore"
        )


    # ========================================
    # SCAN
    # ========================================

    results = scan_text(
        file_content
    )


    # ========================================
    # RISK SCORE
    # ========================================

    score, level = calculate_risk(
        results
    )


    # ========================================
    # SHAREABILITY
    # ========================================

    share_status, share_message = get_shareability(
        score
    )


    # ========================================
    # RECOMMENDATIONS
    # ========================================

    recommendations = get_recommendations(
        results
    )


    # ========================================
    # RISK BREAKDOWN
    # ========================================

    risk_breakdown = {

        "emails": len(
            results["emails"]
        ),

        "phone_numbers": len(
            results["phone_numbers"]
        ),

        "ip_addresses": len(
            results["ip_addresses"]
        ),

        "credentials": len(
            results["credentials"]
        )
    }


    # ========================================
    # SCAN SUMMARY
    # ========================================

    total_risks = (

        len(results["emails"])

        + len(results["phone_numbers"])

        + len(results["ip_addresses"])

        + len(results["credentials"])
    )


    categories_checked = 4


    # ========================================
    # RISK EXPLANATIONS
    # ========================================

    explanations = get_risk_explanations(
        results
    )


    # ========================================
    # RISK SEVERITY
    # ========================================

    severity = get_risk_severity(
        results
    )


    # ========================================
    # SAVE SCAN HISTORY
    # ========================================

    save_scan_history(
        filename,
        score,
        level,
        share_status
    )


    # ========================================
    # SAVE EXTRACTED CONTENT
    # ========================================

    file_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )


    with open(
        file_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            file_content
        )


    # ========================================
    # SHOW RESULTS PAGE
    # ========================================

    return render_template(

        "results.html",

        filename=filename,

        results=results,

        score=score,

        level=level,

        recommendations=recommendations,

        share_status=share_status,

        share_message=share_message,

        risk_breakdown=risk_breakdown,

        explanations=explanations,

        severity=severity,

        total_risks=total_risks,

        categories_checked=categories_checked,

        history=get_scan_history()
    )


# ========================================
# SMART REDACTION
# ========================================

@app.route(
    "/redact/<filename>",
    methods=["POST"]
)
def redact(filename):

    file_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )


    # --------------------------------
    # READ ORIGINAL FILE
    # --------------------------------

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        original_text = file.read()


    # --------------------------------
    # REDACT SENSITIVE INFORMATION
    # --------------------------------

    cleaned_text = redact_text(
        original_text
    )


    # --------------------------------
    # CLEANED FILE NAME
    # --------------------------------

    cleaned_filename = (
        "PrivacyGuard_Cleaned_"
        + filename
    )


    cleaned_path = os.path.join(
        UPLOAD_FOLDER,
        cleaned_filename
    )


    # --------------------------------
    # SAVE CLEANED FILE
    # --------------------------------

    with open(
        cleaned_path,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            cleaned_text
        )


    # --------------------------------
    # DOWNLOAD CLEAN FILE
    # --------------------------------

    return send_file(

        cleaned_path,

        as_attachment=True,

        download_name=cleaned_filename
    )


# ========================================
# DOWNLOADABLE PRIVACY REPORT
# ========================================

@app.route(
    "/report/<filename>"
)
def report(filename):

    file_path = os.path.join(
        UPLOAD_FOLDER,
        filename
    )


    # --------------------------------
    # READ FILE
    # --------------------------------

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        original_text = file.read()


    # --------------------------------
    # SCAN AGAIN
    # --------------------------------

    results = scan_text(
        original_text
    )


    # --------------------------------
    # RISK SCORE
    # --------------------------------

    score, level = calculate_risk(
        results
    )


    # --------------------------------
    # SHAREABILITY
    # --------------------------------

    share_status, share_message = get_shareability(
        score
    )


    # --------------------------------
    # RECOMMENDATIONS
    # --------------------------------

    recommendations = get_recommendations(
        results
    )


    # --------------------------------
    # EXPLANATIONS
    # --------------------------------

    explanations = get_risk_explanations(
        results
    )


    # ========================================
    # CREATE REPORT
    # ========================================

    report_text = f"""
========================================
          PRIVACYGUARD REPORT
========================================

File: {filename}


PRIVACY RISK SCORE
{score} / 100


RISK LEVEL
{level}


SHAREABILITY VERDICT
{share_status}

{share_message}


----------------------------------------
RISK BREAKDOWN
----------------------------------------

Email Addresses: {len(results["emails"])}

Phone Numbers: {len(results["phone_numbers"])}

IP Addresses: {len(results["ip_addresses"])}

Credentials / Secrets: {len(results["credentials"])}


----------------------------------------
WHY THESE RISKS ARE IMPORTANT
----------------------------------------

"""


    # --------------------------------
    # ADD EXPLANATIONS
    # --------------------------------

    for explanation in explanations:

        report_text += (
            "- "
            + explanation
            + "\n"
        )


    report_text += """
----------------------------------------
RECOMMENDATIONS
----------------------------------------

"""


    # --------------------------------
    # ADD RECOMMENDATIONS
    # --------------------------------

    for recommendation in recommendations:

        report_text += (
            "- "
            + recommendation
            + "\n"
        )


    report_text += """
========================================
          Generated by PrivacyGuard
========================================
"""


    # ========================================
    # DOWNLOAD REPORT
    # ========================================

    response = make_response(
        report_text
    )


    response.headers[
        "Content-Type"
    ] = "text/plain"


    response.headers[
        "Content-Disposition"
    ] = (
        "attachment; "
        "filename=PrivacyGuard_Report_"
        + filename
        + ".txt"
    )


    return response


# ========================================
# RUN APPLICATION
# ========================================

if __name__ == "__main__":

    app.run(
        debug=True
    )