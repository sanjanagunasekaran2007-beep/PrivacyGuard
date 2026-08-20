import re


def scan_text(text):

    results = {
        "emails": re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            text
        ),

        "phone_numbers": re.findall(
            r"\b\d{10}\b",
            text
        ),

        "ip_addresses": re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            text
        ),

        "credentials": re.findall(
            r"(?i)(?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*\S+",
            text
        )
    }

    return results


def calculate_risk(results):

    score = 0

    score += len(results["emails"]) * 20
    score += len(results["phone_numbers"]) * 25
    score += len(results["ip_addresses"]) * 15
    score += len(results["credentials"]) * 40

    if score > 100:
        score = 100

    if score == 0:
        level = "Low Risk"
    elif score <= 40:
        level = "Medium Risk"
    elif score <= 70:
        level = "High Risk"
    else:
        level = "Critical Risk"

    return score, level


def get_recommendations(results):

    recommendations = []

    if results["emails"]:
        recommendations.append(
            "Consider removing or masking email addresses before sharing the file."
        )

    if results["phone_numbers"]:
        recommendations.append(
            "Avoid sharing personal phone numbers publicly."
        )

    if results["ip_addresses"]:
        recommendations.append(
            "IP addresses may reveal network information. Consider removing them."
        )

    if results["credentials"]:
        recommendations.append(
            "Critical: Remove passwords, API keys, tokens, or secrets before sharing the file."
        )

    if not recommendations:
        recommendations.append(
            "No major privacy risks were detected. The file looks relatively safe to share."
        )

    return recommendations


def redact_text(text):

    # Hide email addresses
    text = re.sub(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "[EMAIL REDACTED]",
        text
    )

    # Hide phone numbers
    text = re.sub(
        r"\b\d{10}\b",
        "[PHONE REDACTED]",
        text
    )

    # Hide IP addresses
    text = re.sub(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "[IP REDACTED]",
        text
    )

    # Hide passwords, API keys, tokens and secrets
    text = re.sub(
        r"(?i)((?:password|passwd|api[_-]?key|secret|token)\s*[:=]\s*)\S+",
        r"\1[REDACTED]",
        text
    )

    return text

def get_shareability(score):

    if score == 0:
        return "SAFE TO SHARE", "No significant privacy risks were detected."

    elif score <= 40:
        return "SHARE WITH CAUTION", "Some privacy-sensitive information was detected."

    else:
        return "DO NOT SHARE", "This file contains sensitive information that should be removed before sharing."


def get_risk_explanations(results):

    explanations = []

    if results["emails"]:
        explanations.append(
            "📧 Email Address: Exposed email addresses can be used for spam, phishing, and targeted social engineering attacks."
        )

    if results["phone_numbers"]:
        explanations.append(
            "📱 Phone Number: Exposed phone numbers can be misused for spam, phishing, impersonation, or unwanted contact."
        )

    if results["ip_addresses"]:
        explanations.append(
            "🌐 IP Address: An IP address can reveal network-related information and may provide useful information to an attacker."
        )

    if results["credentials"]:
        explanations.append(
            "🔐 Credentials / Secrets: Exposed passwords, API keys, tokens, or secrets can allow unauthorized access to accounts or services."
        )

    if not explanations:
        explanations.append(
            "✅ No significant privacy risks were detected in the scanned file."
        )

    return explanations
def get_risk_severity(results):

    severity = {}

    # Email severity
    if results["emails"]:
        severity["emails"] = "MEDIUM"
    else:
        severity["emails"] = "NONE"

    # Phone severity
    if results["phone_numbers"]:
        severity["phone_numbers"] = "HIGH"
    else:
        severity["phone_numbers"] = "NONE"

    # IP severity
    if results["ip_addresses"]:
        severity["ip_addresses"] = "MEDIUM"
    else:
        severity["ip_addresses"] = "NONE"

    # Credentials severity
    if results["credentials"]:
        severity["credentials"] = "CRITICAL"
    else:
        severity["credentials"] = "NONE"

    return severity