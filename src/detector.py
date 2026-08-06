from email.utils import parseaddr
from pathlib import Path
import re

import joblib


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = PROJECT_ROOT / "models"

URL_PATTERN = re.compile(r"https?://\S+")

SUSPICIOUS_KEYWORDS = (
    "verify",
    "urgent",
    "suspended",
    "immediately",
    "click here",
    "password",
    "confirm",
    "account locked",
    "act now",
    "limited time",
)

ALLOWLISTED_DOMAINS = {
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "google.com",
    "apple.com",
    "chase.com",
    "bankofamerica.com",
}

RISK_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}

RANK_TO_RISK = {
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
}


def load_detector_artifacts():
    model = joblib.load(MODELS_DIR / "phishing_model.pkl")
    vectorizer = joblib.load(MODELS_DIR / "vectorizer.pkl")

    return model, vectorizer


def extract_urls(body: str) -> list[str]:
    return URL_PATTERN.findall(body)


def find_suspicious_keywords(subject: str, body: str) -> list[str]:
    email_text = f"{subject} {body}".lower()

    return [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in email_text
    ]


def extract_sender_domain(sender: str) -> str | None:
    _, email_address = parseaddr(sender)

    if not email_address or "@" not in email_address:
        return None

    local_part, domain = email_address.rsplit("@", 1)

    if not local_part or not domain:
        return None

    return domain.lower()


def analyze_sender_domain(sender: str) -> dict[str, str | None]:
    domain = extract_sender_domain(sender)

    if domain is None:
        return {
            "domain": None,
            "domain_status": "invalid",
        }

    if domain in ALLOWLISTED_DOMAINS:
        status = "allowlisted"
    else:
        status = "unknown"

    return {
        "domain": domain,
        "domain_status": status,
    }


def risk_from_probability(phishing_probability: float) -> str:
    if phishing_probability >= 0.70:
        return "HIGH"

    if phishing_probability >= 0.30:
        return "MEDIUM"

    return "LOW"

def determine_risk_level(
    phishing_probability: float,
    matched_keywords: list[str],
    urls: list[str],
    sender_domain_status: str | None,
) -> dict[str, object]:
    starting_risk_level = risk_from_probability(phishing_probability)
    current_rank = RISK_RANK[starting_risk_level]
    triggered_rules = []

    if len(matched_keywords) >= 3:
        current_rank = max(current_rank, RISK_RANK["MEDIUM"])
        triggered_rules.append("multiple_suspicious_keywords")

    if len(urls) > 3:
        current_rank = max(current_rank, RISK_RANK["MEDIUM"])
        triggered_rules.append("many_urls")

    if sender_domain_status == "invalid":
        current_rank = max(current_rank, RISK_RANK["MEDIUM"])
        triggered_rules.append("invalid_sender_address")

    return {
        "starting_risk_level": starting_risk_level,
        "risk_level": RANK_TO_RISK[current_rank],
        "triggered_rules": triggered_rules,
    }


def analyze_email(parsed_email: dict[str, str], model, vectorizer) -> dict[str, object]:
    subject = parsed_email["subject"]
    sender = parsed_email["sender"]
    body = parsed_email["body"]

    urls = extract_urls(body)
    matched_keywords = find_suspicious_keywords(subject, body)
    sender_domain_info = analyze_sender_domain(sender)

    email_text = f"{subject} {body}"
    email_vector = vectorizer.transform([email_text])

    prediction = model.predict(email_vector)[0]
    probabilities = model.predict_proba(email_vector)[0]
    phishing_probability = float(probabilities[1])
    legitimate_probability = float(probabilities[0])

    risk_info = determine_risk_level(
        phishing_probability,
        matched_keywords,
        urls,
        sender_domain_info["domain_status"],
    )

    return {
        "prediction": "phishing" if prediction == 1 else "legitimate",
        "phishing_probability": phishing_probability,
        "legitimate_probability": legitimate_probability,
        "starting_risk_level": risk_info["starting_risk_level"],
        "risk_level": risk_info["risk_level"],
        "triggered_rules": risk_info["triggered_rules"],
        "urls": urls,
        "matched_keywords": matched_keywords,
        "sender_domain": sender_domain_info["domain"],
        "sender_domain_status": sender_domain_info["domain_status"],
    }