import sys

from src.detector import analyze_email, load_detector_artifacts
from src.email_parser import parse_eml


def display_analysis(parsed_email: dict[str, str], analysis: dict[str, object]) -> None:
    if analysis["prediction"] == "phishing":
        confidence = analysis["phishing_probability"]
    else:
        confidence = analysis["legitimate_probability"]

    print("=" * 50)
    print("PHISHING EMAIL ANALYSIS")
    print("=" * 50)

    print(f"Subject: {parsed_email['subject']}")
    print(f"Sender: {parsed_email['sender']}")
    print()

    print(f"Prediction: {str(analysis['prediction']).upper()}")
    print(f"Confidence: {float(confidence):.2%}")
    print(f"Starting risk: {analysis['starting_risk_level']}")
    print(f"Final risk: {analysis['risk_level']}")
    print()

    print("Evidence found:")
    print(f"- Matched keywords: {analysis['matched_keywords'] or 'None'}")
    print(f"- URLs: {analysis['urls'] or 'None'}")
    print(
        f"- Sender domain: {analysis['sender_domain'] or 'unavailable'} "
        f"({analysis['sender_domain_status']})"
    )
    print(f"- Triggered risk rules: {analysis['triggered_rules'] or 'None'}")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python -m src.predict <path_to_email.eml>")
        return 1

    file_path = sys.argv[1]

    try:
        parsed_email = parse_eml(file_path)
        model, vectorizer = load_detector_artifacts()
        analysis = analyze_email(parsed_email, model, vectorizer)
    except (ValueError, OSError) as error:
        print(f"Error: {error}")
        return 1

    display_analysis(parsed_email, analysis)
    return 0


if __name__ == "__main__":
    sys.exit(main())