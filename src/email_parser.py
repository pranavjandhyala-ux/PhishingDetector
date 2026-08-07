from pathlib import Path
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

def parse_email_bytes(raw_email: bytes):
    return BytesParser(policy=policy.default).parsebytes(raw_email)

def load_email_message(file_path: str | Path):
    path = Path(file_path)

    if path.suffix.lower() != ".eml":
        raise ValueError("Only .eml files are supported.")

    try:
        with path.open("rb") as email_file:
            raw_email = email_file.read()
    except FileNotFoundError as error:
        raise FileNotFoundError(f"Email file not found: {path}") from error
    except PermissionError as error:
        raise PermissionError(
            f"Permission denied reading email file: {path}"
        ) from error

    return parse_email_bytes(raw_email)

def extract_headers(message) -> dict[str, str]:
    return {
        "subject": message.get("Subject", ""),
        "sender": message.get("From", ""),
    }

def extract_body_parts(message) -> dict[str, str]:
    plain_text = ""
    html_text = ""

    for part in message.walk():
        if part.is_multipart():
            continue

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type == "text/plain" and not plain_text:
            plain_text = part.get_content()
        elif content_type == "text/html" and not html_text:
            html_text = part.get_content()

    return {
        "plain_text": plain_text,
        "html_text": html_text,
    }
    
def html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")

    for element in soup(["script", "style"]):
        element.decompose()

    return soup.get_text(separator=" ", strip=True)

def select_email_body(body_parts: dict[str, str]) -> dict[str, str]:
    plain_text = body_parts["plain_text"].strip()

    if plain_text:
        return {
            "body": plain_text,
            "body_source": "plain",
        }

    html_text = body_parts["html_text"]

    if html_text:
        readable_html = html_to_text(html_text)

        if readable_html:
            return {
                "body": readable_html,
                "body_source": "html",
            }

    return {
        "body": "",
        "body_source": "none",
    }
    
def build_parsed_email(message) -> dict[str, str]:
    headers = extract_headers(message)
    body_parts = extract_body_parts(message)
    body_info = select_email_body(body_parts)

    return {
        "subject": headers["subject"],
        "sender": headers["sender"],
        "body": body_info["body"],
        "body_source": body_info["body_source"],
    }


def parse_eml(file_path: str | Path) -> dict[str, str]:
    message = load_email_message(file_path)
    return build_parsed_email(message)


def parse_eml_bytes(raw_email: bytes) -> dict[str, str]:
    message = parse_email_bytes(raw_email)
    return build_parsed_email(message)