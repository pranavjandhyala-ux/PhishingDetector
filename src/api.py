from fastapi import FastAPI, File, HTTPException, UploadFile

from src.detector import analyze_email, load_detector_artifacts
from src.email_parser import parse_eml_bytes

MAX_EMAIL_SIZE_BYTES = 10 * 1024 * 1024

app = FastAPI(title="Phishing Detector API")

model, vectorizer = load_detector_artifacts()


@app.get("/health")
def health():
    return {"status": "healthy"}

@app.post("/analyze")
async def analyze_uploaded_email(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported.",
        )

    raw_email = await file.read(MAX_EMAIL_SIZE_BYTES + 1)

    if not raw_email:
        raise HTTPException(
            status_code=400,
            detail="The uploaded email file is empty.",
        )

    if len(raw_email) > MAX_EMAIL_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail="The uploaded email exceeds the 10 MB size limit.",
        )

    parsed_email = parse_eml_bytes(raw_email)
    analysis = analyze_email(parsed_email, model, vectorizer)

    return {
        "email": {
            "subject": parsed_email["subject"],
            "sender": parsed_email["sender"],
            "body_source": parsed_email["body_source"],
        },
        "analysis": analysis,
    }