import joblib
import re
import sys

try:
    file_path = sys.argv[1]
except IndexError:
    print("Usage: python predict.py <path_to_email_file>")
    sys.exit(1)

model = joblib.load("models/phishing_model.pkl")
vectorizer = joblib.load("models/vectorizer.pkl")

subject = input("Enter the email subject: ")

sender = input("Enter the sender's email address: ")

match = re.search(r'<(.+)>', sender)

if match:
    email_address = match.group(1)
else:
    email_address = sender

domain = email_address.split("@")[1]

trusted_domains = [
    "paypal.com", "amazon.com", "microsoft.com",
    "google.com", "apple.com", "chase.com", "bankofamerica.com"
]

domain_trusted = domain.lower() in trusted_domains

print("Enter the email body. Type END on its own line when finished.")

body_lines = []

while True:
    line = input()
    if line.upper() == "END":
        break
    body_lines.append(line)

body = "\n".join(body_lines)

urls = re.findall(r'https?://\S+', body)
url_count = len(urls)

suspicious_words = [
    "verify", "urgent", "suspended", "immediately",
    "click here", "password", "confirm", "account locked",
    "act now", "limited time"
]

combined_lower = (subject + " " + body).lower()

keyword_count = 0
for word in suspicious_words:
    if word in combined_lower:
        keyword_count += 1

email_text = subject + " " + body

email_vector = vectorizer.transform([email_text])

prediction = model.predict(email_vector)

probabilities = model.predict_proba(email_vector)

legitimate_probability = probabilities[0][0]
phishing_probability = probabilities[0][1]

# Step 1: model's starting risk level, based on probability alone
if phishing_probability > 0.70:
    risk_level = "HIGH"
elif phishing_probability > 0.30:
    risk_level = "MEDIUM"
else:
    risk_level = "LOW"

# Step 2: ratchet logic — url/keyword/domain signals can only push risk UP
risk_rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
rank_to_risk = {1: "LOW", 2: "MEDIUM", 3: "HIGH"}

current_rank = risk_rank[risk_level]

if domain_trusted == False:
    current_rank = max(current_rank, risk_rank["HIGH"])

if keyword_count >= 3:
    current_rank = max(current_rank, risk_rank["MEDIUM"])

if url_count > 3:
    current_rank = max(current_rank, risk_rank["MEDIUM"])

risk_level = rank_to_risk[current_rank]

# Step 3: generate display text + recommendation from the FINAL risk_level
if risk_level == "HIGH":
    risk_display = "🔴 HIGH"
    recommendation = "Do NOT click links or open attachments."
elif risk_level == "MEDIUM":
    risk_display = "🟡 MEDIUM"
    recommendation = "Review the email carefully before taking action."
else:
    risk_display = "🟢 LOW"
    recommendation = "Likely legitimate, but continue to use normal caution."

if prediction[0] == 1:
    prediction_label = "⚠️ PHISHING"
    confidence = phishing_probability
else:
    prediction_label = "✅ LEGITIMATE"
    confidence = legitimate_probability

print("=" * 50)
print("PHISHING EMAIL ANALYSIS")
print("=" * 50)

print(f"Subject: {subject}")
print(f"Sender domain: {domain}")
print()
print(f"Prediction: {prediction_label}")
print(f"Confidence: {confidence:.2%}")
print(f"Risk Level: {risk_display}")
print(f"URLs found: {url_count}")
print(f"Suspicious keywords found: {keyword_count}")
print(f"Domain trusted: {'✅ Yes' if domain_trusted else '⚠️ No'}")
print()
print("Recommendation:")
print(recommendation)