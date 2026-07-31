import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# -----------------------------
# Load the datasets
# -----------------------------

train_emails = pd.read_parquet("data/train.parquet")
test_emails = pd.read_parquet("data/test.parquet")

# -----------------------------
# Keep only the columns we need
# -----------------------------

train_emails = train_emails[["subject", "text", "label"]]
test_emails = test_emails[["subject", "text", "label"]]

# -----------------------------
# Remove missing values
# -----------------------------

train_emails = train_emails.dropna()
test_emails = test_emails.dropna()

# -----------------------------
# Separate features and labels
# -----------------------------

X_train = train_emails[["subject", "text"]]
y_train = train_emails["label"]

X_test = test_emails[["subject", "text"]]
y_test = test_emails["label"]

# -----------------------------
# Combine subject and body
# -----------------------------

X_train_text = X_train["subject"] + " " + X_train["text"]
X_test_text = X_test["subject"] + " " + X_test["text"]

# -----------------------------
# Vectorize the text
# -----------------------------

vectorizer = TfidfVectorizer()

X_train_vectors = vectorizer.fit_transform(X_train_text)
X_test_vectors = vectorizer.transform(X_test_text)

# -----------------------------
# Train the model
# -----------------------------

model = LogisticRegression(max_iter=1000)

model.fit(X_train_vectors, y_train)

# -----------------------------
# Make predictions
# -----------------------------

predictions = model.predict(X_test_vectors)

# -----------------------------
# Evaluate the model
# -----------------------------

accuracy = accuracy_score(y_test, predictions)

print(f"Accuracy: {accuracy:.4f}")

print()

print(confusion_matrix(y_test, predictions))

#-----------------------------
# Print classification report
# -----------------------------

print()

print(classification_report(y_test, predictions))

# -----------------------------
# Save the trained model
# -----------------------------

joblib.dump(model, "models/phishing_model.pkl")
joblib.dump(vectorizer, "models/vectorizer.pkl")

print()

print("Model and vectorizer saved successfully!")