import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
import joblib
import re

# Load your dataset
df = pd.read_csv('upi_transaction_data.csv')

# Select only the required columns
df = df[["Sender's Identity", "Sender's UPI ID", "Sender's Phone Number", 
         "Receiver's UPI ID", "Fraudulent"]]

# Feature engineering functions
def extract_email_domain(upi_id):
    if pd.isna(upi_id):
        return 'missing'
    if '@' in upi_id:
        return upi_id.split('@')[-1].split('.')[0]
    if 'ok' in upi_id.lower():
        return upi_id.lower().split('ok')[-1]
    return 'other'

def clean_phone_number(phone):
    if pd.isna(phone):
        return 'missing'
    # Remove all non-digit characters
    cleaned = re.sub(r'\D', '', str(phone))
    # Take last 4 digits
    return cleaned[-4:] if len(cleaned) >= 4 else cleaned

# Apply feature engineering
df['sender_domain'] = df["Sender's UPI ID"].apply(extract_email_domain)
df['receiver_domain'] = df["Receiver's UPI ID"].apply(extract_email_domain)
df['phone_last4'] = df["Sender's Phone Number"].apply(clean_phone_number)

# Features and target
X = df[["Sender's Identity", "sender_domain", "receiver_domain", "phone_last4"]]
y = df['Fraudulent']

# Preprocessing pipeline
preprocessor = ColumnTransformer(
    transformers=[
        ('identity', OneHotEncoder(handle_unknown='ignore'), ["Sender's Identity"]),
        ('sender_domain', OneHotEncoder(handle_unknown='ignore'), ['sender_domain']),
        ('receiver_domain', OneHotEncoder(handle_unknown='ignore'), ['receiver_domain']),
        ('phone', OneHotEncoder(handle_unknown='ignore'), ['phone_last4'])
    ])

# Create pipeline
pipeline = Pipeline([
    ('preprocessor', preprocessor),
    ('classifier', RandomForestClassifier(random_state=42))
])

# Train the model
pipeline.fit(X, y)

# Save the model
joblib.dump(pipeline, 'fraud_detection_27_model.pkl')

print("Model trained and saved as fraud_detection_model.pkl")