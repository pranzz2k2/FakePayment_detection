# import pandas as pd
# import joblib
# from sklearn.ensemble import RandomForestClassifier

# # Load dataset
# df = pd.read_csv("upi_fraud_data.csv")  # Must contain: utr_id, bank, amount, label

# # Feature engineering
# df['bank_code'] = df['utr_id'].str[:4].astype('category').cat.codes
# X = df[['bank_code', 'amount']]
# y = df['label']

# # Train model
# model = RandomForestClassifier()
# model.fit(X, y)

# # Save model
# joblib.dump(model, "fraud_model.pkl")
# print("✅ Model trained and saved as fraud_model.pkl")


import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import joblib

# Load your UPI transaction dataset
df = pd.read_csv("fake_upi_fraud_dataset.csv")

# Encode categorical variables (sender, receiver, bank)
label_encoders = {}
for col in ['sender_upi', 'receiver_upi', 'bank']:
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col])
    label_encoders[col] = le

# Features and target
X = df[['sender_upi', 'receiver_upi', 'amount', 'bank']]
y = df['fraud']

# Train/Test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save model
joblib.dump(model, "fraud_model.pkl")
print("✅ Model trained and saved as 'fraud_model.pkl'.")

# Save encoders
joblib.dump(label_encoders, "encoders.pkl")
print("✅ Label encoders saved as 'encoders.pkl'.")
