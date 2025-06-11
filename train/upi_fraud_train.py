# ====== Import libraries ======
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

# ====== Load Dataset ======
df = pd.read_csv("upi_transaction_data.csv")   # Change to your dataset file

# ====== Data Preprocessing ======
# Encode categorical columns
le_location = LabelEncoder()
le_state = LabelEncoder()

df['Location'] = le_location.fit_transform(df['Location'])
df['State'] = le_state.fit_transform(df['State'])

# ====== Feature Selection ======
# You can add/remove columns based on your model needs
features = ['Transaction Amount', 'Location', 'State']
X = df[features]
y = df['Fraudulent']  # Target column

# ====== Split Dataset ======
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ====== Train Model ======
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# ====== Save Model ======
joblib.dump(model, "fraud_detection_model.pkl")
print("✅ Model trained and saved successfully as 'fraud_detection_model.pkl'.")

# ====== (Optional) Evaluate ======
score = model.score(X_test, y_test)
print(f"✅ Model Accuracy on Test Set: {score*100:.2f}%")
