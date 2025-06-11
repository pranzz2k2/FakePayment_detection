import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import joblib

# Load your dataset
def load_data(filepath):
    df = pd.read_csv(filepath)
    
    # Display dataset info
    print("Dataset Info:")
    print(df.info())
    print("\nFirst 5 rows:")
    print(df.head())
    
    return df

# Preprocess data
def preprocess_data(df):
    # Drop unnecessary columns
    df = df.drop(columns=['Unnamed: 0'], errors='ignore')
    
    # Convert categorical target to numerical if needed
    if 'type' in df.columns and 'type_code' not in df.columns:
        type_mapping = {'benign': 0, 'defacement': 1, 'phishing': 2, 'malware': 3}
        df['type_code'] = df['type'].map(type_mapping)
    
    # Separate features and target
    X = df.drop(columns=['url', 'type', 'type_code'])
    y = df['type_code']
    
    return X, y

# Train model
def train_model(X, y):
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # Initialize and train model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        random_state=42,
        class_weight='balanced'
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    print("\nModel Evaluation:")
    print(classification_report(y_test, y_pred))
    print(f"Accuracy: {accuracy_score(y_test, y_pred):.4f}")
    
    return model

# Save model
def save_model(model, filename):
    # Save as pickle file
    with open(filename, 'wb') as f:
        pickle.dump(model, f)
    
    # Also save as joblib (often better for sklearn models)
    joblib.dump(model, filename.replace('.pkl', '.joblib'))
    
    print(f"\nModel saved as {filename} and .joblib")

# Main execution
if __name__ == "__main__":
    # Configuration
    DATA_PATH = "train.csv"  # Update with your file path
    MODEL_PATH = "models/phishing_detector.pkl"
    
    # Load data
    print("Loading data...")
    df = load_data(DATA_PATH)
    
    # Preprocess
    print("\nPreprocessing data...")
    X, y = preprocess_data(df)
    
    # Train
    print("\nTraining model...")
    model = train_model(X, y)
    
    # Save
    print("\nSaving model...")
    save_model(model, MODEL_PATH)
    
    print("\nTraining complete!")