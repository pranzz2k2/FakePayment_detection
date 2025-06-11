import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import time
import re
from datetime import datetime

st.set_page_config(
    page_title="Threat Guard AI Admin Panel",
    page_icon="🔒",
    layout="centered"
)
# Load the dataset
@st.cache_data
def load_data():
    return pd.read_csv('upi_transaction_data.csv')

# UPI domain extraction function
def extract_upi_domain(upi_id):
    if pd.isna(upi_id) or upi_id == '':
        return 'unknown'
    if re.match(r'.*@ok(sbi|hdfc|icici|axis|paytm)', upi_id.lower()):
        return 'legitimate_bank'
    elif re.match(r'.*@(oksbi|okhdfc|okicici|okaxis|okpaytm)', upi_id.lower()):
        return 'legitimate_bank'
    elif re.match(r'^\d+@upi$', upi_id.lower()):
        return 'legitimate_upi'
    elif '@' in upi_id:
        return 'suspicious_domain'
    return 'unknown'

# Phone validation function
def validate_phone(phone):
    phone_str = str(phone)
    if len(phone_str) != 10:
        return 0
    if phone_str.startswith(('6', '7', '8', '9')):
        return 1
    return 0

# Enhanced preprocessing
def preprocess_data(df):
    df['Sender_Domain_Type'] = df["Sender's UPI ID"].apply(extract_upi_domain)
    df['Receiver_Domain_Type'] = df["Receiver's UPI ID"].apply(extract_upi_domain)
    
    domain_mapping = {
        'legitimate_bank': 0,
        'legitimate_upi': 1,
        'suspicious_domain': 2,
        'unknown': 3
    }
    df['Sender_Domain_Encoded'] = df['Sender_Domain_Type'].map(domain_mapping)
    df['Receiver_Domain_Encoded'] = df['Receiver_Domain_Type'].map(domain_mapping)
    
    df['Phone_Valid'] = df["Sender's Phone Number"].apply(validate_phone)
    
    if 'Time of Transaction' in df.columns:
        df['Transaction_Date'] = pd.to_datetime(df['Time of Transaction'])
        df['Transaction_Day'] = df['Transaction_Date'].dt.day
        df['Transaction_Hour'] = df['Transaction_Date'].dt.hour
        df['Is_Night'] = ((df['Transaction_Hour'] >= 22) | (df['Transaction_Hour'] <= 6)).astype(int)
    
    df['Location_Encoded'] = df['Location'].apply(lambda x: locations.index(x) if x in locations else -1)
    df['State_Encoded'] = df['State'].apply(lambda x: states.index(x) if x in states else -1)
    
    df['Amount_Bin'] = pd.cut(df['Transaction Amount'], 
                             bins=[0, 1000, 10000, 50000, 100000, 1000000],
                             labels=[0, 1, 2, 3, 4])
    
    return df

# Train the model
def train_model(df):
    features = ['Transaction Amount', 'Sender_Domain_Encoded', 'Receiver_Domain_Encoded',
                'Location_Encoded', 'State_Encoded', 'Phone_Valid', 'Amount_Bin']
    if 'Is_Night' in df.columns:
        features.append('Is_Night')
    
    X = df[features]
    y = df['Fraudulent']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    model = RandomForestClassifier(n_estimators=200, 
                                  class_weight='balanced',
                                  max_depth=10,
                                  random_state=42)
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred)
    class_report = classification_report(y_test, y_pred, output_dict=True)
    
    return model, accuracy, conf_matrix, class_report, X_test, y_test

# Admin Dashboard
def admin_dashboard():
    st.title("🛡️ Admin Dashboard - UPI Fraud Detection System")
    st.write("Comprehensive administration tools for managing the fraud detection system")
    
    # Load data
    df = load_data()
    df_processed = preprocess_data(df)
    
    # Admin tabs
    tab1, tab2, tab3 = st.tabs([
        "📊 Dashboard", 
        "🤖 Model Management", 
        "🔍 Fraud Analysis"
    ])
    
    with tab1:
        st.header("System Overview")
        
        # Key metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Transactions", len(df))
        col2.metric("Fraudulent Transactions", df['Fraudulent'].sum())
        col3.metric("Fraud Rate", f"{df['Fraudulent'].mean()*100:.2f}%")
        
        # Fraud trend
        st.subheader("Fraud Trend Over Time")
        if 'Transaction_Date' in df_processed.columns:
            fraud_trend = df_processed.groupby(df_processed['Transaction_Date'].dt.date)['Fraudulent'].mean()
            fig, ax = plt.subplots()
            fraud_trend.plot(ax=ax, color='red', marker='o')
            ax.set_title('Daily Fraud Rate')
            ax.set_ylabel('Fraud Rate')
            st.pyplot(fig)
        
        # Top fraudulent locations
        st.subheader("Top Fraudulent Locations")
        fraud_by_loc = df_processed.groupby('Location')['Fraudulent'].mean().sort_values(ascending=False).head(10)
        st.bar_chart(fraud_by_loc)
    
    with tab2:
        st.header("Model Management")
        
        # Model training section
        if st.button("🔄 Train New Model"):
            with st.spinner("Training model with latest data..."):
                model, accuracy, conf_matrix, class_report, X_test, y_test = train_model(df_processed)
                joblib.dump(model, 'enhanced_upi_fraud_model.pkl')
                st.success("Model trained and saved successfully!")
                
                # Performance metrics
                st.subheader("Model Performance")
                col1, col2 = st.columns(2)
                col1.metric("Accuracy", f"{accuracy:.4f}")
                col2.metric("Fraud Recall", f"{class_report['1']['recall']:.4f}")
                
                # Confusion matrix
                st.write("Confusion Matrix:")
                fig, ax = plt.subplots()
                sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues', 
                           xticklabels=['Legitimate', 'Fraudulent'],
                           yticklabels=['Legitimate', 'Fraudulent'], ax=ax)
                st.pyplot(fig)
                
                # Feature importance
                st.subheader("Feature Importance")
                feat_importances = pd.Series(model.feature_importances_, index=X_test.columns)
                st.bar_chart(feat_importances.sort_values(ascending=False))
        
        # Current model info
        try:
            model = joblib.load('enhanced_upi_fraud_model.pkl')
            st.subheader("Current Model Information")
            st.write(f"Model type: {type(model).__name__}")
            st.write(f"Number of estimators: {model.n_estimators}")
            st.write(f"Max depth: {model.max_depth}")
        except:
            st.warning("No trained model found. Please train a model first.")
    
    with tab3:
        st.header("Fraud Analysis Tools")
        
        # Filter options
        st.sidebar.subheader("Filter Options")
        min_amount = st.sidebar.number_input("Minimum Amount", 0, 1000000, 0)
        max_amount = st.sidebar.number_input("Maximum Amount", 0, 1000000, 100000)
        selected_locations = st.sidebar.multiselect("Locations", locations)
        fraud_status = st.sidebar.radio("Fraud Status", ["All", "Legitimate Only", "Fraudulent Only"])
        
        # Apply filters
        filtered = df_processed[
            (df_processed['Transaction Amount'] >= min_amount) & 
            (df_processed['Transaction Amount'] <= max_amount)
        ]
        if selected_locations:
            filtered = filtered[filtered['Location'].isin(selected_locations)]
        if fraud_status == "Legitimate Only":
            filtered = filtered[filtered['Fraudulent'] == 0]
        elif fraud_status == "Fraudulent Only":
            filtered = filtered[filtered['Fraudulent'] == 1]
        
        # Display filtered data
        st.subheader(f"Filtered Transactions ({len(filtered)})")
        st.dataframe(filtered.head(100))
        
        # Analysis options
        analysis_type = st.selectbox(
            "Analysis Type",
            ["Amount Distribution", "Time Patterns", "Domain Analysis", "Geographical"]
        )
        
        if analysis_type == "Amount Distribution":
            st.subheader("Transaction Amount Analysis")
            fig, ax = plt.subplots(1, 2, figsize=(15, 5))
            
            sns.histplot(filtered['Transaction Amount'], bins=50, ax=ax[0])
            ax[0].set_title('Amount Distribution')
            
            sns.boxplot(x='Fraudulent', y='Transaction Amount', data=filtered, ax=ax[1])
            ax[1].set_title('Amount by Fraud Status')
            
            st.pyplot(fig)
        
        elif analysis_type == "Time Patterns" and 'Transaction_Date' in filtered.columns:
            st.subheader("Time Patterns")
            filtered['Hour'] = filtered['Transaction_Date'].dt.hour
            fraud_by_hour = filtered.groupby('Hour')['Fraudulent'].mean()
            
            fig, ax = plt.subplots()
            fraud_by_hour.plot(kind='bar', ax=ax)
            ax.set_title('Fraud Rate by Hour of Day')
            st.pyplot(fig)
        
        elif analysis_type == "Domain Analysis":
            st.subheader("UPI Domain Analysis")
            fig, ax = plt.subplots(1, 2, figsize=(15, 5))
            
            sns.countplot(x='Sender_Domain_Type', hue='Fraudulent', data=filtered, ax=ax[0])
            ax[0].set_title('Sender Domains')
            ax[0].tick_params(axis='x', rotation=45)
            
            sns.countplot(x='Receiver_Domain_Type', hue='Fraudulent', data=filtered, ax=ax[1])
            ax[1].set_title('Receiver Domains')
            ax[1].tick_params(axis='x', rotation=45)
            
            st.pyplot(fig)
        
        elif analysis_type == "Geographical":
            st.subheader("Geographical Distribution")
            fig, ax = plt.subplots(figsize=(10, 6))
            
            fraud_by_state = filtered.groupby('State')['Fraudulent'].mean().sort_values(ascending=False)
            fraud_by_state.plot(kind='bar', ax=ax)
            ax.set_title('Fraud Rate by State')
            
            st.pyplot(fig)
# Main function
def main():
    # Define locations and states at module level
    global locations, states
    locations = ['Mumbai', 'Delhi', 'Kolkata', 'Bangalore', 'Chennai', 'Hyderabad', 
                 'Pune', 'Jaipur', 'Lucknow', 'Ahmedabad']
    states = ['Maharashtra', 'Delhi', 'West Bengal', 'Karnataka', 'Tamil Nadu', 
              'Telangana', 'Uttar Pradesh', 'Gujarat', 'Rajasthan', 'Punjab']
    
    # In a real app, you would check user role here
    # For demo, we'll just show the admin dashboard
    admin_dashboard()

if __name__ == "__main__":
    main()