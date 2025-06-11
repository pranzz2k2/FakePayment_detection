import streamlit as st
import joblib
import numpy as np

# ===== Load Pre-trained Model =====
model = joblib.load("models/fraud_detection_model.pkl")  # Update if model path is different

# ===== Custom CSS Styling =====
st.markdown("""
    <style>
    body {
        background-color: #eef2f7;
    }
    .main {
        background-color: #f9fafb;
        padding: 2rem;
        border-radius: 20px;
    }
    h1, h2, h3 {
        text-align: center;
        color: #003366;
        font-family: 'Poppins', sans-serif;
    }
    .stButton>button {
        color: white;
        background-color: #004488;
        padding: 0.75rem 1.5rem;
        border-radius: 10px;
        font-size: 1rem;
    }
    .stTextInput>div>input {
        padding: 0.75rem;
        border-radius: 10px;
    }
    .stSelectbox>div>div {
        padding: 0.75rem;
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)

# ===== Streamlit App =====
st.title("🚨 UPI Transaction Fraud Detection (Real-time)")

st.subheader("📝 Enter Transaction Details:")

with st.form("fraud_form"):
    sender_identity = st.text_input("Sender's Identity")
    sender_upi = st.text_input("Sender's UPI ID")
    sender_phone = st.text_input("Sender's Phone Number")
    transaction_amount = st.number_input("Transaction Amount", min_value=0.0, step=1.0)
    receiver_upi = st.text_input("Receiver's UPI ID")
    transaction_time = st.time_input("Time of Transaction")
    location = st.selectbox("Location", ['Delhi', 'Mumbai', 'Bangalore', 'Hyderabad', 'Chennai', 'Kolkata', 'Other'])
    state = st.selectbox("State", ['Delhi', 'Maharashtra', 'Karnataka', 'Telangana', 'Tamil Nadu', 'West Bengal', 'Other'])

    submit_button = st.form_submit_button("🚀 Predict Fraud Status")

# ===== Prediction Section =====
if submit_button:
    st.subheader("🔎 Prediction Result:")

    # Manual encoding for Location and State (because model expects numeric)
    location_mapping = {'Delhi': 0, 'Mumbai': 1, 'Bangalore': 2, 'Hyderabad': 3, 'Chennai': 4, 'Kolkata': 5, 'Other': 6}
    state_mapping = {'Delhi': 0, 'Maharashtra': 1, 'Karnataka': 2, 'Telangana': 3, 'Tamil Nadu': 4, 'West Bengal': 5, 'Other': 6}

    location_encoded = location_mapping.get(location, 6)
    state_encoded = state_mapping.get(state, 6)

    # Prepare input array [Transaction Amount, Location, State]
    input_data = np.array([[transaction_amount, location_encoded, state_encoded]])

    # Make prediction
    prediction = model.predict(input_data)[0]

    if prediction == 1:
        st.error("🚨 This Transaction is Predicted as **Fraudulent!**")
    else:
        st.success("✅ This Transaction is Predicted as **Legitimate.**")

    # Show Entered Details
    with st.expander("📄 View Entered Transaction Details"):
        st.write(f"**Sender's Identity:** {sender_identity}")
        st.write(f"**Sender's UPI ID:** {sender_upi}")
        st.write(f"**Sender's Phone:** {sender_phone}")
        st.write(f"**Receiver's UPI ID:** {receiver_upi}")
        st.write(f"**Transaction Amount:** ₹{transaction_amount}")
        st.write(f"**Location:** {location}")
        st.write(f"**State:** {state}")
        st.write(f"**Time:** {transaction_time}")

# Footer
st.markdown("---")
st.caption("Built with ❤️ | Real-Time UPI Fraud Detection System")
