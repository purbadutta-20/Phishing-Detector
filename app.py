import os
import logging
import pickle
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash
from feature_extraction import extract_features, get_deep_analysis
from train_model import train_model

# Configure logging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "your-secret-key-here")

# Global variable to store the trained model
model = None

def load_or_train_model():
    """Load existing model or train a new one if not available"""
    global model
    model_path = 'models/phishing_model.pkl'
    
    try:
        # Try to load existing model
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            logging.info("Model loaded successfully")
        else:
            # Train new model if not exists
            logging.info("Training new model...")
            model = train_model()
            logging.info("Model trained successfully")
    except Exception as e:
        logging.error(f"Error loading/training model: {e}")
        # Train new model as fallback
        model = train_model()

@app.route('/')
def index():
    """Main page with URL input form"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze the submitted URL for phishing detection"""
    url = request.form.get('url', '').strip()
    
    if not url:
        flash('Please enter a URL to analyze', 'error')
        return redirect(url_for('index'))
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        # Ensure model is loaded
        if model is None:
            load_or_train_model()
        
        # Extract features from the URL
        features = extract_features(url)
        
        # Make prediction
        prediction = model.predict([features])[0]
        probability = model.predict_proba([features])[0]
        deep_info = get_deep_analysis(url)
        # Determine risk level and message
        phishing_prob = probability[1]  # Probability of being phishing
        
        
        if phishing_prob < 0.3:
            risk_level = "Low Risk"
            risk_color = "success"
            message = "This URL appears to be legitimate."
        elif phishing_prob < 0.7:
            risk_level = "Medium Risk"
            risk_color = "warning"
            message = "This URL shows some suspicious characteristics. Exercise caution."
        else:
            risk_level = "High Risk"
            risk_color = "danger"
            message = "This URL appears to be a phishing attempt. Do not proceed!"
        
        result = {
            'url': url,
            'prediction': 'Phishing' if prediction == 1 else 'Legitimate',
            'phishing_probability': round(phishing_prob * 100, 2),
            'legitimate_probability': round(probability[0] * 100, 2),
            'risk_level': risk_level,
            'risk_color': risk_color,
            'message': message,
            'features': features,
            'deep_info' : deep_info
        }
        
        return render_template('result.html', result=result)
        
    except Exception as e:
        logging.error(f"Error analyzing URL: {e}")
        flash(f'Error analyzing URL: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/retrain', methods=['POST'])
def retrain():
    """Retrain the model with updated data"""
    try:
        global model
        model = train_model()
        flash('Model retrained successfully!', 'success')
    except Exception as e:
        logging.error(f"Error retraining model: {e}")
        flash(f'Error retraining model: {str(e)}', 'error')
    
    return redirect(url_for('index.html'))

if __name__ == '__main__':
    # Load or train model on startup
    load_or_train_model()
    
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
