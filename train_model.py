import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os
import logging
from feature_extraction import extract_features

def train_model():
    """
    Train a Random Forest model for phishing detection
    Returns the trained model
    """
    logging.info("Starting model training...")
    
    # Load dataset
    try:
        df = pd.read_csv('dataset/phishing_data.csv')
        logging.info(f"Loaded dataset with {len(df)} samples")
    except Exception as e:
        logging.error(f"Error loading dataset: {e}")
        raise
    
    # Extract features for all URLs
    features_list = []
    valid_labels = []
    
    for idx, row in df.iterrows():
        try:
            url = row['url']
            label = row['label']
            
            # Extract features
            features = extract_features(url)
            features_list.append(features)
            valid_labels.append(label)
            
            if (len(features_list)) % 100 == 0:
                logging.info(f"Processed {len(features_list)} URLs...")
                
        except Exception as e:
            logging.warning(f"Error processing URL at index {idx}: {e}")
            continue
    
    # Convert to numpy arrays
    X = np.array(features_list)
    y = np.array(valid_labels)
    
    logging.info(f"Feature matrix shape: {X.shape}")
    logging.info(f"Labels shape: {y.shape}")
    
    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train Random Forest model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    
    logging.info("Training Random Forest model...")
    model.fit(X_train, y_train)
    
    # Evaluate model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    logging.info(f"Model accuracy: {accuracy:.4f}")
    logging.info("Classification Report:")
    logging.info(classification_report(y_test, y_pred))
    
    # Save the model
    os.makedirs('models', exist_ok=True)
    model_path = 'models/phishing_model.pkl'
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    logging.info(f"Model saved to {model_path}")
    
    return model

if __name__ == "__main__":
    train_model()
