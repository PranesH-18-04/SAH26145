import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
import sys

sys.path.append(os.path.dirname(__file__))
from preprocess_cicids import get_training_data

def get_mapped_data():
    """
    Loads preprocessed CICIDS2018 data with unidirectional features.
    Maps labels to: 0 (Safe), 1 (DDoS), 2 (Data Exfiltration), 3 (Unauthorized Tunneling)
    """
    df = get_training_data()
    
    label_map = {
        'Safe': 0,
        'DDoS': 1,
        'Data Exfiltration': 2,
        'Unauthorized Tunneling': 3
    }
    
    y = df['Label'].map(label_map).values
    X = df.drop(columns=['Label'])
    
    return X, y

def train_and_save():
    print("Loading and preprocessing dataset...")
    X, y = get_mapped_data()
    
    # Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training RandomForestClassifier...")
    rf_clf = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    rf_clf.fit(X_train, y_train)
    
    print("Training IsolationForest (Unsupervised)...")
    iso_forest = IsolationForest(contamination=0.1, random_state=42)
    # Fit only on safe data for better anomaly detection baseline
    X_safe = X_train[y_train == 0]
    iso_forest.fit(X_safe)
    
    # Save models
    models_dir = os.path.join(os.path.dirname(__file__), '../models/trained')
    os.makedirs(models_dir, exist_ok=True)
    
    rf_path = os.path.join(models_dir, 'rf_classifier.pkl')
    iso_path = os.path.join(models_dir, 'isolation_forest.pkl')
    
    joblib.dump(rf_clf, rf_path)
    joblib.dump(iso_forest, iso_path)
    print(f"Models saved to {models_dir}")
    
    # Save test set for evaluate_model.py
    test_data_path = os.path.join(models_dir, 'test_data.pkl')
    joblib.dump({'X_test': X_test, 'y_test': y_test}, test_data_path)
    print("Test split saved for evaluation.")
    
    # Display Feature Importances
    importances = rf_clf.feature_importances_
    features = X.columns
    print("\n--- Feature Importances ---")
    for f, imp in sorted(zip(features, importances), key=lambda x: x[1], reverse=True):
        print(f"{f}: {imp:.4f}")

if __name__ == "__main__":
    train_and_save()
