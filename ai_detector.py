#!/usr/bin/env python
"""
AI Detector Module for Firewall
--------------------------------
This module reads injection data from separate Excel files and trains a multi-class 
RandomForestClassifier to classify requests as:
    0: Benign
    1: SQL Injection
    2: XSS
    3: DDoS (simulated via repeated GET content)
It provides a function `detect_attack(data)` which returns the predicted label.
A rate limiter is applied so that no more than 100 calls are allowed per minute.

Expected Excel Files:
    - benign.xlsx
    - sql_injection.xlsx
    - xss.xlsx
    - ddos.xlsx
Each file should have examples in the first column.
"""

import os
import time
import threading
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

# ---------------------------
# Rate Limiting Decorator
# ---------------------------
def rate_limited(max_calls, period):
    """
    Decorator that limits the number of calls to a function.
    
    Args:
        max_calls (int): Maximum number of calls allowed in the given period.
        period (int): Period (in seconds) during which the calls are counted.
    
    Raises:
        Exception: If the rate limit is exceeded.
    """
    def decorator(func):
        lock = threading.Lock()
        call_times = []
        def wrapper(*args, **kwargs):
            nonlocal call_times
            with lock:
                now = time.time()
                # Keep only calls within the period
                call_times[:] = [t for t in call_times if now - t < period]
                if len(call_times) >= max_calls:
                    raise Exception("Rate limit exceeded for function: {}".format(func.__name__))
                call_times.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator

# ---------------------------
# Feature Extraction
# ---------------------------
def extract_features(data):
    """
    Extract features from the request data.
    
    Features used:
        - Total length of the data.
        - Count of '<' characters.
        - Count of the substring "SELECT".
        - Count of '/' characters.
        - Count of "GET" occurrences.
    """
    return [
        len(data),
        data.count("<"),
        data.count("SELECT"),
        data.count("/"),
        data.count("GET")
    ]

# ---------------------------
# Helper: Load Examples from Excel
# ---------------------------
def load_examples_from_excel(filename, default_examples):
    """
    Load examples from the first column of an Excel file.
    If the file cannot be read, returns the default_examples list.
    """
    try:
        df = pd.read_excel(filename)
        examples = df.iloc[:, 0].dropna().tolist()
        print(f"Loaded {len(examples)} examples from {filename}")
        return examples
    except Exception as e:
        print(f"Error reading {filename}: {e}. Using default examples.")
        return default_examples

# ---------------------------
# Model Training
# ---------------------------
def train_detector():
    texts = []
    labels = []
    
    # Benign examples (label 0)
    default_benign = [
         "Hello world",
         "GET /index.html HTTP/1.1",
         "User login attempt",
         "Normal data request",
         "GET /api/data HTTP/1.1",
         "POST /submit HTTP/1.1",
         "Welcome to our site",
         "This is a regular request",
         "Fetching user profile",
         "Updating user settings"
    ]
    
    # SQL Injection examples (label 1)
    default_sqli = [
         "SELECT * FROM users",
         "DROP TABLE students; --",
         "UNION SELECT password FROM admin",
         "INSERT INTO users VALUES ('malicious')",
         "SELECT name, password FROM accounts WHERE username='admin' --",
         "SELECT * FROM orders WHERE id=1; DROP TABLE orders;"
    ]
    sqli_examples = load_examples_from_excel("sql_injection.xlsx", default_sqli)
    for text in sqli_examples:
        texts.append(text)
        labels.append(1)
    
    # XSS examples (label 2)
    default_xss = [
         "<script>alert('XSS')</script>",
         "<img src=x onerror=alert('XSS')>",
         "<svg onload=alert('XSS')>",
         "<body onload=alert('XSS')>",
         "<iframe src='javascript:alert(\"XSS\")'></iframe>",
         "<div onclick=alert('XSS')>Click me!</div>"
    ]
    xss_examples = load_examples_from_excel("xss.xlsx", default_xss)
    for text in xss_examples:
        texts.append(text)
        labels.append(2)
    
    # DDoS examples (simulated via repeated GET requests; label 3)
    default_ddos = [
         "GET / " * 50,
         "GET /api/data " * 40,
         "GET /index.html " * 60,
         "GET /home " * 55,
         "GET /login " * 45
    ]
    ddos_examples = load_examples_from_excel("ddos.xlsx", default_ddos)
    for text in ddos_examples:
        texts.append(text)
        labels.append(3)
    
    features = [extract_features(text) for text in texts]
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(features, labels)
    joblib.dump(clf, 'ai_detector_model.pkl')
    print("AI Detector model trained and saved as 'ai_detector_model.pkl'")
    return clf

def load_detector():
    if os.path.exists('ai_detector_model.pkl'):
        clf = joblib.load('ai_detector_model.pkl')
        print("Loaded existing AI Detector model.")
    else:
        clf = train_detector()
    return clf

# ---------------------------
# Attack Detection with Rate Limit
# ---------------------------
@rate_limited(max_calls=100, period=60)  # Allow up to 100 calls per minute
def detect_attack(data):
    """
    Detect the type of attack in the given request data.
    
    Returns:
        0 if benign,
        1 if SQL Injection,
        2 if XSS,
        3 if simulated DDoS.
    """
    clf = load_detector()
    features = extract_features(data)
    prediction = clf.predict([features])[0]
    return prediction

if __name__ == "__main__":
    # When running this module directly, (re)train the model.
    train_detector()
