#!/usr/bin/env python3
"""
AI Detector Module (precise, XLSX-only) - Linux Compatible
----------------------------------------------------------
Trains a multi-class model from ONLY the provided Excel payload files:

  payloads/sqli.xlsx    -> label 1 (SQLi)
  payloads/xss.xlsx     -> label 2 (XSS)
  payloads/ddos.xlsx    -> label 3 (DDoS)

Each file MUST contain examples in the FIRST column. No default/fallback data
is used. If a file is missing or empty, training will raise a clear error.

Model:
  - TfidfVectorizer (character n-grams, 3–5) with lowercase normalization
  - LinearSVC (strong baseline for short, obfuscated payloads)
  - Optional hyperparameter tuning via GridSearchCV if env AI_DETECTOR_TUNE=1

API:
  - detect_attack(data: str) -> int
        1 = SQLi, 2 = XSS, 3 = DDoS

Operational niceties:
  - Thread-safe lazy loading/training
  - On-disk caching: ai_detector_model.pkl
  - Simple rate-limit: max 100 calls/minute (tunable)
"""

import os
import time
import threading
import joblib
import pandas as pd
from typing import List, Tuple
from functools import wraps

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.model_selection import GridSearchCV
from sklearn.utils.class_weight import compute_class_weight
from sklearn.exceptions import NotFittedError
import numpy as np

# ---------------------------
# Config
# ---------------------------
PAYLOAD_DIR = os.environ.get("AI_PAYLOAD_DIR", "payloads")
FILE_MAP = {
    1: os.path.join(PAYLOAD_DIR, "sqli.xlsx"),
    2: os.path.join(PAYLOAD_DIR, "xss.xlsx"),
    3: os.path.join(PAYLOAD_DIR, "ddos.xlsx"),
}
MODEL_PATH = os.environ.get("AI_MODEL_PATH", "ai_detector_model.pkl")
TUNE = os.environ.get("AI_DETECTOR_TUNE", "0") == "1"

# Rate limits
MAX_CALLS = int(os.environ.get("AI_RATE_MAX_CALLS", "100"))
PERIOD_SEC = int(os.environ.get("AI_RATE_PERIOD", "60"))

# Thread-safety
_model_lock = threading.Lock()
_model = None  # cached classifier pipeline


# ---------------------------
# Rate Limiter Decorator
# ---------------------------
def rate_limited(max_calls: int, period: int):
    def decorator(func):
        calls = []
        lock = threading.Lock()

        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal calls
            now = time.time()
            with lock:
                # keep only calls within window
                calls = [t for t in calls if now - t < period]
                if len(calls) >= max_calls:
                    raise RuntimeError(f"Rate limit exceeded for {func.__name__}")
                calls.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------
# Data Loading (XLSX only) - Linux Compatible
# ---------------------------
def _check_excel_engines():
    """Check which Excel engines are available"""
    engines = {}
    
    try:
        import openpyxl
        engines['openpyxl'] = True
    except ImportError:
        engines['openpyxl'] = False
    
    try:
        import xlrd
        engines['xlrd'] = True
    except ImportError:
        engines['xlrd'] = False
        
    try:
        import calamine
        engines['calamine'] = True
    except ImportError:
        engines['calamine'] = False
    
    return engines


def _read_first_column(xlsx_path: str) -> List[str]:
    if not os.path.exists(xlsx_path):
        raise FileNotFoundError(
            f"Required payload file not found: {xlsx_path}\n"
            f"Expected files: {list(FILE_MAP.values())}"
        )

    # Check available engines
    engines = _check_excel_engines()
    
    # Try engines in order of preference for Linux compatibility
    engines_to_try = []
    if engines.get('openpyxl', False):
        engines_to_try.append('openpyxl')
    if engines.get('calamine', False):
        engines_to_try.append('calamine')
    if engines.get('xlrd', False):
        engines_to_try.append('xlrd')
    
    if not engines_to_try:
        raise RuntimeError(
            f"No Excel engines available. Install one of:\n"
            f"  pip install openpyxl     # Recommended for .xlsx\n"
            f"  pip install xlrd         # For .xls files\n"
            f"  pip install python-calamine  # Alternative engine"
        )

    df = None
    errors = []
    
    for engine in engines_to_try:
        try:
            # Explicitly specify engine and read only first column
            df = pd.read_excel(xlsx_path, engine=engine, usecols=[0])
            break
        except Exception as e:
            errors.append(f"{engine}: {str(e)}")
            continue
    
    if df is None:
        error_msg = f"Failed to read {xlsx_path} with all available engines:\n"
        for error in errors:
            error_msg += f"  - {error}\n"
        raise RuntimeError(error_msg)

    if df.shape[1] < 1:
        raise ValueError(f"{xlsx_path} has no columns. Put examples in the FIRST column.")
    
    series = df.iloc[:, 0].dropna()
    examples = [str(x) for x in series.tolist() if str(x).strip()]
    
    if not examples:
        raise ValueError(f"{xlsx_path} has no non-empty examples in the first column.")
    
    return examples


def _load_dataset() -> Tuple[List[str], List[int]]:
    texts: List[str] = []
    labels: List[int] = []
    for label, path in FILE_MAP.items():
        samples = _read_first_column(path)
        texts.extend(samples)
        labels.extend([label] * len(samples))
    return texts, labels


# ---------------------------
# Training
# ---------------------------
def _make_pipeline() -> Pipeline:
    """
    Char n-grams are robust to obfuscation, spacing, and mixed case.
    """
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        lowercase=True,
        min_df=1,
        max_df=1.0,
        strip_accents=None,
        sublinear_tf=True,
    )
    clf = LinearSVC(random_state=42)  # Add random_state for reproducibility
    return Pipeline([("tfidf", vectorizer), ("clf", clf)])


def _train_model() -> Pipeline:
    texts, labels = _load_dataset()

    # Class weights (balanced) – helpful if classes are imbalanced.
    classes = np.unique(labels)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=labels)
    class_weight = {int(c): float(w) for c, w in zip(classes, weights)}

    base = _make_pipeline()

    if TUNE:
        # Lightweight grid – expand if you have more data/time
        param_grid = {
            "tfidf__ngram_range": [(3, 5), (2, 5), (3, 6)],
            "clf__C": [0.5, 1.0, 2.0],
            "clf__class_weight": [class_weight],  # Include class_weight in tuning
        }
        tuned = GridSearchCV(
            base,
            param_grid=param_grid,
            scoring="f1_macro",
            n_jobs=-1,
            cv=3,
            verbose=0,
        )
        tuned.fit(texts, labels)
        model = tuned.best_estimator_
    else:
        # Attach class_weight to LinearSVC by refitting a new instance
        vectorizer = base.named_steps["tfidf"]
        clf = LinearSVC(C=1.0, class_weight=class_weight, random_state=42)
        model = Pipeline([("tfidf", vectorizer), ("clf", clf)])
        model.fit(texts, labels)

    # Persist
    joblib.dump(
        {
            "model": model,
            "meta": {
                "version": 2,
                "classes": sorted(list(set(labels))),
                "files": FILE_MAP,
                "tuned": TUNE,
                "timestamp": time.time(),
            },
        },
        MODEL_PATH,
    )
    return model


def _load_or_train() -> Pipeline:
    global _model
    with _model_lock:
        if _model is not None:
            return _model

        needs_train = True
        if os.path.exists(MODEL_PATH):
            try:
                payload = joblib.load(MODEL_PATH)
                model = payload.get("model", None)
                meta = payload.get("meta", {})
                # Basic sanity checks
                classes = set(meta.get("classes", []))
                expected = {0, 1, 2, 3}
                if model is not None and classes == expected:
                    _model = model
                    return _model
            except Exception:
                # ignore and retrain
                pass

        if needs_train:
            _model = _train_model()
            return _model


# ---------------------------
# Public API
# ---------------------------
@rate_limited(MAX_CALLS, PERIOD_SEC)
def detect_attack(data: str) -> int:
    """
    Returns:
        1 SQLi, 2 XSS, 3 DDoS
    """
    try:
        model = _load_or_train()
        text = "" if data is None else str(data)
        if not text.strip():
            return 0
        return int(model.predict([text])[0])
    except NotFittedError:
        # Shouldn't happen due to _load_or_train(), but be safe
        _train_model()
        model = _load_or_train()
        return int(model.predict([str(data)])[0])
    except Exception as e:
        # when the detector itself fails.
        # print(f"[ai_detector] detection error: {e}")
        return 0


if __name__ == "__main__":
    # Quick manual smoke test
    print("Detector label map: 1=SQLi, 2=XSS, 3=DDoS")
    print("Loading/training model from XLSX files...")
    
    # Check Excel engines
    engines = _check_excel_engines()
    print("Available Excel engines:")
    for engine, available in engines.items():
        status = "✓" if available else "✗"
        print(f"  {status} {engine}")
    
    # Check if payload files exist
    missing_files = []
    for label, path in FILE_MAP.items():
        if not os.path.exists(path):
            missing_files.append(path)
    
    if missing_files:
        print(f"\nMissing payload files:")
        for f in missing_files:
            print(f"  - {f}")
        print("\nCreate these files first or run the sample creation script.")
        exit(1)
    
    try:
        m = _load_or_train()
        print("Model loaded/trained successfully!")
        
        # Test cases
        test_cases = [
            "Hello", 
            "<script>alert(1)</script>", 
            "SELECT * FROM users", 
            "GET / " * 30
        ]
        
        print("\nTesting detection:")
        labels = { 1: "SQLi", 2: "XSS", 3: "DDoS"}
        for t in test_cases:
            result = detect_attack(t)
            print(f"{repr(t[:60]):65} => {result} ({labels.get(result, 'unknown')})")
            
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
