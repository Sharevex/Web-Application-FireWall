#!/usr/bin/env python3
"""
AI Detector Module (robust, XLSX‑based)
--------------------------------------

This module trains a text classifier to detect malicious payloads such as SQL injection (SQLi),
cross‑site scripting (XSS), and distributed denial‑of‑service patterns (DDoS). It loads examples
from a set of Excel files (one per class) and trains a character n‑gram model using a linear
support vector machine (LinearSVC). The resulting model is cached on disk to avoid retraining on
every run. The module exposes a single function `detect_attack(data: str) -> int` which returns
an integer code corresponding to the detected class:

    0 = benign
    1 = SQLi
    2 = XSS
    3 = DDoS

Key features:

* Uses character n‑gram TF‑IDF features (3–5 grams) with lowercase normalisation. This makes the
  model resilient to obfuscation and spacing variations.
* Supports optional hyperparameter tuning via GridSearchCV when the environment variable
  `AI_DETECTOR_TUNE` is set to "1". This can improve accuracy at the cost of training time.
* Ensures thread‑safe model loading and training. Multiple concurrent calls to `detect_attack`
  will not race.
* Employs on‑disk caching using joblib. If a valid model cache exists and its metadata matches
  the expected classes, training is skipped.
* Enforces a simple rate limit on calls to `detect_attack` to prevent resource abuse.

Environment variables:

* `AI_PAYLOAD_DIR`: Directory containing payload XLSX files. Defaults to `<script_dir>/payloads`.
* `AI_MODEL_PATH`: Path to save/load the trained model. Defaults to `<script_dir>/ai_detector_model.pkl`.
* `AI_DETECTOR_TUNE`: Set to "1" to enable hyperparameter tuning. Default: "0".
* `AI_RATE_MAX_CALLS`: Maximum allowed calls per rate period. Default: 100.
* `AI_RATE_PERIOD`: Rate limiting period in seconds. Default: 60.

The module will raise clear errors if required XLSX files are missing or empty, or if the optional
dependency `openpyxl` is not installed. To install the dependency, run:

    pip install openpyxl

"""

from __future__ import annotations

import os
import time
import threading
import joblib
import pandas as pd
from typing import List, Tuple, Dict, Optional
from functools import wraps
from pathlib import Path
import importlib.util

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.model_selection import GridSearchCV
from sklearn.utils.class_weight import compute_class_weight
from sklearn.exceptions import NotFittedError
import numpy as np

# ---------------------------
# Configuration
# ---------------------------

# Determine the directory of this script to resolve relative paths
HERE = Path(__file__).resolve().parent

# Directory containing the payload XLSX files. Defaults to `<script_dir>/payloads`.
PAYLOAD_DIR = Path(os.environ.get("AI_PAYLOAD_DIR", HERE / "payloads")).resolve()

# Map of class label to payload file path. The paths are resolved relative to
# PAYLOAD_DIR and converted to strings for compatibility with joblib.
FILE_MAP: Dict[int, str] = {
    0: str(PAYLOAD_DIR / "benign.xlsx"),
    1: str(PAYLOAD_DIR / "sqli.xlsx"),
    2: str(PAYLOAD_DIR / "xss.xlsx"),
    3: str(PAYLOAD_DIR / "ddos.xlsx"),
}

# Path to save the trained model. Defaults to `<script_dir>/ai_detector_model.pkl`.
MODEL_PATH = str(Path(os.environ.get("AI_MODEL_PATH", HERE / "ai_detector_model.pkl")).resolve())

# Enable hyperparameter tuning if set to "1". Default is off for speed.
TUNE = os.environ.get("AI_DETECTOR_TUNE", "0") == "1"

# Rate limiting configuration
MAX_CALLS = int(os.environ.get("AI_RATE_MAX_CALLS", "100"))
PERIOD_SEC = int(os.environ.get("AI_RATE_PERIOD", "60"))

# Thread‑safety: global model cache and lock
_model_lock = threading.Lock()
_model: Optional[Pipeline] = None  # cached classifier pipeline


# ---------------------------
# Helpers
# ---------------------------

def _ensure_openpyxl_available() -> None:
    """Ensure that the openpyxl library is available to read XLSX files.

    Pandas requires openpyxl to parse .xlsx files. If the library is missing,
    this function raises a RuntimeError with installation instructions.
    """
    if importlib.util.find_spec("openpyxl") is None:
        raise RuntimeError(
            "Reading .xlsx requires 'openpyxl' but it is not installed. "
            "Install it via 'pip install openpyxl'."
        )


def _read_first_column(xlsx_path: str) -> List[str]:
    """Load the first column of a .xlsx file into a list of non‑empty strings.

    Args:
        xlsx_path: Path to the Excel file.

    Returns:
        A list of strings representing non‑empty cells in the first column.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file has no columns or no examples.
        RuntimeError: If the file cannot be read or openpyxl is missing.
    """
    p = Path(xlsx_path)
    if not p.exists():
        raise FileNotFoundError(
            f"Required payload file not found: {p}\n"
            f"Expected files: {list(FILE_MAP.values())}"
        )
    # On case‑sensitive filesystems, ensure the filename matches exactly
    try:
        # For Windows or case‑insensitive FS, this check is redundant but harmless
        actual_name = p.name
        requested_name = Path(xlsx_path).name
        if actual_name != requested_name:
            raise FileNotFoundError(
                f"Filename case mismatch: requested '{requested_name}', found '{actual_name}'. "
                "Filenames must match exactly on case‑sensitive filesystems."
            )
    except Exception:
        # best effort; ignore if error retrieving name
        pass

    _ensure_openpyxl_available()
    try:
        # Force openpyxl engine for .xlsx
        df = pd.read_excel(p, engine="openpyxl")
    except Exception as e:
        raise RuntimeError(f"Failed to read '{p}': {e}") from e
    if df.shape[1] < 1:
        raise ValueError(f"'{p}' has no columns. Put examples in the FIRST column.")
    series = df.iloc[:, 0].dropna()
    examples = [str(x) for x in series.tolist() if str(x).strip()]
    if not examples:
        raise ValueError(f"'{p}' has no non‑empty examples in the first column.")
    return examples


def _load_dataset() -> Tuple[List[str], List[int]]:
    """Load all texts and labels from the configured payload files."""
    texts: List[str] = []
    labels: List[int] = []
    for label, path in FILE_MAP.items():
        samples = _read_first_column(path)
        texts.extend(samples)
        labels.extend([label] * len(samples))
    return texts, labels


def _make_pipeline() -> Pipeline:
    """Create a pipeline consisting of a character n‑gram TF‑IDF vectoriser and a linear SVM."""
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        lowercase=True,
        min_df=1,
        max_df=1.0,
        strip_accents=None,
        sublinear_tf=True,
    )
    clf = LinearSVC()
    return Pipeline([("tfidf", vectorizer), ("clf", clf)])


def _train_model() -> Pipeline:
    """Train a new model from the payload data and save it to disk."""
    texts, labels = _load_dataset()
    # Compute class weights to handle imbalanced datasets
    classes = np.unique(labels).astype(int)
    weights = compute_class_weight(class_weight="balanced", classes=classes, y=np.asarray(labels, dtype=int))
    class_weight = {int(c): float(w) for c, w in zip(classes, weights)}

    base = _make_pipeline()

    if TUNE:
        param_grid = {
            "tfidf__ngram_range": [(3, 5), (2, 5), (3, 6)],
            "clf__C": [0.5, 1.0, 2.0],
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
        vectorizer = base.named_steps["tfidf"]
        clf = LinearSVC(C=1.0, class_weight=class_weight)
        model = Pipeline([("tfidf", vectorizer), ("clf", clf)])
        model.fit(texts, labels)

    # Save the model and metadata
    joblib.dump(
        {
            "model": model,
            "meta": {
                "version": 1,
                "classes": sorted(list(set(int(x) for x in labels))),
                "files": FILE_MAP,
                "tuned": TUNE,
                "timestamp": time.time(),
            },
        },
        MODEL_PATH,
    )
    return model


def _load_or_train() -> Pipeline:
    """Load a cached model if available and valid; otherwise train a new one."""
    global _model
    with _model_lock:
        if _model is not None:
            return _model
        # Try to load from cache
        if os.path.exists(MODEL_PATH):
            try:
                payload = joblib.load(MODEL_PATH)
                model = payload.get("model")
                meta = payload.get("meta", {})
                classes = set(int(x) for x in meta.get("classes", []))
                expected = {0, 1, 2, 3}
                if model is not None and classes == expected:
                    _model = model
                    return _model
            except Exception:
                # If loading fails, fall through to train
                pass
        # If cache is invalid or missing, train anew
        _model = _train_model()
        return _model


# ---------------------------
# Rate Limiter
# ---------------------------

def rate_limited(max_calls: int, period: int):
    """Decorator to rate limit calls to a function. Raises RuntimeError on overflow."""
    def decorator(func):
        calls: List[float] = []
        lock = threading.Lock()

        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal calls
            now = time.time()
            with lock:
                # Remove timestamps outside the current window
                calls = [t for t in calls if now - t < period]
                if len(calls) >= max_calls:
                    raise RuntimeError(f"Rate limit exceeded for {func.__name__}")
                calls.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------
# Public API
# ---------------------------

@rate_limited(MAX_CALLS, PERIOD_SEC)
def detect_attack(data: str) -> int:
    """Detect malicious payload type in the given data string.

    Args:
        data: The payload to classify. If None or empty/whitespace, it is treated as benign.

    Returns:
        An integer code: 0 for benign, 1 for SQLi, 2 for XSS, or 3 for DDoS.
    """
    try:
        model = _load_or_train()
        # Treat None or empty/whitespace as benign
        text = "" if data is None else str(data)
        if not text.strip():
            return 0
        return int(model.predict([text])[0])
    except NotFittedError:
        # Train if somehow model is not fitted
        model = _train_model()
        return int(model.predict([str(data)])[0])
    except Exception:
        # On any error, default to benign to avoid false positives
        return 0


if __name__ == "__main__":
    # Manual smoke test when running directly
    print("Detector label map: 0=benign, 1=SQLi, 2=XSS, 3=DDoS")
    print("Loading/training model from XLSX files...")
    m = _load_or_train()
    for t in ["Hello", "<script>alert(1)</script>", "SELECT * FROM users", "GET / " * 30]:
        print(repr(t[:60]), "=>", detect_attack(t))
