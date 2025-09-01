
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ai_detector.py
--------------
Trains & caches a multi-class text model from ONLY XLSX payloads:

  payloads/benign.xlsx -> 0
  payloads/sqli.xlsx   -> 1
  payloads/xss.xlsx    -> 2
  payloads/ddos.xlsx   -> 3

- Vectorizer: TF-IDF char_wb n-grams (3–5)
- Classifier: LinearSVC (with class_weight)
- Thread-safe lazy init + joblib cache
- Defensive Excel engine handling (openpyxl / python-calamine / xlrd)

Env:
  AI_PAYLOAD_DIR, AI_MODEL_PATH, AI_DETECTOR_TUNE, AI_RATE_MAX_CALLS, AI_RATE_PERIOD
"""

import os
import time
import threading
from functools import wraps
from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.model_selection import GridSearchCV
from sklearn.utils.class_weight import compute_class_weight
from sklearn.exceptions import NotFittedError

PAYLOAD_DIR = os.getenv("AI_PAYLOAD_DIR", "payloads")
FILE_MAP = {
    0: os.path.join(PAYLOAD_DIR, "benign.xlsx"),
    1: os.path.join(PAYLOAD_DIR, "sqli.xlsx"),
    2: os.path.join(PAYLOAD_DIR, "xss.xlsx"),
    3: os.path.join(PAYLOAD_DIR, "ddos.xlsx"),
}
MODEL_PATH = os.getenv("AI_MODEL_PATH", "ai_detector_model.pkl")
TUNE = os.getenv("AI_DETECTOR_TUNE", "0") == "1"

MAX_CALLS = int(os.getenv("AI_RATE_MAX_CALLS", "100"))
PERIOD_SEC = int(os.getenv("AI_RATE_PERIOD", "60"))

_model_lock = threading.Lock()
_model = None

def rate_limited(max_calls: int, period: int):
    def deco(fn):
        calls = []
        lock = threading.Lock()
        @wraps(fn)
        def wrapper(*a, **k):
            nonlocal calls
            now = time.time()
            with lock:
                calls = [t for t in calls if now - t < period]
                if len(calls) >= max_calls:
                    raise RuntimeError("ai_detector rate limit exceeded")
                calls.append(now)
            return fn(*a, **k)
        return wrapper
    return deco

def _available_engines():
    engines = []
    try:
        import openpyxl  # noqa
        engines.append("openpyxl")
    except Exception:
        pass
    try:
        import calamine  # noqa
        engines.append("calamine")
    except Exception:
        pass
    try:
        import xlrd  # noqa
        engines.append("xlrd")
    except Exception:
        pass
    return engines

def _read_first_col(path: str) -> List[str]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing required file: {path}")
    engines = _available_engines()
    if not engines:
        raise RuntimeError("No Excel engine: install openpyxl or python-calamine or xlrd")
    last_err = None
    for eng in engines:
        try:
            df = pd.read_excel(path, engine=eng, usecols=[0])
            s = df.iloc[:,0].dropna().astype(str).str.strip()
            items = [x for x in s.tolist() if x]
            if not items:
                raise ValueError(f"{path} has no non-empty examples in col 0")
            return items
        except Exception as e:
            last_err = e
    raise RuntimeError(f"Failed reading {path}: {last_err}")

def _load_data() -> Tuple[List[str], List[int]]:
    texts, labels = [], []
    for label, f in FILE_MAP.items():
        items = _read_first_col(f)
        texts.extend(items)
        labels.extend([label]*len(items))
    return texts, labels

def _make_pipeline() -> Pipeline:
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3,5), lowercase=True, sublinear_tf=True)
    clf = LinearSVC(random_state=42)
    return Pipeline([("tfidf", vec), ("clf", clf)])

def _train() -> Pipeline:
    X, y = _load_data()
    classes = np.unique(y)
    weights = compute_class_weight("balanced", classes=classes, y=y)
    cw = {int(c): float(w) for c, w in zip(classes, weights)}

    if TUNE:
        base = _make_pipeline()
        grid = {
            "tfidf__ngram_range": [(3,5), (2,5), (3,6)],
            "clf__C": [0.5, 1.0, 2.0],
            "clf__class_weight": [cw],
        }
        model = GridSearchCV(base, grid, scoring="f1_macro", cv=3, n_jobs=-1).fit(X, y).best_estimator_
    else:
        vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3,5), lowercase=True, sublinear_tf=True)
        clf = LinearSVC(C=1.0, class_weight=cw, random_state=42)
        model = Pipeline([("tfidf", vec), ("clf", clf)]).fit(X, y)

    joblib.dump({"model": model, "meta": {"classes": [0,1,2,3], "timestamp": time.time()}}, MODEL_PATH)
    return model

def _load_or_train() -> Pipeline:
    global _model
    with _model_lock:
        if _model is not None:
            return _model
        if os.path.exists(MODEL_PATH):
            try:
                payload = joblib.load(MODEL_PATH)
                m = payload.get("model")
                meta = payload.get("meta", {})
                if m is not None and set(meta.get("classes", [])) == {0,1,2,3}:
                    _model = m
                    return _model
            except Exception:
                pass
        _model = _train()
        return _model

@rate_limited(MAX_CALLS, PERIOD_SEC)
def detect_attack(data: str) -> int:
    try:
        m = _load_or_train()
        txt = "" if data is None else str(data)
        if not txt.strip():
            return 0
        return int(m.predict([txt])[0])
    except NotFittedError:
        _train()
        m = _load_or_train()
        return int(m.predict([str(data)])[0])
    except Exception:
        return 0

if __name__ == "__main__":
    print("0=benign, 1=SQLi, 2=XSS, 3=DDoS")
    print("engines:", _available_engines())
    print("predict('select * from users') ->", detect_attack("select * from users"))
