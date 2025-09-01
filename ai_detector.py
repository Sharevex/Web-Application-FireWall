#!/usr/bin/env python3
"""
ai_detector.py
- XLSX-only datasets (first column = text examples)
- Models: SVM (default) or RandomForest via env AI_MODEL=svm|rf
- Char TF-IDF (3..5 n-grams) robust to obfuscation
- Strict: FAIL if any payload file missing or empty
- Cached model to AI_MODEL_PATH (joblib)
- Thread-safe lazy load + rate limiting

Env:
  AI_PAYLOAD_DIR (default: payloads)
  AI_MODEL (svm|rf; default svm)
  AI_MODEL_PATH (default ai_detector_model.pkl)
  AI_DETECTOR_TUNE=1 to enable light GridSearch
  AI_RATE_MAX_CALLS=100 per AI_RATE_PERIOD=60
"""

import os
import time
import threading
import joblib
import pandas as pd
import numpy as np
from typing import List, Tuple
from functools import wraps
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.utils.class_weight import compute_class_weight
from sklearn.exceptions import NotFittedError
import logging

# ---------- Logging ----------
logger = logging.getLogger("ai_detector")
if not logger.handlers:
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(ch)

# ---------- Config ----------
PAYLOAD_DIR = os.getenv("AI_PAYLOAD_DIR", "payloads")
FILE_MAP = {
    0: os.path.join(PAYLOAD_DIR, "benign.xlsx"),
    1: os.path.join(PAYLOAD_DIR, "sqli.xlsx"),
    2: os.path.join(PAYLOAD_DIR, "xss.xlsx"),
    3: os.path.join(PAYLOAD_DIR, "ddos.xlsx"),
}
MODEL_PATH = os.getenv("AI_MODEL_PATH", "ai_detector_model.pkl")
AI_MODEL = os.getenv("AI_MODEL", "svm").lower()  # svm | rf
TUNE = os.getenv("AI_DETECTOR_TUNE", "0") == "1"
MAX_CALLS = int(os.getenv("AI_RATE_MAX_CALLS", "100"))
PERIOD_SEC = int(os.getenv("AI_RATE_PERIOD", "60"))

# Thread safety
_model_lock = threading.Lock()
_model: Pipeline | None = None


def rate_limited(max_calls: int, period: int):
    def deco(fn):
        calls = []
        lock = threading.Lock()

        @wraps(fn)
        def wrapper(*a, **kw):
            nonlocal calls
            now = time.time()
            with lock:
                calls = [t for t in calls if now - t < period]
                if len(calls) >= max_calls:
                    raise RuntimeError("ai_detector rate limit exceeded")
                calls.append(now)
            return fn(*a, **kw)
        return wrapper
    return deco


def _available_excel_engines():
    engines = []
    try:
        import openpyxl  # noqa
        engines.append("openpyxl")
    except Exception:
        pass
    try:
        import calamine  # python-calamine
        engines.append("calamine")
    except Exception:
        pass
    try:
        import xlrd  # old .xls
        engines.append("xlrd")
    except Exception:
        pass
    return engines


def _read_first_column(path: str) -> List[str]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing payload file: {path}")

    engines = _available_excel_engines()
    if not engines:
        raise RuntimeError(
            "No Excel engines available. Install one of:\n"
            "  pip install openpyxl   # for .xlsx (recommended)\n"
            "  pip install python-calamine\n"
            "  pip install xlrd       # for old .xls"
        )

    errors = []
    for eng in engines:
        try:
            df = pd.read_excel(path, engine=eng, usecols=[0])
            series = df.iloc[:, 0].dropna()
            texts = [str(x).strip() for x in series.tolist() if str(x).strip()]
            if not texts:
                raise ValueError(f"No non-empty examples in first column: {path}")
            return texts
        except Exception as e:
            errors.append(f"{eng}: {e}")
    raise RuntimeError("Failed to read {} via engines:\n{}".format(path, "\n".join("  - " + e for e in errors)))


def _load_dataset() -> Tuple[List[str], List[int]]:
    X, y = [], []
    for label, f in FILE_MAP.items():
        samples = _read_first_column(f)
        X.extend(samples)
        y.extend([label] * len(samples))
    return X, y


def _vectorizer():
    return TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        lowercase=True,
        min_df=1,
        sublinear_tf=True,
    )


def _build_pipeline(model_name: str, class_weight_map: dict | None) -> Pipeline:
    vec = _vectorizer()
    if model_name == "rf":
        clf = RandomForestClassifier(
            n_estimators=300,
            random_state=42,
            n_jobs=-1,
        )
        # RF has no class_weight; will pass sample_weight in fit()
        pipe = Pipeline([("tfidf", vec), ("clf", clf)])
    else:
        clf = LinearSVC(C=1.0, class_weight=class_weight_map, random_state=42)
        pipe = Pipeline([("tfidf", vec), ("clf", clf)])
    return pipe


def _train() -> Pipeline:
    X, y = _load_dataset()
    classes = np.unique(np.array(y))
    weights = compute_class_weight("balanced", classes=classes, y=np.array(y))
    class_weight_map = {int(c): float(w) for c, w in zip(classes, weights)}

    base = _build_pipeline(AI_MODEL, class_weight_map)

    if TUNE and AI_MODEL == "svm":
        grid = {
            "tfidf__ngram_range": [(3, 5), (2, 5), (3, 6)],
            "clf__C": [0.5, 1.0, 2.0],
        }
        search = GridSearchCV(base, grid, scoring="f1_macro", cv=3, n_jobs=-1, verbose=0)
        search.fit(X, y)
        model = search.best_estimator_
    else:
        if AI_MODEL == "rf":
            # Fit with sample weights to emulate class balance
            sample_weight = np.array([class_weight_map[int(lbl)] for lbl in y], dtype=float)
            # Fit stage-by-stage: transform then RF
            tfidf = base.named_steps["tfidf"]
            Xvec = tfidf.fit_transform(X)
            clf: RandomForestClassifier = base.named_steps["clf"]
            clf.fit(Xvec, y, sample_weight=sample_weight)
            from sklearn.pipeline import Pipeline as _P
            model = _P([("tfidf", tfidf), ("clf", clf)])
        else:
            model = base.fit(X, y)

    meta = {
        "version": 3,
        "classes": [0, 1, 2, 3],
        "files": FILE_MAP,
        "model": AI_MODEL,
        "timestamp": time.time(),
        "tuned": TUNE,
    }
    joblib.dump({"model": model, "meta": meta}, MODEL_PATH)
    logger.info("✅ AI model trained & saved: %s", MODEL_PATH)
    return model


def _load_or_train() -> Pipeline:
    global _model
    with _model_lock:
        if _model is not None:
            return _model
        if os.path.exists(MODEL_PATH):
            try:
                payload = joblib.load(MODEL_PATH)
                mdl = payload.get("model")
                meta = payload.get("meta", {})
                if mdl and set(meta.get("classes", [])) == {0, 1, 2, 3}:
                    _model = mdl
                    return _model
            except Exception as e:
                logger.warning("model load failed: %s (retraining)", e)
        _model = _train()
        return _model


@rate_limited(MAX_CALLS, PERIOD_SEC)
def detect_attack(text: str) -> int:
    """
    0=benign, 1=SQLi, 2=XSS, 3=DDoS
    """
    try:
        mdl = _load_or_train()
        s = "" if text is None else str(text)
        if not s.strip():
            return 0
        return int(mdl.predict([s])[0])
    except NotFittedError:
        mdl = _train()
        return int(mdl.predict([str(text)])[0])
    except Exception as e:
        logger.error("detect_attack error: %s", e)
        return 0


if __name__ == "__main__":
    print("Detector 0=benign,1=SQLi,2=XSS,3=DDoS")
    engines = _available_excel_engines()
    print("Excel engines:", ", ".join(engines) or "none ❌")
    for missing in [p for p in FILE_MAP.values() if not os.path.exists(p)]:
        print("Missing:", missing)
    mdl = _load_or_train()
    for t in ["hello", "<script>alert(1)</script>", "SELECT * FROM users", "GET / " * 30]:
        print(repr(t[:60]), "=>", detect_attack(t))
