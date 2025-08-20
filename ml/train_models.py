#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy.stats import binomtest

from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from xgboost import XGBClassifier
import joblib


DATA_DEFAULT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "back-end", "dataset_merged.csv"))
CANONICAL_DEFAULT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "back-end", "phishing.csv"))
OUT_MODELS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "back-end", "models"))
OUT_REPORTS = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "back-end", "reports"))


def load_data(path: Optional[str] = None) -> Tuple[pd.DataFrame, str]:
    path = path or DATA_DEFAULT
    if not os.path.exists(path):
        path = CANONICAL_DEFAULT
    df = pd.read_csv(path)
    return df, path


def split_xy(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    cols = list(df.columns)
    label = "class" if "class" in cols else cols[-1]
    features = [c for c in cols if c not in (label, "Index")]
    X = df[features].values
    y = df[label].values
    return X, y, features


def tune_threshold(y_true: np.ndarray, scores: np.ndarray, metric: str = "f1") -> Tuple[float, Dict[str, float]]:
    # scores = probability of class 1 (legitimate). We want phishing = -1, legitimate = 1
    # Convert to phishing prob: p_phish = 1 - p_legit
    p_legit = scores
    p_phish = 1.0 - p_legit
    thresholds = np.linspace(0.1, 0.9, 17)
    best_t = 0.5
    best_f1 = -1.0
    for t in thresholds:
        y_pred = np.where(p_phish >= t, -1, 1)
        f1 = f1_score(y_true == -1, y_pred == -1)
        if f1 > best_f1:
            best_f1 = f1
            best_t = t
    # report
    y_pred = np.where(p_phish >= best_t, -1, 1)
    rep = {
        "threshold": float(best_t),
        "f1": float(f1_score(y_true == -1, y_pred == -1)),
        "recall": float(recall_score(y_true == -1, y_pred == -1)),
        "precision": float(precision_score(y_true == -1, y_pred == -1)),
    }
    return best_t, rep


def bootstrap_ci(y_true: np.ndarray, y_pred: np.ndarray, metric: str = "f1", n_boot: int = 500, seed: int = 42) -> Tuple[float, float]:
    rng = np.random.default_rng(seed)
    n = len(y_true)
    vals = []
    for _ in range(n_boot):
        idx = rng.integers(0, n, size=n)
        if metric == "f1":
            vals.append(f1_score((y_true[idx] == -1), (y_pred[idx] == -1)))
        elif metric == "recall":
            vals.append(recall_score((y_true[idx] == -1), (y_pred[idx] == -1)))
    vals = np.array(vals)
    lo, hi = np.percentile(vals, [2.5, 97.5])
    return float(lo), float(hi)


def mcnemar_test(y_true: np.ndarray, pred_a: np.ndarray, pred_b: np.ndarray) -> Dict[str, float]:
    # Count disagreements
    a_wrong = (pred_a != y_true)
    b_wrong = (pred_b != y_true)
    b01 = np.sum((a_wrong == 0) & (b_wrong == 1))
    b10 = np.sum((a_wrong == 1) & (b_wrong == 0))
    n = b01 + b10
    if n == 0:
        p = 1.0
    else:
        # Binomial test for b01 successes in n trials with p=0.5
        p = binomtest(k=min(b01, b10), n=n, p=0.5, alternative="two-sided").pvalue
    return {"b01": int(b01), "b10": int(b10), "p_value": float(p)}


def build_models() -> Dict[str, object]:
    models: Dict[str, object] = {}
    models["logreg"] = LogisticRegression(max_iter=500, class_weight="balanced", n_jobs=None)
    svc = LinearSVC(class_weight="balanced")
    models["linear_svm"] = CalibratedClassifierCV(svc, method="isotonic", cv=3)
    models["rf"] = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=42, n_jobs=-1)
    models["xgb"] = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=1.0,
        n_jobs=4,
        random_state=42,
        tree_method="hist",
        objective="binary:logistic",
        # We'll invert labels to {0,1} for training with -1→1 mapping below
    )
    return models


def to01(y: np.ndarray) -> np.ndarray:
    # map -1→1 (phish), 1→0 (legit) so positive class=phishing
    return np.where(y == -1, 1, 0)


def main(data_path: Optional[str] = None, seed: int = 42) -> int:
    os.makedirs(OUT_MODELS, exist_ok=True)
    os.makedirs(OUT_REPORTS, exist_ok=True)

    df, used_path = load_data(data_path)
    X, y, feat_names = split_xy(df)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=seed
    )

    models = build_models()
    metrics_report: Dict[str, dict] = {}
    preds_store: Dict[str, np.ndarray] = {}
    thresholds: Dict[str, float] = {}

    for name, model in models.items():
        # XGBoost expects {0,1}; others can handle -1/1 but we'll standardize
        if name == "xgb":
            y_train01 = to01(y_train)
            pos_weight = (y_train01 == 0).sum() / max((y_train01 == 1).sum(), 1)
            model.set_params(scale_pos_weight=pos_weight)
            model.fit(X_train, y_train01)
            # get proba for legitimate (class 0) then convert
            proba_legit = model.predict_proba(X_train)[..., 0]
        else:
            model.fit(X_train, y_train)
            if hasattr(model, "predict_proba"):
                proba_legit = model.predict_proba(X_train)[..., 1]  # class 1=legit
            elif hasattr(model, "decision_function"):
                # Map decision_function to pseudo-prob via min-max on train (rough)
                dfval = model.decision_function(X_train)
                dfval = (dfval - dfval.min()) / (dfval.ptp() + 1e-9)
                proba_legit = dfval
            else:
                # fallback: predictions only
                proba_legit = (model.predict(X_train) == 1).astype(float)

        t, t_rep = tune_threshold(y_train, proba_legit, metric="f1")
        thresholds[name] = t

        # Evaluate on test
        if name == "xgb":
            proba_legit_test = model.predict_proba(X_test)[..., 0]
        else:
            if hasattr(model, "predict_proba"):
                proba_legit_test = model.predict_proba(X_test)[..., 1]
            elif hasattr(model, "decision_function"):
                dfval = model.decision_function(X_test)
                dfval = (dfval - dfval.min()) / (dfval.ptp() + 1e-9)
                proba_legit_test = dfval
            else:
                proba_legit_test = (model.predict(X_test) == 1).astype(float)

        y_pred = np.where((1.0 - proba_legit_test) >= t, -1, 1)
        preds_store[name] = y_pred

        # Metrics
        acc = accuracy_score(y_test == -1, y_pred == -1)
        prec = precision_score(y_test == -1, y_pred == -1)
        rec = recall_score(y_test == -1, y_pred == -1)
        f1 = f1_score(y_test == -1, y_pred == -1)
        # AUCs need 01 labels
        try:
            roc = roc_auc_score(to01(y_test), 1.0 - proba_legit_test)
        except Exception:
            roc = float("nan")
        try:
            precs, recs, _ = precision_recall_curve(to01(y_test), 1.0 - proba_legit_test)
            pr_auc = float(np.trapz(precs[::-1], recs[::-1]))
        except Exception:
            pr_auc = float("nan")
        cm = confusion_matrix(y_test == -1, y_pred == -1).tolist()
        f1_ci = bootstrap_ci(y_test, y_pred, metric="f1")
        rec_ci = bootstrap_ci(y_test, y_pred, metric="recall")

        metrics_report[name] = {
            "threshold": t,
            "train_tuning": t_rep,
            "metrics": {
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "f1": f1,
                "roc_auc": roc,
                "pr_auc": pr_auc,
                "confusion_matrix": cm,
                "f1_CI95": f1_ci,
                "recall_CI95": rec_ci,
            },
        }

    # McNemar between best two by F1
    order = sorted(metrics_report.items(), key=lambda kv: kv[1]["metrics"]["f1"], reverse=True)
    if len(order) >= 2:
        a, b = order[0][0], order[1][0]
        mcn = mcnemar_test(y_test, preds_store[a], preds_store[b])
    else:
        mcn = {"p_value": None}

    # Persist best model
    best_name = order[0][0]
    best_model = models[best_name]
    best_threshold = thresholds[best_name]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    os.makedirs(OUT_MODELS, exist_ok=True)
    os.makedirs(OUT_REPORTS, exist_ok=True)
    model_path = os.path.join(OUT_MODELS, f"{best_name}_{stamp}.joblib")
    joblib.dump({"model": best_model, "threshold": best_threshold, "features": feat_names}, model_path)

    # Write best pointer
    joblib.dump({"path": model_path}, os.path.join(OUT_MODELS, "best_pointer.joblib"))

    # Report
    report = {
        "data_path": used_path,
        "models": metrics_report,
        "mcnemar_best_vs_second": mcn,
        "best": {"name": best_name, "threshold": best_threshold, "model_path": model_path},
    }
    with open(os.path.join(OUT_REPORTS, f"report_{stamp}.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Saved best model: {model_path}")
    print(f"Best model: {best_name} | threshold={best_threshold}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
