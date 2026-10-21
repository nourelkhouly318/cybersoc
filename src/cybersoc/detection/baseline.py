"""Baseline detectors for UNSW-NB15.

These are the reference points CyberSOC's multi-agent pipeline is measured
against (proposal: "relative to single-model or rule-based baselines").

  1. rule      - single-threshold rule on the strongest feature (sttl)
  2. rf        - Random Forest on all flow features (single-model baseline)

Usage:
    python -m cybersoc.detection.baseline --data-dir data/raw --out reports
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from cybersoc.detection.eda import CATEGORICAL, TARGETS, load

SEED = 42


def featurize(train: pd.DataFrame, test: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """One-hot the categorical columns, aligning test to the train vocabulary."""
    Xtr = train.drop(columns=["id"] + TARGETS)
    Xte = test.drop(columns=["id"] + TARGETS)
    Xtr = pd.get_dummies(Xtr, columns=CATEGORICAL, dtype=np.uint8)
    Xte = pd.get_dummies(Xte, columns=CATEGORICAL, dtype=np.uint8)
    Xte = Xte.reindex(columns=Xtr.columns, fill_value=0)
    return Xtr, Xte


def binary_metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "f1": round(f1_score(y_true, y_pred), 4),
        "false_positive_rate": round(fp / (fp + tn), 4),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def rule_baseline(train: pd.DataFrame, test: pd.DataFrame) -> dict:
    """Pick the sttl threshold that maximises F1 on train, apply it to test."""
    best_t, best_f1 = None, -1.0
    for t in sorted(train["sttl"].unique()):
        f1 = f1_score(train["label"], (train["sttl"] >= t).astype(int))
        if f1 > best_f1:
            best_t, best_f1 = int(t), f1
    pred = (test["sttl"] >= best_t).astype(int)
    return {"rule": f"label = 1 if sttl >= {best_t}", **binary_metrics(test["label"], pred)}


def rf_baseline(train, test, Xtr, Xte) -> tuple[dict, dict]:
    clf = RandomForestClassifier(
        n_estimators=200, n_jobs=-1, random_state=SEED, class_weight="balanced_subsample"
    )
    t0 = time.time()
    clf.fit(Xtr, train["label"])
    fit_s = time.time() - t0
    pred = clf.predict(Xte)
    binary = {"fit_seconds": round(fit_s, 1), **binary_metrics(test["label"], pred)}
    imp = pd.Series(clf.feature_importances_, index=Xtr.columns).sort_values(ascending=False)
    binary["top_features"] = {k: round(float(v), 4) for k, v in imp.head(10).items()}

    mc = RandomForestClassifier(
        n_estimators=200, n_jobs=-1, random_state=SEED, class_weight="balanced_subsample"
    )
    mc.fit(Xtr, train["attack_cat"])
    mpred = mc.predict(Xte)
    rep = classification_report(test["attack_cat"], mpred, output_dict=True, zero_division=0)
    multi = {
        "accuracy": round(accuracy_score(test["attack_cat"], mpred), 4),
        "macro_f1": round(f1_score(test["attack_cat"], mpred, average="macro"), 4),
        "weighted_f1": round(f1_score(test["attack_cat"], mpred, average="weighted"), 4),
        "per_class_f1": {
            k: round(v["f1-score"], 3)
            for k, v in rep.items()
            if k not in ("accuracy", "macro avg", "weighted avg")
        },
    }
    return binary, multi


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/raw")
    ap.add_argument("--out", default="reports")
    a = ap.parse_args()
    train, test = load(Path(a.data_dir))
    Xtr, Xte = featurize(train, test)
    results = {"rule_baseline": rule_baseline(train, test)}
    results["rf_binary"], results["rf_multiclass"] = rf_baseline(train, test, Xtr, Xte)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "baseline_results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
