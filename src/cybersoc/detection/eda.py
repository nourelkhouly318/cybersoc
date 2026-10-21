"""Initial exploratory data analysis for UNSW-NB15.

Usage:
    python -m cybersoc.detection.eda --data-dir data/raw --out reports

Writes:
    reports/eda_summary.json   - machine-readable summary (sizes, classes, quality)
    reports/eda_summary.md     - human-readable summary for the Milestone I report
    reports/figures/*.png      - class distribution, attack categories, protocols,
                                 feature correlation with the label
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

TRAIN_FILE = "UNSW_NB15_training-set.csv"
TEST_FILE = "UNSW_NB15_testing-set.csv"
CATEGORICAL = ["proto", "service", "state"]
TARGETS = ["attack_cat", "label"]


def load(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    # utf-8-sig strips the BOM present in some public copies of the CSVs
    train = pd.read_csv(data_dir / TRAIN_FILE, encoding="utf-8-sig")
    test = pd.read_csv(data_dir / TEST_FILE, encoding="utf-8-sig")
    for df in (train, test):
        df["attack_cat"] = df["attack_cat"].astype(str).str.strip()
    return train, test


def quality(df: pd.DataFrame) -> dict:
    feats = df.drop(columns=["id"] + TARGETS)
    numeric = feats.select_dtypes(include=np.number)
    return {
        "rows": int(len(df)),
        "columns": int(df.shape[1]),
        "numeric_features": int(numeric.shape[1]),
        "categorical_features": int(feats.shape[1] - numeric.shape[1]),
        "missing_cells": int(df.isna().sum().sum()),
        "duplicate_rows_excl_id": int(df.drop(columns=["id"]).duplicated().sum()),
        "constant_features": [c for c in numeric if numeric[c].nunique() <= 1],
        "service_dash_share": round(float((df["service"] == "-").mean()), 4),
        "infinite_values": int(np.isinf(numeric.to_numpy()).sum()),
    }


def summarize(train: pd.DataFrame, test: pd.DataFrame) -> dict:
    s: dict = {"train": quality(train), "test": quality(test)}
    for name, df in (("train", train), ("test", test)):
        s[name]["label_counts"] = {
            "normal": int((df["label"] == 0).sum()),
            "attack": int((df["label"] == 1).sum()),
        }
        s[name]["attack_cat_counts"] = df["attack_cat"].value_counts().astype(int).to_dict()
    s["proto_unique_train"] = int(train["proto"].nunique())
    s["service_unique_train"] = int(train["service"].nunique())
    s["state_unique_train"] = int(train["state"].nunique())
    s["categories_only_in_test"] = {
        c: sorted(set(test[c]) - set(train[c])) for c in CATEGORICAL
    }
    num = train.drop(columns=["id"] + TARGETS).select_dtypes(include=np.number)
    corr = num.corrwith(train["label"]).abs().sort_values(ascending=False)
    s["top_label_correlations"] = {k: round(float(v), 3) for k, v in corr.head(10).items()}
    # Highly redundant feature pairs (|r| > 0.95) are candidates for pruning
    cm = num.corr().abs()
    upper = cm.where(np.triu(np.ones(cm.shape, dtype=bool), k=1))
    pairs = [
        (a, b, round(float(upper.loc[a, b]), 3))
        for a in upper.index
        for b in upper.columns
        if pd.notna(upper.loc[a, b]) and upper.loc[a, b] > 0.95
    ]
    s["redundant_pairs_gt_0_95"] = pairs
    return s


def plots(train: pd.DataFrame, test: pd.DataFrame, fig_dir: Path) -> list[str]:
    fig_dir.mkdir(parents=True, exist_ok=True)
    out = []

    # 1. Attack category distribution, train vs test
    cats = train["attack_cat"].value_counts().index
    tr = train["attack_cat"].value_counts().reindex(cats)
    te = test["attack_cat"].value_counts().reindex(cats).fillna(0)
    fig, ax = plt.subplots(figsize=(9, 4.5))
    x = np.arange(len(cats))
    ax.bar(x - 0.2, tr.values, 0.4, label="train", color="#7a1f3d")
    ax.bar(x + 0.2, te.values, 0.4, label="test", color="#c9a3b1")
    ax.set_xticks(x, cats, rotation=35, ha="right")
    ax.set_yscale("log")
    ax.set_ylabel("records (log scale)")
    ax.set_title("UNSW-NB15: records per class")
    ax.legend(frameon=False)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    p = fig_dir / "class_distribution.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    out.append(p.name)

    # 2. Top protocols by attack share
    top = train["proto"].value_counts().head(8).index
    sub = train[train["proto"].isin(top)]
    ct = pd.crosstab(sub["proto"], sub["label"]).reindex(top)
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh(ct.index, ct[0], color="#c9a3b1", label="normal")
    ax.barh(ct.index, ct[1], left=ct[0], color="#7a1f3d", label="attack")
    ax.invert_yaxis()
    ax.set_xlabel("records")
    ax.set_title("Top 8 protocols in training set, normal vs attack")
    ax.legend(frameon=False)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    p = fig_dir / "protocols.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    out.append(p.name)

    # 3. Features most correlated with the binary label
    num = train.drop(columns=["id"] + TARGETS).select_dtypes(include=np.number)
    corr = num.corrwith(train["label"]).dropna()
    top = corr.abs().sort_values(ascending=False).head(12).index
    vals = corr[top]
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh(vals.index, vals.values, color=["#7a1f3d" if v > 0 else "#8a8a8a" for v in vals])
    ax.invert_yaxis()
    ax.axvline(0, color="#444", lw=0.8)
    ax.set_xlabel("Pearson r with label (1 = attack)")
    ax.set_title("Features most correlated with the attack label")
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout()
    p = fig_dir / "label_correlation.png"
    fig.savefig(p, dpi=160)
    plt.close(fig)
    out.append(p.name)
    return out


def to_markdown(s: dict) -> str:
    t, e = s["train"], s["test"]
    lines = [
        "# UNSW-NB15 — initial EDA summary",
        "",
        "| | Train | Test |",
        "|---|---|---|",
        f"| Records | {t['rows']:,} | {e['rows']:,} |",
        f"| Columns | {t['columns']} | {e['columns']} |",
        f"| Numeric / categorical features | {t['numeric_features']} / {t['categorical_features']} | {e['numeric_features']} / {e['categorical_features']} |",
        f"| Normal / attack | {t['label_counts']['normal']:,} / {t['label_counts']['attack']:,} | {e['label_counts']['normal']:,} / {e['label_counts']['attack']:,} |",
        f"| Missing cells | {t['missing_cells']} | {e['missing_cells']} |",
        f"| Duplicate rows (excl. id) | {t['duplicate_rows_excl_id']:,} | {e['duplicate_rows_excl_id']:,} |",
        f"| `service` = '-' (unknown) | {t['service_dash_share']:.1%} | {e['service_dash_share']:.1%} |",
        "",
        "## Records per attack category (train)",
        "",
        "| Category | Records | Share |",
        "|---|---|---|",
    ]
    total = t["rows"]
    for k, v in t["attack_cat_counts"].items():
        lines.append(f"| {k} | {v:,} | {v / total:.2%} |")
    lines += ["", "## Top features by |correlation| with label", ""]
    for k, v in s["top_label_correlations"].items():
        lines.append(f"- `{k}`: {v}")
    lines += ["", f"Highly redundant pairs (|r| > 0.95): {len(s['redundant_pairs_gt_0_95'])}"]
    for a, b, r in s["redundant_pairs_gt_0_95"]:
        lines.append(f"- `{a}` ~ `{b}` ({r})")
    lines += ["", f"Categories present only in test: {s['categories_only_in_test']}"]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data/raw")
    ap.add_argument("--out", default="reports")
    a = ap.parse_args()
    out = Path(a.out)
    train, test = load(Path(a.data_dir))
    s = summarize(train, test)
    s["figures"] = plots(train, test, out / "figures")
    out.mkdir(parents=True, exist_ok=True)
    (out / "eda_summary.json").write_text(json.dumps(s, indent=2))
    (out / "eda_summary.md").write_text(to_markdown(s))
    print(to_markdown(s))


if __name__ == "__main__":
    main()
