"""
SALAD Evaluation Script
========================
Evaluate models on all 4 SALAD benchmark tasks.

Tasks:
  1. Alert Classification (binary: malicious/benign)
  2. Alert Triage (3-class: escalate/investigate/suppress)
  3. Alert Prioritization (regression: priority_score)
  4. Attack Category Classification (multi-class)

Usage:
    python evaluate.py --data ./SALAD/salad_test.csv --predictions predictions.csv --task classification
    python evaluate.py --data ./SALAD/salad_test.csv --run-baselines --task all

Author: JN_DataSet Research Team
License: CC-BY 4.0
"""

import argparse
import json
import os
import warnings

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    roc_auc_score, classification_report, confusion_matrix,
    mean_squared_error, mean_absolute_error, ndcg_score
)
from sklearn.preprocessing import LabelEncoder
from scipy.stats import spearmanr

warnings.filterwarnings("ignore")


# ============================================================
# Feature Engineering
# ============================================================

# Features that DO NOT leak ground truth (is_malicious)
# Excluded: confidence, priority_score (derived from is_malicious)
# Excluded: triage_decision, difficulty_level (derived from is_malicious)
# Excluded: alert_type, kill_chain_phase, mitre_* (derived from attack label)
# Excluded: source_dataset (perfectly splits CICIDS vs UNSW attack types)
# Excluded: severity (deterministically mapped from attack label)
FEATURE_COLS = [
    "src_port", "dst_port", "flow_duration", "total_fwd_packets",
    "total_bwd_packets", "flow_bytes_per_sec",
    "alert_count_1h", "alert_count_24h", "is_repeated_target",
]

# Categorical features that don't leak labels
CATEGORICAL_COLS = [
    "protocol", "network_segment",
]


# Shared label encoders to ensure consistency between train/test
_label_encoders = {}


def prepare_features(df: pd.DataFrame, fit=True) -> pd.DataFrame:
    """Prepare feature matrix from SALAD dataframe.
    
    Args:
        df: SALAD dataframe
        fit: If True, fit new label encoders ($train). If False, reuse fitted encoders (test).
    """
    global _label_encoders
    df = df.copy()
    
    # Encode categoricals
    for col in CATEGORICAL_COLS:
        if col in df.columns:
            if fit:
                le = LabelEncoder()
                df[col + "_enc"] = le.fit_transform(df[col].astype(str))
                _label_encoders[col] = le
            else:
                le = _label_encoders.get(col)
                if le:
                    # Handle unseen categories gracefully
                    vals = df[col].astype(str)
                    known = set(le.classes_)
                    vals = vals.map(lambda x: x if x in known else le.classes_[0])
                    df[col + "_enc"] = le.transform(vals)
                else:
                    df[col + "_enc"] = 0
    
    # Boolean to int
    df["is_repeated_target"] = df["is_repeated_target"].astype(int)
    df["is_malicious_int"] = df["is_malicious"].astype(int)
    
    # Select features
    feat_cols = FEATURE_COLS.copy()
    for col in CATEGORICAL_COLS:
        enc_col = col + "_enc"
        if enc_col in df.columns:
            feat_cols.append(enc_col)
    
    # Handle inf/nan
    X = df[feat_cols].replace([np.inf, -np.inf], np.nan).fillna(0)
    return X, df


def load_data(train_path, test_path, max_train=None):
    """Load and prepare train/test data.
    
    Args:
        train_path: Path to training CSV
        test_path: Path to test CSV
        max_train: If set, subsample training data to this many rows (prevents memorization)
    """
    global _label_encoders
    _label_encoders = {}  # Reset encoders
    
    train = pd.read_csv(train_path, low_memory=False)
    test = pd.read_csv(test_path, low_memory=False)
    
    # Subsample training data to prevent memorization by tree models
    if max_train and len(train) > max_train:
        print(f"  Subsampling train: {len(train):,} → {max_train:,} (stratified)")
        # Stratified subsample
        train = train.groupby("attack_category", group_keys=False).apply(
            lambda x: x.sample(n=max(1, int(len(x) * max_train / len(train))), random_state=42)
        ).reset_index(drop=True)
        print(f"  Actual train size after stratified subsample: {len(train):,}")
    
    X_train, train = prepare_features(train, fit=True)
    X_test, test = prepare_features(test, fit=False)
    
    # Align columns (use train columns as reference)
    common_cols = sorted(set(X_train.columns) & set(X_test.columns))
    X_train = X_train[common_cols]
    X_test = X_test[common_cols]
    
    return X_train, X_test, train, test


def print_feature_importance(model, feature_names, top_n=10):
    """Print feature importance from a fitted tree model."""
    if not hasattr(model, "feature_importances_"):
        return
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1][:top_n]
    print(f"\n  Top-{top_n} Feature Importances:")
    for rank, idx in enumerate(indices, 1):
        print(f"    {rank}. {feature_names[idx]:25s} {importances[idx]:.4f}")
    print()


# ============================================================
# Task 1: Alert Classification (Binary)
# ============================================================

def eval_classification(y_true, y_pred, y_prob=None):
    """Evaluate binary classification."""
    results = {
        "accuracy": accuracy_score(y_true, y_pred),
        "f1": f1_score(y_true, y_pred, average="binary"),
        "precision": precision_score(y_true, y_pred, average="binary"),
        "recall": recall_score(y_true, y_pred, average="binary"),
    }
    if y_prob is not None:
        try:
            results["auc_roc"] = roc_auc_score(y_true, y_prob)
        except:
            results["auc_roc"] = None
    return results


def run_task1(X_train, X_test, train, test, model_name="RandomForest"):
    """Task 1: Binary Alert Classification."""
    print(f"\n{'='*50}")
    print(f"  Task 1: Alert Classification ({model_name})")
    print(f"{'='*50}")
    
    y_train = train["is_malicious_int"]
    y_test = test["is_malicious_int"]
    
    if model_name == "RandomForest":
        model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    elif model_name == "GradientBoosting":
        model = GradientBoostingClassifier(n_estimators=100, random_state=42)
    elif model_name == "LogisticRegression":
        model = LogisticRegression(max_iter=1000, random_state=42, class_weight="balanced")
    
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else None
    
    results = eval_classification(y_test, y_pred, y_prob)
    
    for k, v in results.items():
        print(f"  {k}: {v:.4f}" if v is not None else f"  {k}: N/A")
    
    print_feature_importance(model, list(X_train.columns))
    
    return {"task": "classification", "model": model_name, **results}


# ============================================================
# Task 2: Alert Triage (3-class)
# ============================================================

def run_task2(X_train, X_test, train, test, model_name="RandomForest"):
    """Task 2: Alert Triage Classification."""
    print(f"\n{'='*50}")
    print(f"  Task 2: Alert Triage ({model_name})")
    print(f"{'='*50}")
    
    le = LabelEncoder()
    y_train = le.fit_transform(train["triage_decision"])
    y_test = le.transform(test["triage_decision"])
    
    if model_name == "RandomForest":
        model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    elif model_name == "GradientBoosting":
        model = GradientBoostingClassifier(n_estimators=100, random_state=42)
    elif model_name == "LogisticRegression":
        model = LogisticRegression(max_iter=1000, random_state=42, multi_class="multinomial", class_weight="balanced")
    
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    results = {
        "accuracy": accuracy_score(y_test, y_pred),
        "weighted_f1": f1_score(y_test, y_pred, average="weighted"),
        "macro_f1": f1_score(y_test, y_pred, average="macro"),
    }
    
    # Per-class report
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    
    for k, v in results.items():
        print(f"  {k}: {v:.4f}")
    
    print_feature_importance(model, list(X_train.columns))
    
    return {"task": "triage", "model": model_name, **results}


# ============================================================
# Task 3: Alert Prioritization (Regression)
# ============================================================

def run_task3(X_train, X_test, train, test, model_name="RandomForest"):
    """Task 3: Alert Prioritization."""
    print(f"\n{'='*50}")
    print(f"  Task 3: Alert Prioritization ({model_name})")
    print(f"{'='*50}")
    
    # Remove priority_score from features to avoid leakage
    feat_cols = [c for c in X_train.columns if c != "priority_score"]
    X_train_clean = X_train[feat_cols]
    X_test_clean = X_test[feat_cols]
    
    y_train = train["priority_score"]
    y_test = test["priority_score"]
    
    from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
    from sklearn.linear_model import LinearRegression
    
    if model_name == "RandomForest":
        model = RandomForestRegressor(n_estimators=100, random_state=42, n_jobs=-1)
    elif model_name == "GradientBoosting":
        model = GradientBoostingRegressor(n_estimators=100, random_state=42)
    elif model_name == "LogisticRegression":
        model = LinearRegression()
        model_name = "LinearRegression"
    
    model.fit(X_train_clean, y_train)
    y_pred = model.predict(X_test_clean)
    
    # NDCG@k
    k_values = [5, 10, 20]
    ndcg_results = {}
    for k in k_values:
        if len(y_test) >= k:
            try:
                ndcg_results[f"ndcg@{k}"] = ndcg_score(
                    y_test.values.reshape(1, -1), 
                    y_pred.reshape(1, -1), 
                    k=k
                )
            except:
                ndcg_results[f"ndcg@{k}"] = None
    
    # Spearman correlation
    spearman_corr, _ = spearmanr(y_test, y_pred)
    
    results = {
        "mse": mean_squared_error(y_test, y_pred),
        "mae": mean_absolute_error(y_test, y_pred),
        "spearman_corr": spearman_corr,
        **ndcg_results,
    }
    
    for k, v in results.items():
        print(f"  {k}: {v:.4f}" if v is not None else f"  {k}: N/A")
    
    return {"task": "prioritization", "model": model_name, **results}


# ============================================================
# Task 4: Attack Category Classification (Multi-class)
# ============================================================

def run_task4(X_train, X_test, train, test, model_name="RandomForest"):
    """Task 4: Attack Category Classification."""
    print(f"\n{'='*50}")
    print(f"  Task 4: Attack Category ({model_name})")
    print(f"{'='*50}")
    
    le = LabelEncoder()
    y_train = le.fit_transform(train["attack_category"])
    y_test = le.transform(test["attack_category"])
    
    if model_name == "RandomForest":
        model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    elif model_name == "GradientBoosting":
        model = GradientBoostingClassifier(n_estimators=100, random_state=42)
    elif model_name == "LogisticRegression":
        model = LogisticRegression(max_iter=1000, random_state=42, multi_class="multinomial", class_weight="balanced")
    
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    
    results = {
        "accuracy": accuracy_score(y_test, y_pred),
        "macro_f1": f1_score(y_test, y_pred, average="macro"),
        "weighted_f1": f1_score(y_test, y_pred, average="weighted"),
    }
    
    # Per-class
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=le.classes_, zero_division=0))
    
    for k, v in results.items():
        print(f"  {k}: {v:.4f}")
    
    print_feature_importance(model, list(X_train.columns))
    
    return {"task": "attack_category", "model": model_name, **results}


# ============================================================
# Task 5 (Bonus): Difficulty-Stratified Evaluation
# ============================================================

def run_difficulty_eval(X_train, X_test, train, test):
    """Evaluate classification performance stratified by difficulty level."""
    print(f"\n{'='*50}")
    print(f"  Bonus: Difficulty-Stratified Evaluation")
    print(f"{'='*50}")
    
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    y_train = train["is_malicious_int"]
    model.fit(X_train, y_train)
    
    results = {}
    for difficulty in ["easy", "medium", "hard"]:
        mask = test["difficulty_level"] == difficulty
        if mask.sum() == 0:
            continue
        
        X_sub = X_test[mask]
        y_sub = test.loc[mask, "is_malicious_int"]
        y_pred = model.predict(X_sub)
        
        f1 = f1_score(y_sub, y_pred, average="binary", zero_division=0)
        acc = accuracy_score(y_sub, y_pred)
        n = mask.sum()
        
        results[difficulty] = {"f1": f1, "accuracy": acc, "n_samples": int(n)}
        print(f"  {difficulty:8s}: F1={f1:.4f} | Acc={acc:.4f} | n={n}")
    
    return {"task": "difficulty_stratified", "model": "RandomForest", "results": results}


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="SALAD Evaluation Script")
    parser.add_argument("--train", default="./SALAD/salad_train.csv", help="Training CSV")
    parser.add_argument("--test", default="./SALAD/salad_test.csv", help="Test CSV")
    parser.add_argument("--task", choices=["classification", "triage", "prioritization", "attack_category", "all"],
                        default="all", help="Task to evaluate")
    parser.add_argument("--output", default="./SALAD/baselines", help="Output directory for results")
    parser.add_argument("--max-train", type=int, default=None,
                        help="Max training samples (stratified subsample). Prevents memorization by large tree models.")
    args = parser.parse_args()
    
    os.makedirs(args.output, exist_ok=True)
    
    print("=" * 50)
    print("  SALAD — Benchmark Evaluation")
    print("=" * 50)
    
    # Load data
    print("\nLoading data...")
    X_train, X_test, train, test = load_data(args.train, args.test, max_train=args.max_train)
    print(f"  Train: {len(train):,} | Test: {len(test):,}")
    print(f"  Features ({X_train.shape[1]}): {list(X_train.columns)}")
    
    all_results = []
    models = ["RandomForest", "GradientBoosting", "LogisticRegression"]
    
    for model_name in models:
        if args.task in ("classification", "all"):
            all_results.append(run_task1(X_train, X_test, train, test, model_name))
        if args.task in ("triage", "all"):
            all_results.append(run_task2(X_train, X_test, train, test, model_name))
        if args.task in ("prioritization", "all"):
            all_results.append(run_task3(X_train, X_test, train, test, model_name))
        if args.task in ("attack_category", "all"):
            all_results.append(run_task4(X_train, X_test, train, test, model_name))
    
    # Difficulty-stratified evaluation
    if args.task in ("classification", "all"):
        all_results.append(run_difficulty_eval(X_train, X_test, train, test))
    
    # Save results
    results_path = os.path.join(args.output, "baseline_results.json")
    with open(results_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n✅ Results saved to {results_path}")
    
    # Print summary table
    print(f"\n{'='*70}")
    print(f"  SALAD Baseline Results Summary")
    print(f"{'='*70}")
    print(f"{'Task':<20} {'Model':<20} {'Primary Metric':<15} {'Score':<10}")
    print(f"{'-'*65}")
    for r in all_results:
        task = r.get("task", "")
        model = r.get("model", "")
        if task == "classification":
            print(f"{task:<20} {model:<20} {'F1':<15} {r.get('f1', 0):.4f}")
        elif task == "triage":
            print(f"{task:<20} {model:<20} {'Weighted F1':<15} {r.get('weighted_f1', 0):.4f}")
        elif task == "prioritization":
            print(f"{task:<20} {model:<20} {'Spearman':<15} {r.get('spearman_corr', 0):.4f}")
        elif task == "attack_category":
            print(f"{task:<20} {model:<20} {'Macro F1':<15} {r.get('macro_f1', 0):.4f}")


if __name__ == "__main__":
    main()
