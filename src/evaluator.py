"""
evaluator.py
------------
Improvement 2: Dataset-based evaluation of the IPS detection engine.
Loads CICIDS2017 CSV files, replays rows through the signature
detection logic, and computes standard IDS evaluation metrics.

Architecture:
    Config          — centralised threshold and path configuration
    DatasetLoader   — CSV loading and normalisation
    SignatureDetector — predict() and score() per flow
    MetricsEngine   — computes and saves all evaluation metrics
    PlotEngine      — all matplotlib/seaborn visualisations
    Evaluator       — orchestrator (fast to_dict loop, no iterrows)

Outputs:
    results/evaluation/confusion_matrix.png
    results/evaluation/roc_curve.png
    results/evaluation/precision_recall_curve.png
    results/evaluation/metrics_report.txt
    results/evaluation/all_results.json

Thresholds derived from empirical data analysis (src/diagnose2.py):
    Attack (PortScan):  fwd_pkt_mean p95=2B,  flow_duration p95=90us
    Benign:             fwd_pkt_mean p25=6B,  flow_duration p25=186us
"""

import os
import sys
import json
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve,
    precision_recall_curve, average_precision_score,
)

# ── Dark theme ─────────────────────────────────────────────────────────────────

plt.rcParams.update({
    'figure.facecolor' : '#0d1117',
    'axes.facecolor'   : '#0d1117',
    'axes.edgecolor'   : '#30363d',
    'axes.labelcolor'  : '#c9d1d9',
    'text.color'       : '#c9d1d9',
    'xtick.color'      : '#8b949e',
    'ytick.color'      : '#8b949e',
    'grid.color'       : '#21262d',
    'grid.alpha'       : 0.5,
    'font.family'      : 'monospace',
})

# ══════════════════════════════════════════════════════════════════════════════
# Config
# ══════════════════════════════════════════════════════════════════════════════

class Config:
    """
    Centralised configuration.
    All thresholds derived from empirical analysis of CICIDS2017 flows.
    Edit here to tune detection — no changes needed elsewhere.
    """

    # Detection thresholds
    SCAN_MAX_PAYLOAD_BYTES    = 5      # fwd_pkt_mean <= this → scan probe
    SCAN_MAX_DURATION_US      = 500    # flow_duration <= this → scan probe
    PORTSCAN_PACKET_THRESHOLD = 100    # fwd_packets fallback for aggressive scans
    DNS_AMP_PACKET_THRESHOLD  = 50     # fwd_packets for DNS amplification

    SENSITIVE_PORTS = {22, 23, 25, 445, 3306, 3389}

    # Paths
    BASE_DIR    = os.path.join(os.path.dirname(__file__), '..')
    OUTPUT_DIR  = os.path.join(BASE_DIR, 'results', 'evaluation')
    DATASET_DIR = os.path.join(BASE_DIR, 'data', 'cicids2017')

# ══════════════════════════════════════════════════════════════════════════════
# DatasetLoader
# ══════════════════════════════════════════════════════════════════════════════

class DatasetLoader:
    """Loads and normalises CICIDS2017 CSV files."""

    COLUMN_MAP = {
        'Source IP'                   : 'src_ip',
        'Destination IP'              : 'dst_ip',
        'Source Port'                 : 'src_port',
        'Destination Port'            : 'dst_port',
        'Protocol'                    : 'protocol',
        'Total Length of Fwd Packets' : 'fwd_bytes',
        'Fwd Packet Length Max'       : 'fwd_pkt_max',
        'Fwd Packet Length Mean'      : 'fwd_pkt_mean',
        'Flow Duration'               : 'flow_duration',
        'Total Fwd Packets'           : 'fwd_packets',
        'Total Backward Packets'      : 'bwd_packets',
        'Flow Packets/s'              : 'flow_pps',
        'Label'                       : 'label',
    }

    @staticmethod
    def load(path: str) -> pd.DataFrame:
        print(f"[*] Loading {os.path.basename(path)}")

        df = pd.read_csv(path, low_memory=False)
        df.columns = df.columns.str.strip()

        df = df.rename(columns={
            k: v for k, v in DatasetLoader.COLUMN_MAP.items()
            if k in df.columns
        })

        if 'label' not in df.columns:
            raise ValueError("No 'Label' column found in dataset")

        df['is_attack'] = (df['label'].str.strip() != 'BENIGN').astype(int)

        attack_count = df['is_attack'].sum()
        benign_count = len(df) - attack_count
        print(f"[✓] Rows: {len(df):,}  |  "
              f"Attacks: {attack_count:,}  |  "
              f"Benign: {benign_count:,}")
        print(f"    Labels: {df['label'].str.strip().unique().tolist()}")

        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna(subset=['is_attack'])

        return df

# ══════════════════════════════════════════════════════════════════════════════
# SignatureDetector
# ══════════════════════════════════════════════════════════════════════════════

class SignatureDetector:
    """
    Per-flow signature detector.

    Two public methods:
        predict(row) → int   binary classification (0 or 1)
        score(row)   → float continuous confidence (0.0–1.0) for ROC curve

    Thresholds from Config — no magic numbers in logic.
    """

    def predict(self, row: dict) -> int:
        """Returns 1 (attack) or 0 (benign)."""
        size     = self._safe_float(row.get('fwd_pkt_mean'), default=100.0)
        duration = self._safe_float(row.get('flow_duration'), default=99999.0)
        fwd_pkts = self._safe_int(row.get('fwd_packets'), default=1)
        proto    = self._safe_int(row.get('protocol'), default=0)
        dst_port = self._safe_int(row.get('dst_port'), default=0)

        # Primary: scan probe — tiny payload + very short duration
        if (size <= Config.SCAN_MAX_PAYLOAD_BYTES and
                duration <= Config.SCAN_MAX_DURATION_US):
            return 1

        # Secondary: high forward packet count (aggressive scan)
        if fwd_pkts >= Config.PORTSCAN_PACKET_THRESHOLD:
            return 1

        # DNS amplification: UDP/53 with high packet count
        if (proto == 17 and dst_port == 53 and
                fwd_pkts >= Config.DNS_AMP_PACKET_THRESHOLD):
            return 1

        return 0

    def score(self, row: dict) -> float:
        """Returns a 0.0–1.0 confidence score for ROC/PR curve plotting."""
        size     = self._safe_float(row.get('fwd_pkt_mean'), default=100.0)
        duration = self._safe_float(row.get('flow_duration'), default=99999.0)
        fwd_pkts = self._safe_int(row.get('fwd_packets'), default=1)
        proto    = self._safe_int(row.get('protocol'), default=0)
        dst_port = self._safe_int(row.get('dst_port'), default=0)

        s = 0.0

        # Smaller payload → higher suspicion
        s += max(0.0, 1.0 - (size / 10.0)) * 0.50

        # Shorter duration → higher suspicion
        s += max(0.0, 1.0 - (duration / 1000.0)) * 0.35

        # High packet count
        if fwd_pkts >= Config.PORTSCAN_PACKET_THRESHOLD:
            s += 0.10

        # DNS amplification signal
        if proto == 17 and dst_port == 53:
            s += min(fwd_pkts / Config.DNS_AMP_PACKET_THRESHOLD, 1.0) * 0.05

        return min(s, 1.0)

    @staticmethod
    def _safe_float(val, default: float) -> float:
        try:
            v = float(val)
            return default if (np.isnan(v) or np.isinf(v)) else v
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _safe_int(val, default: int) -> int:
        try:
            return int(float(val))
        except (TypeError, ValueError):
            return default

# ══════════════════════════════════════════════════════════════════════════════
# MetricsEngine
# ══════════════════════════════════════════════════════════════════════════════

class MetricsEngine:
    """Computes, prints, and saves all evaluation metrics."""

    @staticmethod
    def compute(y_true: list, y_pred: list, y_score: list) -> dict:
        precision = precision_score(y_true, y_pred, zero_division=0)
        recall    = recall_score(y_true, y_pred, zero_division=0)
        f1        = f1_score(y_true, y_pred, zero_division=0)
        cm        = confusion_matrix(y_true, y_pred)
        tn, fp, fn, tp = cm.ravel()

        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        fnr = fn / (fn + tp) if (fn + tp) else 0.0

        try:
            auc = roc_auc_score(y_true, y_score)
        except Exception:
            auc = 0.0

        return {
            'precision'         : round(precision, 4),
            'recall'            : round(recall,    4),
            'f1_score'          : round(f1,         4),
            'false_positive_rate': round(fpr,       4),
            'false_negative_rate': round(fnr,       4),
            'auc_roc'           : round(auc,        4),
            'true_positives'    : int(tp),
            'false_positives'   : int(fp),
            'true_negatives'    : int(tn),
            'false_negatives'   : int(fn),
            'total_samples'     : len(y_true),
            'total_attacks'     : int(sum(y_true)),
            'total_benign'      : int(len(y_true) - sum(y_true)),
        }

    @staticmethod
    def print_report(m: dict) -> None:
        print("\n" + "="*55)
        print("  EVALUATION RESULTS — CICIDS2017")
        print("="*55)
        print(f"  Total samples       : {m['total_samples']:,}")
        print(f"  Attacks             : {m['total_attacks']:,}")
        print(f"  Benign              : {m['total_benign']:,}")
        print("-"*55)
        print(f"  Precision           : {m['precision']:.4f}")
        print(f"  Recall              : {m['recall']:.4f}")
        print(f"  F1 Score            : {m['f1_score']:.4f}")
        print(f"  False Positive Rate : {m['false_positive_rate']:.4f}")
        print(f"  False Negative Rate : {m['false_negative_rate']:.4f}")
        print(f"  AUC-ROC             : {m['auc_roc']:.4f}")
        print("-"*55)
        print(f"  TP={m['true_positives']:,}  FP={m['false_positives']:,}  "
              f"TN={m['true_negatives']:,}  FN={m['false_negatives']:,}")
        print("="*55 + "\n")

    @staticmethod
    def save(m: dict) -> None:
        os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
        path = os.path.join(Config.OUTPUT_DIR, 'metrics_report.txt')
        with open(path, 'w') as f:
            f.write("NETWORK IPS — EVALUATION REPORT\n")
            f.write(f"Generated  : {datetime.now().isoformat()}\n")
            f.write(f"Dataset    : CICIDS2017\n")
            f.write(f"Detector   : Per-flow signature engine (v5 refactor)\n")
            f.write(f"Thresholds : payload<={Config.SCAN_MAX_PAYLOAD_BYTES}B, "
                    f"duration<={Config.SCAN_MAX_DURATION_US}us\n")
            f.write("="*55 + "\n\n")
            for k, v in m.items():
                f.write(f"{k:<25}: {v}\n")
        print(f"[✓] Metrics saved      -> {path}")

# ══════════════════════════════════════════════════════════════════════════════
# PlotEngine
# ══════════════════════════════════════════════════════════════════════════════

class PlotEngine:
    """All matplotlib/seaborn visualisations."""

    @staticmethod
    def confusion_matrix(y_true: list, y_pred: list) -> None:
        cm = confusion_matrix(y_true, y_pred)
        fig, ax = plt.subplots(figsize=(6, 5))
        fig.patch.set_facecolor('#0d1117')

        sns.heatmap(
            cm, annot=True, fmt='d', cmap='Greens', ax=ax,
            linewidths=0.5, linecolor='#21262d',
            annot_kws={'size': 14, 'color': 'white'},
            cbar_kws={'shrink': 0.8},
        )
        ax.set_title('Confusion Matrix — CICIDS2017',
                     color='#00ff41', fontsize=13, pad=12)
        ax.set_xlabel('Predicted Label', color='#c9d1d9')
        ax.set_ylabel('True Label',      color='#c9d1d9')
        ax.set_xticklabels(['Benign', 'Attack'], color='#8b949e')
        ax.set_yticklabels(['Benign', 'Attack'], color='#8b949e', rotation=0)

        path = os.path.join(Config.OUTPUT_DIR, 'confusion_matrix.png')
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='#0d1117')
        plt.close()
        print(f"[✓] Confusion matrix   -> {path}")

    @staticmethod
    def roc_curve(y_true: list, y_score: list) -> None:
        try:
            fpr_vals, tpr_vals, _ = roc_curve(y_true, y_score)
            auc = roc_auc_score(y_true, y_score)
        except Exception as e:
            print(f"[!] ROC curve error: {e}")
            return

        fig, ax = plt.subplots(figsize=(7, 5))
        ax.plot(fpr_vals, tpr_vals, color='#00ff41', linewidth=2,
                label=f'IPS Detector (AUC = {auc:.3f})')
        ax.plot([0, 1], [0, 1], color='#447744', linewidth=1,
                linestyle='--', label='Random classifier')
        ax.fill_between(fpr_vals, tpr_vals, alpha=0.1, color='#00ff41')
        ax.set_title('ROC Curve — CICIDS2017', color='#00ff41', fontsize=13)
        ax.set_xlabel('False Positive Rate')
        ax.set_ylabel('True Positive Rate (Recall)')
        ax.legend(loc='lower right', facecolor='#0d1117',
                  edgecolor='#30363d', labelcolor='#c9d1d9')
        ax.set_xlim([0, 1])
        ax.set_ylim([0, 1.02])
        ax.grid(True, alpha=0.3)

        path = os.path.join(Config.OUTPUT_DIR, 'roc_curve.png')
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='#0d1117')
        plt.close()
        print(f"[✓] ROC curve          -> {path}")

    @staticmethod
    def precision_recall_curve(y_true: list, y_score: list) -> None:
        try:
            prec_vals, rec_vals, _ = precision_recall_curve(y_true, y_score)
            ap = average_precision_score(y_true, y_score)
        except Exception as e:
            print(f"[!] PR curve error: {e}")
            return

        fig, ax = plt.subplots(figsize=(7, 5))
        ax.plot(rec_vals, prec_vals, color='#ffaa00', linewidth=2,
                label=f'IPS Detector (AP = {ap:.3f})')
        ax.fill_between(rec_vals, prec_vals, alpha=0.1, color='#ffaa00')
        ax.set_title('Precision-Recall Curve — CICIDS2017',
                     color='#00ff41', fontsize=13)
        ax.set_xlabel('Recall')
        ax.set_ylabel('Precision')
        ax.legend(loc='upper right', facecolor='#0d1117',
                  edgecolor='#30363d', labelcolor='#c9d1d9')
        ax.set_xlim([0, 1])
        ax.set_ylim([0, 1.02])
        ax.grid(True, alpha=0.3)

        path = os.path.join(Config.OUTPUT_DIR, 'precision_recall_curve.png')
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='#0d1117')
        plt.close()
        print(f"[✓] Precision-recall   -> {path}")

# ══════════════════════════════════════════════════════════════════════════════
# Evaluator (orchestrator)
# ══════════════════════════════════════════════════════════════════════════════

class Evaluator:
    """
    Orchestrates the full evaluation pipeline.
    Uses to_dict('records') instead of iterrows() for ~5x speed improvement.
    """

    def __init__(self):
        self.detector = SignatureDetector()

    def run(self, df: pd.DataFrame):
        """
        Runs detection on all rows and returns (y_true, y_pred, y_score).
        to_dict('records') converts DataFrame to list of dicts once —
        dict key lookup is significantly faster than pandas row access.
        """
        print(f"\n[*] Running detection on {len(df):,} rows...")

        records = df.to_dict('records')

        y_true  = []
        y_pred  = []
        y_score = []

        for i, row in enumerate(records):
            y_true.append(int(row['is_attack']))
            y_pred.append(self.detector.predict(row))
            y_score.append(self.detector.score(row))

            if i % 50000 == 0 and i > 0:
                print(f"    Processed {i:,} / {len(records):,} rows...")

        print(f"[✓] Detection complete")
        return y_true, y_pred, y_score

# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    os.makedirs(Config.OUTPUT_DIR,  exist_ok=True)
    os.makedirs(Config.DATASET_DIR, exist_ok=True)

    csv_files = [
        f for f in os.listdir(Config.DATASET_DIR)
        if f.endswith('.csv')
    ]

    if not csv_files:
        print(f"[✗] No CSV files found in {Config.DATASET_DIR}")
        print(f"    Download from: https://www.unb.ca/cic/datasets/ids-2017.html")
        print(f"    Place CSV files in: data/cicids2017/")
        sys.exit(1)

    print(f"[✓] Found {len(csv_files)} dataset file(s):")
    for f in csv_files:
        print(f"    - {f}")

    evaluator   = Evaluator()
    all_results = {}

    for csv_file in csv_files:
        path = os.path.join(Config.DATASET_DIR, csv_file)
        print(f"\n{'='*55}")
        print(f"  Evaluating: {csv_file}")
        print(f"{'='*55}")

        try:
            df = DatasetLoader.load(path)

            y_true, y_pred, y_score = evaluator.run(df)

            metrics = MetricsEngine.compute(y_true, y_pred, y_score)
            MetricsEngine.print_report(metrics)
            MetricsEngine.save(metrics)

            PlotEngine.confusion_matrix(y_true, y_pred)
            PlotEngine.roc_curve(y_true, y_score)
            PlotEngine.precision_recall_curve(y_true, y_score)

            all_results[csv_file] = metrics

        except Exception as e:
            print(f"[✗] Error evaluating {csv_file}: {e}")
            import traceback
            traceback.print_exc()

    results_path = os.path.join(Config.OUTPUT_DIR, 'all_results.json')
    with open(results_path, 'w') as f:
        json.dump(all_results, f, indent=2)

    print(f"\n[✓] All results saved  -> {results_path}")
    print(f"[✓] Graphs saved       -> results/evaluation/")


if __name__ == '__main__':
    main()