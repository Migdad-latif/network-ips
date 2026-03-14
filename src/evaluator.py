"""
evaluator.py
------------
Multi-class IPS evaluation against CICIDS2017.

Classes:
  0 = BENIGN
  1 = PORT_SCAN
  2 = DDOS
  3 = BOTNET

Outputs:
  results/evaluation/confusion_matrix.png        (4 x 4)
  results/evaluation/roc_curve.png               (binary: attack vs benign)
  results/evaluation/precision_recall_curve.png  (binary: attack vs benign)
  results/evaluation/per_class_f1.png            (bar chart per class)
  results/evaluation/metrics_report.txt
  results/evaluation/multi_attack_benchmark.csv
  results/evaluation/all_results.json
"""

import os
import sys
import json
import csv
from enum import IntEnum
from datetime import datetime
from typing import Dict, List, Tuple

import pandas as pd
import numpy as np

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    average_precision_score,
)

# ── Paths ─────────────────────────────────────────────────────────────────────

BASE_DIR    = os.path.join(os.path.dirname(__file__), "..")
OUTPUT_DIR  = os.path.join(BASE_DIR, "results", "evaluation")
DATASET_DIR = os.path.join(BASE_DIR, "data", "cicids2017")

os.makedirs(OUTPUT_DIR,  exist_ok=True)
os.makedirs(DATASET_DIR, exist_ok=True)

# ── Dark theme ────────────────────────────────────────────────────────────────

plt.rcParams.update({
    "figure.facecolor": "#0d1117",
    "axes.facecolor"  : "#0d1117",
    "axes.edgecolor"  : "#30363d",
    "axes.labelcolor" : "#c9d1d9",
    "text.color"      : "#c9d1d9",
    "xtick.color"     : "#8b949e",
    "ytick.color"     : "#8b949e",
    "grid.color"      : "#21262d",
    "grid.alpha"      : 0.5,
    "font.family"     : "monospace",
})

# ── AttackType ────────────────────────────────────────────────────────────────

class AttackType(IntEnum):
    """
    Four-class taxonomy for the IPS detector and evaluator.

    The integer values are used as y_true / y_pred throughout so that
    sklearn metrics and numpy indexing work without any conversion.
    """
    BENIGN    = 0
    PORT_SCAN = 1
    DDOS      = 2
    BOTNET    = 3


# Human-readable label for each class integer.
ATTACK_NAMES: Dict[int, str] = {
    AttackType.BENIGN    : "BENIGN",
    AttackType.PORT_SCAN : "PORT_SCAN",
    AttackType.DDOS      : "DDOS",
    AttackType.BOTNET    : "BOTNET",
}

# Per-class colours used in bar charts.
CLASS_COLORS: Dict[int, str] = {
    AttackType.BENIGN    : "#009922",
    AttackType.PORT_SCAN : "#00ff41",
    AttackType.DDOS      : "#ff3333",
    AttackType.BOTNET    : "#aa44ff",
}

# CICIDS2017 label string → AttackType.
# Keys are stripped and lowercased before lookup.
LABEL_MAP: Dict[str, AttackType] = {
    # BENIGN
    "benign"           : AttackType.BENIGN,

    # PORT_SCAN
    "portscan"         : AttackType.PORT_SCAN,
    "ftp-patator"      : AttackType.PORT_SCAN,
    "ssh-patator"      : AttackType.PORT_SCAN,

    # DDOS — flood / volumetric
    "ddos"             : AttackType.DDOS,
    "dos hulk"         : AttackType.DDOS,
    "dos goldeneye"    : AttackType.DDOS,
    "dos slowloris"    : AttackType.DDOS,
    "dos slowhttptest" : AttackType.DDOS,
    "heartbleed"       : AttackType.DDOS,

    # BOTNET — C2 / covert channel
    "bot"              : AttackType.BOTNET,
    "infiltration"     : AttackType.BOTNET,
}

# Any attack label not in LABEL_MAP falls back to PORT_SCAN so no
# malicious flow is silently treated as benign.
_FALLBACK_ATTACK_CLASS = AttackType.PORT_SCAN

# ── Config ────────────────────────────────────────────────────────────────────

class Config:
    # PORT_SCAN detection
    SCAN_MAX_PAYLOAD_BYTES    = 5      # fwd_pkt_mean <= this  → tiny probe
    SCAN_MAX_DURATION_US      = 500    # flow_duration <= this → sub-millisecond
    PORTSCAN_PACKET_THRESHOLD = 100    # fwd_packets >= this   → high-volume scan

    # DDOS detection
    DDOS_MIN_PPS              = 500    # packets/s floor for flood
    DDOS_MAX_AVG_SIZE         = 80     # flood packets carry little payload
    DDOS_MAX_DURATION_US      = 5_000_000   # 5 s — burst floods are short

    # BOTNET / C2 detection
    BOTNET_MIN_PPS            = 5      # sustained but not flood-level
    BOTNET_MAX_PPS            = 200    # above this it looks like DDoS
    BOTNET_MIN_FWD_PKTS       = 10     # enough to establish a C2 pattern
    BOTNET_MAX_FWD_PKTS       = 300    # C2 sessions are moderate

    # Shared
    DNS_AMP_PACKET_THRESHOLD  = 50
    SENSITIVE_PORTS           = {22, 23, 25, 445, 3306, 3389}


# Legacy dict kept so packet_interceptor.py doesn't need changes.
THRESHOLDS = {
    "port_scan_unique_ports" : Config.PORTSCAN_PACKET_THRESHOLD,
    "syn_flood_packet_count" : Config.DDOS_MIN_PPS,
    "syn_flood_max_avg_size" : Config.DDOS_MAX_AVG_SIZE,
    "dns_amp_count"          : Config.DNS_AMP_PACKET_THRESHOLD,
    "rate_limit_pps"         : 1000,
}

# ── Column map ────────────────────────────────────────────────────────────────

COLUMN_MAP = {
    "Source IP"                   : "src_ip",
    "Destination IP"              : "dst_ip",
    "Source Port"                 : "src_port",
    "Destination Port"            : "dst_port",
    "Protocol"                    : "protocol",
    "Total Length of Fwd Packets" : "fwd_bytes",
    "Fwd Packet Length Mean"      : "fwd_pkt_mean",
    "Flow Duration"               : "flow_duration",
    "Total Fwd Packets"           : "fwd_packets",
    "Total Backward Packets"      : "bwd_packets",
    "Flow Packets/s"              : "flow_pps",
    "Label"                       : "label",
}

# ── DatasetLoader ─────────────────────────────────────────────────────────────

class DatasetLoader:
    """
    Loads one CICIDS2017 CSV and maps each row to a 4-class label.

    New columns produced:
      attack_type   — raw stripped label string (kept for debugging/tracing)
      attack_class  — AttackType int  (0–3), used as y_true
      is_attack     — binary: 0 = BENIGN, 1 = any attack  (ROC / PR curves)
    """

    @staticmethod
    def load(csv_path: str) -> pd.DataFrame:
        print(f"[*] Loading {os.path.basename(csv_path)}")

        df = pd.read_csv(csv_path, low_memory=False)
        df.columns = df.columns.str.strip()

        rename_map = {orig: clean
                      for orig, clean in COLUMN_MAP.items()
                      if orig in df.columns}
        df = df.rename(columns=rename_map)

        if "label" not in df.columns:
            raise ValueError("Dataset missing 'Label' column")

        # Raw label kept for the benchmark's attack_type column
        df["attack_type"] = df["label"].str.strip()

        # Multi-class ground truth
        df["attack_class"] = df["attack_type"].apply(
            DatasetLoader._map_label).astype(int)

        # Binary ground truth for ROC / PR curves
        df["is_attack"] = (df["attack_class"] != int(AttackType.BENIGN)).astype(int)

        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna(subset=["attack_class"])

        total = len(df)
        print(f"[+] Rows: {total:,}")
        for cls in AttackType:
            n = int((df["attack_class"] == int(cls)).sum())
            print(f"    {ATTACK_NAMES[cls]:<12}: {n:>8,}  ({n / total * 100:.1f}%)")

        return df

    @staticmethod
    def _map_label(raw: str) -> int:
        key = raw.strip().lower()
        if key == "benign":
            return int(AttackType.BENIGN)
        return int(LABEL_MAP.get(key, _FALLBACK_ATTACK_CLASS))


# ── SignatureDetector ─────────────────────────────────────────────────────────

class SignatureDetector:
    """
    Multi-class per-flow signature detector.

    predict() returns an AttackType int (0–3).

    Detection priority (highest severity first):
      DDOS > PORT_SCAN > BOTNET > BENIGN

    DDOS is checked before PORT_SCAN because high-volume DDoS flows
    also exhibit high packet counts that would otherwise match PORT_SCAN.
    """

    def predict(self, row: Dict) -> int:
        dst_port      = int(row.get("dst_port", 0))
        proto         = int(row.get("protocol", 0))
        fwd_pkts      = int(row.get("fwd_packets", 1) or 1)
        bwd_pkts      = int(row.get("bwd_packets", 0) or 0)
        pps           = float(row.get("flow_pps", 0) or 0)
        flow_duration = float(row.get("flow_duration", 1) or 1)
        size          = float(row.get("fwd_pkt_mean", 100) or 100)

        if np.isnan(size):          size          = 100.0
        if np.isnan(pps):           pps           = 0.0
        if np.isnan(flow_duration): flow_duration = 1.0

        # ── DDOS ─────────────────────────────────────────────────────────
        # Extremely high pps + tiny packets + target never responded.
        if (pps  >= Config.DDOS_MIN_PPS and
                size <= Config.DDOS_MAX_AVG_SIZE and
                bwd_pkts == 0):
            return int(AttackType.DDOS)

        # DNS amplification is volumetric — classify as DDoS.
        if (proto == 17 and dst_port == 53 and
                fwd_pkts >= Config.DNS_AMP_PACKET_THRESHOLD):
            return int(AttackType.DDOS)

        # ── PORT_SCAN ─────────────────────────────────────────────────────
        # Primary: near-zero payload AND sub-millisecond flow (single probe).
        if (size     <= Config.SCAN_MAX_PAYLOAD_BYTES and
                flow_duration <= Config.SCAN_MAX_DURATION_US):
            return int(AttackType.PORT_SCAN)

        # Fallback: very high forward-packet count regardless of duration.
        if fwd_pkts >= Config.PORTSCAN_PACKET_THRESHOLD:
            return int(AttackType.PORT_SCAN)

        # ── BOTNET / C2 ───────────────────────────────────────────────────
        # Targets management ports with a sustained, moderate packet rate.
        # A pure scan would have no response; a flood would exceed BOTNET_MAX_PPS.
        if dst_port in Config.SENSITIVE_PORTS:
            sustained = Config.BOTNET_MIN_PPS  <= pps      <= Config.BOTNET_MAX_PPS
            moderate  = Config.BOTNET_MIN_FWD_PKTS <= fwd_pkts <= Config.BOTNET_MAX_FWD_PKTS
            no_reply  = bwd_pkts == 0

            if sustained and moderate:
                return int(AttackType.BOTNET)
            # Single-direction traffic to a sensitive port with enough packets
            # to rule out a one-off connection attempt.
            if no_reply and fwd_pkts >= Config.BOTNET_MIN_FWD_PKTS:
                return int(AttackType.BOTNET)

        # ── BENIGN ────────────────────────────────────────────────────────
        return int(AttackType.BENIGN)

    def score(self, row: Dict) -> float:
        """
        Binary confidence score [0, 1] used for ROC / PR curve plotting only.
        Higher → more likely to be any kind of attack.
        """
        dst_port      = int(row.get("dst_port", 0))
        fwd_pkts      = int(row.get("fwd_packets", 1) or 1)
        pps           = float(row.get("flow_pps", 0) or 0)
        flow_duration = float(row.get("flow_duration", 1) or 1)
        fwd_pkt_mean  = float(row.get("fwd_pkt_mean", 100) or 100)

        if np.isnan(pps):           pps           = 0.0
        if np.isnan(fwd_pkt_mean):  fwd_pkt_mean  = 100.0
        if np.isnan(flow_duration): flow_duration = 1.0

        s  = max(0.0, 1.0 - fwd_pkt_mean  / 100.0)   * 0.50  # small payload → attack
        s += max(0.0, 1.0 - flow_duration / 10_000.0) * 0.35  # short duration → attack
        s += min(fwd_pkts / Config.PORTSCAN_PACKET_THRESHOLD, 1.0) * 0.10
        if dst_port in Config.SENSITIVE_PORTS:
            s += 0.05

        return min(s, 1.0)


# ── Evaluator ─────────────────────────────────────────────────────────────────

class Evaluator:
    """
    Replays all dataset rows through the multi-class detector.

      y_true   — AttackType ints from attack_class column
      y_pred   — AttackType ints returned by SignatureDetector.predict()
      y_score  — binary confidence floats from SignatureDetector.score()
      labels   — raw attack_type strings (for traceability / benchmark)
    """

    def __init__(self):
        self.detector = SignatureDetector()
        self.y_true  : List[int]   = []
        self.y_pred  : List[int]   = []
        self.y_score : List[float] = []
        self.labels  : List[str]   = []

    def run(self, df: pd.DataFrame) -> Tuple[List[int], List[int], List[float]]:
        records = df.to_dict("records")
        print(f"[*] Classifying {len(records):,} flows...")

        self.y_true  = []
        self.y_pred  = []
        self.y_score = []
        self.labels  = []

        for i, row in enumerate(records):
            self.y_true.append(int(row["attack_class"]))
            self.y_pred.append(self.detector.predict(row))
            self.y_score.append(self.detector.score(row))
            self.labels.append(str(row["attack_type"]))

            if i % 50_000 == 0 and i > 0:
                print(f"    {i:,} / {len(records):,}")

        print("[+] Classification complete")
        return self.y_true, self.y_pred, self.y_score

    # ── Convenience wrappers (call order matches __main__ block) ──────────

    def compute_metrics(self) -> dict:
        m = MetricsEngine.compute(self.y_true, self.y_pred, self.y_score)
        MetricsEngine.print_report(m)
        MetricsEngine.save(m, os.path.join(OUTPUT_DIR, "metrics_report.txt"))
        return m

    def plot_confusion_matrix(self) -> None:
        PlotEngine.confusion_matrix(
            self.y_true, self.y_pred,
            os.path.join(OUTPUT_DIR, "confusion_matrix.png"))

    def plot_roc_curve(self) -> None:
        PlotEngine.roc_curve(
            self.y_true, self.y_score,
            os.path.join(OUTPUT_DIR, "roc_curve.png"))

    def plot_precision_recall_curve(self) -> None:
        PlotEngine.precision_recall_curve(
            self.y_true, self.y_score,
            os.path.join(OUTPUT_DIR, "precision_recall_curve.png"))

    def plot_per_class_f1(self, benchmark_results: List[dict]) -> None:
        PlotEngine.per_class_f1(
            benchmark_results,
            os.path.join(OUTPUT_DIR, "per_class_f1.png"))


# ── MetricsEngine ─────────────────────────────────────────────────────────────

class MetricsEngine:
    """
    Multi-class metrics with a binary fallback for FPR / FNR / AUC.

    Overall precision / recall / F1 use macro averaging so that rare
    classes (e.g. BOTNET) are not drowned out by the majority class.
    Binary FPR / FNR / AUC-ROC collapse all four classes to attack vs benign.
    """

    @staticmethod
    def compute(y_true: List[int], y_pred: List[int],
                y_score: List[float]) -> dict:

        label_ids = list(range(len(AttackType)))

        # ── Macro averages ────────────────────────────────────────────────
        prec_macro = precision_score(y_true, y_pred, labels=label_ids,
                                     average="macro", zero_division=0)
        rec_macro  = recall_score(y_true, y_pred, labels=label_ids,
                                  average="macro", zero_division=0)
        f1_macro   = f1_score(y_true, y_pred, labels=label_ids,
                              average="macro", zero_division=0)

        # ── Per-class arrays ──────────────────────────────────────────────
        prec_arr = precision_score(y_true, y_pred, labels=label_ids,
                                   average=None, zero_division=0)
        rec_arr  = recall_score(y_true, y_pred, labels=label_ids,
                                average=None, zero_division=0)
        f1_arr   = f1_score(y_true, y_pred, labels=label_ids,
                            average=None, zero_division=0)

        per_class: Dict[str, dict] = {}
        y_arr = np.array(y_true)
        for cls in AttackType:
            i = int(cls)
            per_class[ATTACK_NAMES[cls]] = {
                "precision" : round(float(prec_arr[i]), 4),
                "recall"    : round(float(rec_arr[i]),  4),
                "f1_score"  : round(float(f1_arr[i]),   4),
                "support"   : int((y_arr == i).sum()),
            }

        # ── Binary FPR / FNR / AUC ────────────────────────────────────────
        y_bin_true = [1 if t > 0 else 0 for t in y_true]
        y_bin_pred = [1 if p > 0 else 0 for p in y_pred]

        cm         = confusion_matrix(y_bin_true, y_bin_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        fnr = fn / (fn + tp) if (fn + tp) else 0.0

        try:
            auc = roc_auc_score(y_bin_true, y_score)
        except Exception:
            auc = 0.0

        return {
            "macro_precision" : round(prec_macro, 4),
            "macro_recall"    : round(rec_macro,  4),
            "macro_f1"        : round(f1_macro,   4),
            "binary_fpr"      : round(fpr, 4),
            "binary_fnr"      : round(fnr, 4),
            "auc_roc"         : round(auc, 4),
            "binary_tp"       : int(tp),
            "binary_fp"       : int(fp),
            "binary_tn"       : int(tn),
            "binary_fn"       : int(fn),
            "total_samples"   : len(y_true),
            "per_class"       : per_class,
        }

    @staticmethod
    def print_report(m: dict) -> None:
        w = 60
        print("\n" + "=" * w)
        print("  MULTI-CLASS EVALUATION — CICIDS2017")
        print("=" * w)
        print(f"  Total flows     : {m['total_samples']:,}")
        print(f"  Macro Precision : {m['macro_precision']:.4f}")
        print(f"  Macro Recall    : {m['macro_recall']:.4f}")
        print(f"  Macro F1        : {m['macro_f1']:.4f}")
        print(f"  Binary FPR      : {m['binary_fpr']:.4f}")
        print(f"  Binary FNR      : {m['binary_fnr']:.4f}")
        print(f"  AUC-ROC         : {m['auc_roc']:.4f}")
        print("-" * w)
        print(f"  {'Class':<14} {'Precision':>10} {'Recall':>8} "
              f"{'F1':>8} {'Support':>9}")
        print("  " + "-" * (w - 2))
        for name, v in m["per_class"].items():
            print(f"  {name:<14} {v['precision']:>10.4f} {v['recall']:>8.4f} "
                  f"{v['f1_score']:>8.4f} {v['support']:>9,}")
        print("=" * w + "\n")

    @staticmethod
    def save(m: dict, path: str) -> None:
        with open(path, "w") as f:
            f.write("NETWORK IPS — MULTI-CLASS EVALUATION REPORT\n")
            f.write(f"Generated : {datetime.now().isoformat()}\n")
            f.write(f"Classes   : {list(ATTACK_NAMES.values())}\n")
            f.write("=" * 60 + "\n\n")
            for key in ("macro_precision", "macro_recall", "macro_f1",
                        "binary_fpr", "binary_fnr", "auc_roc",
                        "binary_tp", "binary_fp", "binary_tn", "binary_fn",
                        "total_samples"):
                f.write(f"{key:<20}: {m[key]}\n")
            f.write("\nPer-class:\n")
            for name, v in m["per_class"].items():
                f.write(f"  {name:<14}: P={v['precision']:.4f}  "
                        f"R={v['recall']:.4f}  F1={v['f1_score']:.4f}  "
                        f"N={v['support']:,}\n")
        print(f"[+] Metrics report     -> {path}")


# ── MultiAttackBenchmark ──────────────────────────────────────────────────────

class MultiAttackBenchmark:
    """
    Per-class precision, recall, F1, flow count and detection count.

    Uses the same 4-class y_true / y_pred arrays produced by Evaluator.run()
    so no extra passes over the dataset are needed.
    """

    def __init__(self, y_true: List[int], y_pred: List[int]):
        self.y_true  = y_true
        self.y_pred  = y_pred
        self.results : List[dict] = []

    def compute(self) -> List[dict]:
        label_ids = list(range(len(AttackType)))
        prec_arr  = precision_score(self.y_true, self.y_pred, labels=label_ids,
                                    average=None, zero_division=0)
        rec_arr   = recall_score(self.y_true, self.y_pred, labels=label_ids,
                                 average=None, zero_division=0)
        f1_arr    = f1_score(self.y_true, self.y_pred, labels=label_ids,
                             average=None, zero_division=0)
        y_arr  = np.array(self.y_true)
        yp_arr = np.array(self.y_pred)

        self.results = []
        for cls in AttackType:
            i = int(cls)
            self.results.append({
                "attack_class" : ATTACK_NAMES[cls],
                "flows"        : int((y_arr == i).sum()),
                "detected"     : int(((y_arr == i) & (yp_arr == i)).sum()),
                "precision"    : round(float(prec_arr[i]), 4),
                "recall"       : round(float(rec_arr[i]),  4),
                "f1_score"     : round(float(f1_arr[i]),   4),
            })
        return self.results

    def print_table(self) -> None:
        if not self.results:
            print("[!] Call compute() first"); return
        hdr = (f"{'Class':<14} {'Flows':>8} {'Detected':>9} "
               f"{'Precision':>10} {'Recall':>8} {'F1':>8}")
        bar = "=" * len(hdr)
        print(f"\n{bar}")
        print("  MULTI-CLASS BENCHMARK")
        print(bar)
        print(hdr)
        print("-" * len(hdr))
        for r in self.results:
            print(f"  {r['attack_class']:<12} {r['flows']:>8,} {r['detected']:>9,} "
                  f"{r['precision']:>10.4f} {r['recall']:>8.4f} {r['f1_score']:>8.4f}")
        print(bar + "\n")

    def save_csv(self, path: str) -> None:
        fields = ["attack_class", "flows", "detected",
                  "precision", "recall", "f1_score"]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(self.results)
        print(f"[+] Benchmark CSV      -> {path}")


# ── PlotEngine ────────────────────────────────────────────────────────────────

class PlotEngine:
    """All plots as static methods so Jupyter notebooks can call them directly."""

    _CLASS_LABELS = [ATTACK_NAMES[c] for c in AttackType]   # display order

    @staticmethod
    def confusion_matrix(y_true: List[int], y_pred: List[int],
                         path: str) -> None:
        """4 × 4 confusion matrix labelled with class names."""
        label_ids = list(range(len(AttackType)))
        cm = confusion_matrix(y_true, y_pred, labels=label_ids)

        fig, ax = plt.subplots(figsize=(7, 6))
        fig.patch.set_facecolor("#0d1117")

        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Greens", ax=ax,
            linewidths=0.5, linecolor="#21262d",
            annot_kws={"size": 11, "color": "white"},
            cbar_kws={"shrink": 0.8},
            xticklabels=PlotEngine._CLASS_LABELS,
            yticklabels=PlotEngine._CLASS_LABELS,
        )

        ax.set_title("Confusion Matrix — 4-Class IPS",
                     color="#00ff41", fontsize=13, pad=12)
        ax.set_xlabel("Predicted Class", color="#c9d1d9")
        ax.set_ylabel("True Class",      color="#c9d1d9")
        ax.tick_params(colors="#8b949e", labelsize=8)
        plt.xticks(rotation=20, ha="right")
        plt.yticks(rotation=0)

        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
        plt.close()
        print(f"[+] Confusion matrix   -> {path}")

    @staticmethod
    def roc_curve(y_true: List[int], y_score: List[float],
                  path: str) -> None:
        """Binary ROC curve — collapses all attack classes to 1."""
        y_bin = [1 if t > 0 else 0 for t in y_true]
        try:
            fpr_v, tpr_v, _ = roc_curve(y_bin, y_score)
            auc = roc_auc_score(y_bin, y_score)
        except Exception as e:
            print(f"[!] ROC error: {e}"); return

        fig, ax = plt.subplots(figsize=(7, 5))
        ax.plot(fpr_v, tpr_v, color="#00ff41", linewidth=2,
                label=f"IPS Detector  (AUC = {auc:.4f})")
        ax.plot([0, 1], [0, 1], color="#447744", linewidth=1,
                linestyle="--", label="Random classifier")
        ax.fill_between(fpr_v, tpr_v, alpha=0.1, color="#00ff41")
        ax.set_title("ROC Curve — Binary (Attack vs Benign)",
                     color="#00ff41", fontsize=13)
        ax.set_xlabel("False Positive Rate")
        ax.set_ylabel("True Positive Rate")
        ax.legend(loc="lower right", facecolor="#0d1117",
                  edgecolor="#30363d", labelcolor="#c9d1d9")
        ax.set_xlim([0, 1]); ax.set_ylim([0, 1.02])
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
        plt.close()
        print(f"[+] ROC curve          -> {path}")

    @staticmethod
    def precision_recall_curve(y_true: List[int], y_score: List[float],
                               path: str) -> None:
        """Binary PR curve — collapses all attack classes to 1."""
        y_bin = [1 if t > 0 else 0 for t in y_true]
        try:
            prec_v, rec_v, _ = precision_recall_curve(y_bin, y_score)
            ap = average_precision_score(y_bin, y_score)
        except Exception as e:
            print(f"[!] PR error: {e}"); return

        fig, ax = plt.subplots(figsize=(7, 5))
        ax.plot(rec_v, prec_v, color="#ffaa00", linewidth=2,
                label=f"IPS Detector  (AP = {ap:.4f})")
        ax.fill_between(rec_v, prec_v, alpha=0.1, color="#ffaa00")
        ax.set_title("Precision-Recall — Binary (Attack vs Benign)",
                     color="#00ff41", fontsize=13)
        ax.set_xlabel("Recall")
        ax.set_ylabel("Precision")
        ax.legend(loc="upper right", facecolor="#0d1117",
                  edgecolor="#30363d", labelcolor="#c9d1d9")
        ax.set_xlim([0, 1]); ax.set_ylim([0, 1.02])
        ax.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
        plt.close()
        print(f"[+] Precision-recall   -> {path}")

    @staticmethod
    def per_class_f1(benchmark_results: List[dict], path: str) -> None:
        """Horizontal bar chart — one bar per attack class, coloured by F1 tier."""
        if not benchmark_results:
            return

        classes = [r["attack_class"] for r in benchmark_results]
        f1s     = [r["f1_score"]     for r in benchmark_results]

        # Map class name → class colour; fall back to green
        bar_colors = [
            CLASS_COLORS.get(
                int(AttackType[c]) if c in AttackType.__members__ else 0,
                "#447744",
            )
            for c in classes
        ]

        fig, ax = plt.subplots(figsize=(9, max(3, len(classes) * 0.9 + 1)))
        bars = ax.barh(classes, f1s, color=bar_colors,
                       edgecolor="#30363d", height=0.55)

        for bar, val in zip(bars, f1s):
            ax.text(
                min(val + 0.01, 1.02),
                bar.get_y() + bar.get_height() / 2,
                f"{val:.4f}", va="center", ha="left",
                color="#c9d1d9", fontsize=9,
            )

        ax.axvline(0.90, color="#ffaa00", linestyle="--",
                   linewidth=1, label="0.90 target")
        ax.set_xlim([0, 1.15])
        ax.set_title("F1 Score per Class — CICIDS2017",
                     color="#00ff41", fontsize=13)
        ax.set_xlabel("F1 Score")
        ax.legend(facecolor="#0d1117", edgecolor="#30363d",
                  labelcolor="#c9d1d9")
        ax.grid(True, axis="x", alpha=0.3)

        plt.tight_layout()
        plt.savefig(path, dpi=150, bbox_inches="tight", facecolor="#0d1117")
        plt.close()
        print(f"[+] Per-class F1 plot  -> {path}")


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":

    csv_files = [f for f in os.listdir(DATASET_DIR) if f.endswith(".csv")]

    if not csv_files:
        print(f"[x] No CSV files in {DATASET_DIR}")
        print("    Download: https://www.unb.ca/cic/datasets/ids-2017.html")
        sys.exit(1)

    print(f"[+] Found {len(csv_files)} file(s): {csv_files}")

    all_results    : dict       = {}
    all_bench_rows : List[dict] = []

    for csv_file in csv_files:
        print(f"\n{'='*60}")
        print(f"  {csv_file}")
        print("=" * 60)

        path = os.path.join(DATASET_DIR, csv_file)

        try:
            df        = DatasetLoader.load(path)
            evaluator = Evaluator()
            y_true, y_pred, y_score = evaluator.run(df)

            # Metrics + terminal report + metrics_report.txt
            metrics = evaluator.compute_metrics()
            all_results[csv_file] = metrics

            # Plots
            evaluator.plot_confusion_matrix()
            evaluator.plot_roc_curve()
            evaluator.plot_precision_recall_curve()

            # Per-class benchmark
            bench = MultiAttackBenchmark(y_true, y_pred)
            bench.compute()
            bench.print_table()
            evaluator.plot_per_class_f1(bench.results)

            for row in bench.results:
                all_bench_rows.append({"source_file": csv_file, **row})

        except Exception as exc:
            print(f"[x] Error processing {csv_file}: {exc}")
            import traceback; traceback.print_exc()

    # JSON — all per-file metrics
    json_path = os.path.join(OUTPUT_DIR, "all_results.json")
    with open(json_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print(f"\n[+] JSON results       -> {json_path}")

    # CSV — combined multi-class benchmark across all files
    if all_bench_rows:
        csv_path = os.path.join(OUTPUT_DIR, "multi_attack_benchmark.csv")
        fields   = ["source_file", "attack_class", "flows", "detected",
                    "precision", "recall", "f1_score"]
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(all_bench_rows)
        print(f"[+] Benchmark CSV      -> {csv_path}")

    print(f"[+] All plots          -> {OUTPUT_DIR}/")