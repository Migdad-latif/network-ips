"""
diagnose2.py
------------
Analyses CICIDS2017 attack flows specifically to find
what features distinguish them from benign flows.
"""
import os
import pandas as pd
import numpy as np

BASE_DIR    = os.path.join(os.path.dirname(__file__), '..')
DATASET_DIR = os.path.join(BASE_DIR, 'data', 'cicids2017')

csv_files = [f for f in os.listdir(DATASET_DIR) if f.endswith('.csv')]
path      = os.path.join(DATASET_DIR, csv_files[0])

df = pd.read_csv(path, low_memory=False)
df.columns = df.columns.str.strip()

benign  = df[df['Label'].str.strip() == 'BENIGN']
attacks = df[df['Label'].str.strip() != 'BENIGN']

print(f"Attack labels: {attacks['Label'].str.strip().unique().tolist()}")
print(f"\n── bwd_pkts == 0 breakdown ──────────────────────────")
b_bwd0 = benign[benign['Total Backward Packets'] == 0]
a_bwd0 = attacks[attacks['Total Backward Packets'] == 0]
print(f"Benign  with bwd==0 : {len(b_bwd0):,} / {len(benign):,} "
      f"({len(b_bwd0)/len(benign)*100:.1f}%)")
print(f"Attacks with bwd==0 : {len(a_bwd0):,} / {len(attacks):,} "
      f"({len(a_bwd0)/len(attacks)*100:.1f}%)")

print(f"\n── Attack flow feature ranges ───────────────────────")
cols = [
    'Total Fwd Packets',
    'Total Backward Packets',
    'Fwd Packet Length Mean',
    'Flow Duration',
    'Destination Port',
    'Flow Packets/s',
]
for col in cols:
    if col in attacks.columns:
        s = pd.to_numeric(attacks[col], errors='coerce').replace(
            [np.inf, -np.inf], np.nan).dropna()
        print(f"{col[:35]:<35} "
              f"min={s.min():.1f}  "
              f"p25={s.quantile(.25):.1f}  "
              f"p50={s.median():.1f}  "
              f"p75={s.quantile(.75):.1f}  "
              f"p95={s.quantile(.95):.1f}")

print(f"\n── Benign flow feature ranges ───────────────────────")
for col in cols:
    if col in benign.columns:
        s = pd.to_numeric(benign[col], errors='coerce').replace(
            [np.inf, -np.inf], np.nan).dropna()
        print(f"{col[:35]:<35} "
              f"min={s.min():.1f}  "
              f"p25={s.quantile(.25):.1f}  "
              f"p50={s.median():.1f}  "
              f"p75={s.quantile(.75):.1f}  "
              f"p95={s.quantile(.95):.1f}")

print(f"\n── Key ratio: fwd/bwd packet ratio ──────────────────")
attacks_r = attacks.copy()
benign_r  = benign.copy()
attacks_r['fwd'] = pd.to_numeric(attacks_r['Total Fwd Packets'], errors='coerce').fillna(1)
attacks_r['bwd'] = pd.to_numeric(attacks_r['Total Backward Packets'], errors='coerce').fillna(1).clip(lower=1)
attacks_r['ratio'] = attacks_r['fwd'] / attacks_r['bwd']
benign_r['fwd']  = pd.to_numeric(benign_r['Total Fwd Packets'], errors='coerce').fillna(1)
benign_r['bwd']  = pd.to_numeric(benign_r['Total Backward Packets'], errors='coerce').fillna(1).clip(lower=1)
benign_r['ratio'] = benign_r['fwd'] / benign_r['bwd']

print(f"Attack fwd/bwd ratio  p50={attacks_r['ratio'].median():.2f}  "
      f"p75={attacks_r['ratio'].quantile(.75):.2f}  "
      f"p95={attacks_r['ratio'].quantile(.95):.2f}")
print(f"Benign fwd/bwd ratio  p50={benign_r['ratio'].median():.2f}  "
      f"p75={benign_r['ratio'].quantile(.75):.2f}  "
      f"p95={benign_r['ratio'].quantile(.95):.2f}")

print(f"\n── Flow duration comparison ─────────────────────────")
a_dur = pd.to_numeric(attacks['Flow Duration'], errors='coerce').dropna()
b_dur = pd.to_numeric(benign['Flow Duration'],  errors='coerce').dropna()
print(f"Attack duration  p50={a_dur.median():.0f}  p95={a_dur.quantile(.95):.0f}  max={a_dur.max():.0f}")
print(f"Benign duration  p50={b_dur.median():.0f}  p95={b_dur.quantile(.95):.0f}  max={b_dur.max():.0f}")