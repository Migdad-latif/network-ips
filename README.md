# Network Intrusion Prevention System

A real-time Network IPS built in Python using Scapy for packet capture, Windows Firewall for active blocking, and a Flask/SocketIO SIEM dashboard for live monitoring.

Evaluated against the CICIDS2017 dataset achieving **F1=0.97, AUC=0.96, FPR=0.06**.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Scapy](https://img.shields.io/badge/Scapy-2.5-green)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey)
![Docker](https://img.shields.io/badge/Docker-Compose-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Features

- **Live packet capture** via Scapy with promiscuous mode sniffing
- **Signature-based detection** — port scan, SYN flood, DNS amplification, sensitive port access, rate limiting
- **Active blocking** via Windows Firewall (netsh) with dual-direction inbound + outbound rules
- **Auto-unblock** after configurable TTL (default 5 minutes)
- **Rule verification** — confirms firewall rules are active after creation
- **Stale rule cleanup** on startup removes leftover rules from previous sessions
- **SIEM dashboard** — real-time alerts, packet feed, blocked IP panel, charts, manual block/unblock controls
- **Async packet queue** — decoupled sniffer and detection threads, plugin-based architecture
- **Docker lab** — attacker/victim/monitor containers for isolated testing
- **CICIDS2017 evaluation** — full metrics pipeline with confusion matrix, ROC, and PR curves
- **Performance benchmark** — throughput, latency distribution, CPU/memory profiling

---

## Evaluation Results — CICIDS2017

Evaluated on the Friday Afternoon PortScan file (286,467 flows).  
Thresholds derived empirically from flow-level feature analysis.

| Metric | Value |
|---|---|
| Precision | **0.9531** |
| Recall | **0.9914** |
| F1 Score | **0.9719** |
| False Positive Rate | **0.0608** |
| False Negative Rate | 0.0086 |
| AUC-ROC | **0.9617** |
| TP | 157,562 |
| FP | 7,749 |
| TN | 119,788 |
| FN | 1,368 |

**Key finding:** PortScan probes have near-zero mean payload (≤5B) AND very short flow duration (≤500µs) — these two features together provide clean separation from benign traffic.

---

## Performance Benchmark

Measured on synthetic traffic (50,000 packet pool, 5s sustained load).

| Metric | Value |
|---|---|
| Throughput | **183,935 pps** |
| Latency p50 | 5.5 µs |
| Latency p95 | 5.8 µs |
| Latency p99 | 6.5 µs |
| CPU usage | 6.1% |
| Memory | 210 MB |

---

## Architecture

```
Network Interface
      │
      ▼ (Scapy promiscuous sniff)
┌─────────────────────┐
│  Async Packet Queue │  ← sniffer thread enqueues, never blocks
└─────────┬───────────┘
          │
          ▼ (worker thread)
┌─────────────────────┐
│   Plugin Registry   │
│  ├ PortScanPlugin   │
│  ├ SynFloodPlugin   │
│  ├ DnsAmpPlugin     │
│  ├ SensitivePort    │
│  └ RateLimitPlugin  │
└─────────┬───────────┘
          │ Alert
          ▼
┌─────────────────────┐     ┌──────────────────────┐
│    Block Engine     │────►│  Windows Firewall     │
│  (auto-unblock TTL) │     │  netsh IN + OUT rules │
└─────────┬───────────┘     └──────────────────────┘
          │ SocketIO
          ▼
┌─────────────────────┐
│   SIEM Dashboard    │  http://localhost:5001
│  (Flask + SocketIO) │
└─────────────────────┘
```

---

## Project Structure

```
network-ips/
├── src/
│   ├── packet_interceptor.py   # Scapy capture + detection
│   ├── block_engine.py         # Firewall rule management
│   ├── rate_limiter.py         # Token bucket rate limiter
│   ├── async_engine.py         # Async queue + plugin architecture
│   ├── evaluator.py            # CICIDS2017 dataset evaluation
│   ├── benchmark.py            # Performance benchmarking
│   └── dashboard/
│       ├── app.py              # Flask + SocketIO server
│       └── ips.html            # SIEM dashboard UI
├── docker/
│   ├── attacker/               # Kali Linux — nmap + hping3
│   ├── victim/                 # Flask HTTP server + monitor
│   └── monitor/                # Scapy-based traffic monitor
├── docker-compose.yml
├── notebooks/
│   └── evaluation.ipynb        # Interactive evaluation notebook
├── data/
│   └── cicids2017/             # Place CICIDS2017 CSV files here
├── results/
│   ├── evaluation/             # Confusion matrix, ROC, PR curves
│   └── benchmark/              # Latency and throughput plots
├── logs/
│   └── firewall.log            # Timestamped firewall rule log
├── docs/
│   └── threat_model.md         # STRIDE threat model
└── requirements.txt
```

---

## Quick Start

### Requirements

- Windows 10/11 (netsh firewall blocking is Windows-only)
- Python 3.11+
- Npcap (for Scapy packet capture)
- Administrator privileges (required for Scapy and netsh)

### Installation

```cmd
git clone https://github.com/migdad-latif/network-ips.git
cd network-ips
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### Run the IPS dashboard

```cmd
# Must be run as Administrator
python src\dashboard\app.py
```

Open **http://localhost:5001** in your browser.

### Run dataset evaluation

```cmd
# Place CICIDS2017 CSV in data/cicids2017/
python src\evaluator.py
```

### Run performance benchmark

```cmd
python src\benchmark.py
```

### Run Docker lab

```cmd
docker compose up
```

Watch the monitor container detect port scans and SYN floods in real time.

### Run Jupyter notebook

```cmd
jupyter notebook notebooks\evaluation.ipynb
```

---

## Detection Signatures

| Attack Type | Method | Threshold |
|---|---|---|
| Port Scan | Unique destination ports per source IP | ≥10 unique ports |
| SYN Flood | SYN packet rate + avg packet size | ≥20 pkts, avg ≤100B |
| DNS Amplification | UDP/53 packet count per source | ≥10 DNS queries |
| Sensitive Port Access | Destination port in sensitive set | Any access to 22,23,25,445,3306,3389 |
| Rate Limit | Packets per second per source | ≥50 pps |

---

## Improvements

| # | Improvement | Status |
|---|---|---|
| 1 | Dual-direction firewall blocking with rule verification | ✅ |
| 2 | CICIDS2017 dataset evaluation (F1=0.97, AUC=0.96) | ✅ |
| 3 | Performance benchmark (183k pps, p99=6.5µs) | ✅ |
| 4 | Docker Compose lab environment | ✅ |
| 5 | STRIDE threat model (20 threats, CVSS scores) | ✅ |
| 6 | Async packet queue + plugin-based signatures | ✅ |
| 7 | Jupyter evaluation notebook | ✅ |

---

## Threat Model

A full STRIDE threat model is available at [`docs/threat_model.md`](docs/threat_model.md).

Top risks identified:

| Threat | CVSS | Severity |
|---|---|---|
| Administrator process compromise | 9.0 | Critical |
| Unauthenticated dashboard | 8.1 | High |
| IP rotation evasion | 7.5 | High |
| Source IP spoofing | 7.5 | High |

---

## Dataset

This project uses the **CICIDS2017** dataset from the Canadian Institute for Cybersecurity.

Download: https://www.unb.ca/cic/datasets/ids-2017.html  
Place CSV files in: `data/cicids2017/`

> Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. ICISSP.

---

## License

MIT License — see [LICENSE](LICENSE) for details.