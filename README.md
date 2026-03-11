# 🛡️ Network Intrusion Prevention System (IPS)

A real-time Network Intrusion Prevention System that detects
and **actively blocks** attack traffic using Python and Scapy.

## Key Capability
> Detect one attack packet → block the source IP instantly

## Technology Stack
| Component | Technology |
|---|---|
| Packet Interception | Scapy |
| Block Engine | Scapy packet drop |
| Rate Limiting | Token bucket algorithm |
| Dashboard | Flask + SocketIO |
| Language | Python 3.11 |

## Status
🚧 Under active development

## Setup
```bash
git clone https://github.com/migdad-latif/network-ips.git
cd network-ips
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python src\dashboard\app.py
```