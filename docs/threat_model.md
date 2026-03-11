# Threat Model — Network Intrusion Prevention System

**Project:** Network IPS  
**Version:** 1.0  
**Date:** March 2026  
**Author:** Migdad Latif  
**Repository:** https://github.com/migdad-latif/network-ips

---

## 1. Overview

This document presents a structured threat model for the Network IPS using the STRIDE methodology. It defines the system scope, assets, trust boundaries, attack surfaces, identified threats, mitigations, and residual risks.

The IPS monitors live network traffic using Scapy, applies signature-based detection, and enforces blocking via Windows Firewall (netsh) rules with dual-direction inbound and outbound coverage.

---

## 2. System Description

### 2.1 Components

| Component | Description |
|---|---|
| `packet_interceptor.py` | Scapy sniff loop — captures and analyses live packets |
| `block_engine.py` | Manages blocked IP state, firewall rules, auto-unblock |
| `rate_limiter.py` | Token bucket rate limiter per source IP |
| `dashboard/app.py` | Flask + SocketIO SIEM dashboard (port 5001) |
| `dashboard/ips.html` | Real-time browser UI — alerts, packet feed, manual controls |
| `evaluator.py` | Offline CICIDS2017 dataset evaluation |
| `benchmark.py` | Performance benchmarking module |
| Docker lab | Attacker / victim / monitor containers for live testing |

### 2.2 Data Flows

```
Internet / LAN
      │
      ▼
[Network Interface]
      │  (Scapy promiscuous sniff)
      ▼
[PacketInterceptor] ──── detects attack ────► [BlockEngine]
      │                                              │
      │                                    netsh firewall rules
      │                                    (inbound + outbound)
      ▼
[SocketIO] ──────────────────────────────► [SIEM Dashboard]
                                           (browser, port 5001)
```

### 2.3 Trust Boundaries

| Boundary | Description |
|---|---|
| TB1 | External network → Host NIC |
| TB2 | Scapy capture → Python process memory |
| TB3 | Python process → Windows Firewall (netsh) |
| TB4 | Flask server → Browser dashboard |
| TB5 | Dashboard user → Manual block/unblock controls |

---

## 3. Assets

| Asset | Sensitivity | Impact if Compromised |
|---|---|---|
| Blocked IP list (`blocked_ips.json`) | Medium | Attacker could remove their own block |
| Block history (`block_history.json`) | Medium | Forensic evidence tampered |
| Firewall rules (netsh) | High | All blocking bypassed |
| Dashboard (port 5001) | High | Unauthorised block/unblock commands |
| Detection thresholds (`Config`) | Medium | Tuned to evade detection |
| SIEM alert feed | Medium | Alerts suppressed or flooded |

---

## 4. STRIDE Threat Analysis

### 4.1 Spoofing

| ID | Threat | Component | Likelihood | Impact |
|---|---|---|---|---|
| S1 | Attacker spoofs source IP to avoid blocking | PacketInterceptor | High | High |
| S2 | Attacker spoofs trusted internal IP to bypass whitelist | BlockEngine | Medium | High |
| S3 | Spoofed packets cause legitimate IPs to be blocked (IP spoofing DoS) | BlockEngine | Medium | High |

**Mitigations:**
- S1/S2: Implement ingress filtering (RFC 2827) at the network boundary
- S3: Rate-limit new block actions; require threshold confirmation before blocking; alert on unusual whitelist IP activity

---

### 4.2 Tampering

| ID | Threat | Component | Likelihood | Impact |
|---|---|---|---|---|
| T1 | Attacker modifies `blocked_ips.json` to remove their block | BlockEngine | Low | High |
| T2 | Attacker modifies detection thresholds in `evaluator.py` / `Config` | Evaluator | Low | High |
| T3 | Packet payload crafted to exploit Scapy parsing bugs | PacketInterceptor | Low | Medium |
| T4 | Dashboard HTTP traffic tampered (no TLS) | Dashboard | Medium | Medium |

**Mitigations:**
- T1: File integrity monitoring on `data/` directory; run IPS as dedicated low-privilege user
- T2: Store thresholds in read-only config; hash verification on startup
- T3: Keep Scapy updated; apply defensive NaN/type handling (already implemented)
- T4: Add TLS to Flask dashboard; bind to localhost only in production

---

### 4.3 Repudiation

| ID | Threat | Component | Likelihood | Impact |
|---|---|---|---|---|
| R1 | No audit trail for manual block/unblock actions via dashboard | Dashboard | Medium | Medium |
| R2 | Block history JSON can be deleted without trace | BlockEngine | Low | Medium |

**Mitigations:**
- R1: Log all dashboard actions with timestamp and source IP to `logs/firewall.log`
- R2: Append-only logging to a separate tamper-evident log file; periodic offsite backup

---

### 4.4 Information Disclosure

| ID | Threat | Component | Likelihood | Impact |
|---|---|---|---|---|
| I1 | Dashboard accessible on LAN without authentication | Dashboard | High | High |
| I2 | Blocked IP list exposes internal network topology | `blocked_ips.json` | Medium | Medium |
| I3 | Alert feed reveals detection thresholds to attacker | SIEM Dashboard | Medium | Medium |

**Mitigations:**
- I1: Add HTTP Basic Auth or token authentication to dashboard; bind to 127.0.0.1 only
- I2: Restrict file permissions; do not expose data directory via web
- I3: Do not display raw threshold values in dashboard UI

---

### 4.5 Denial of Service

| ID | Threat | Component | Likelihood | Impact |
|---|---|---|---|---|
| D1 | IP exhaustion — attacker rotates source IPs faster than block TTL | BlockEngine | High | High |
| D2 | Memory exhaustion — per-IP state dicts grow unbounded | PacketInterceptor | Medium | High |
| D3 | Dashboard flooded with SocketIO events — browser crashes | Dashboard | Medium | Low |
| D4 | Attacker deliberately triggers false positives to block legitimate IPs | BlockEngine | Medium | High |
| D5 | Scapy sniff loop CPU saturation at very high packet rates | PacketInterceptor | Medium | Medium |

**Mitigations:**
- D1: Implement CIDR-range blocking for subnet-level floods; reduce block TTL
- D2: Implement LRU eviction on per-IP state dicts (max entries configurable)
- D3: Throttle SocketIO emit rate; batch events server-side
- D4: Whitelist known-good IPs; require multiple threshold crossings before block
- D5: Implement async packet queue (Improvement 6) to decouple capture from detection

---

### 4.6 Elevation of Privilege

| ID | Threat | Component | Likelihood | Impact |
|---|---|---|---|---|
| E1 | IPS runs as Administrator — compromise gives full system access | All | Medium | Critical |
| E2 | Dashboard has no auth — any LAN user can issue block commands | Dashboard | High | High |
| E3 | Scapy arbitrary packet processing could trigger code execution via crafted packets | PacketInterceptor | Low | Critical |

**Mitigations:**
- E1: Run IPS as a dedicated service account with only the permissions needed for netsh and Scapy; use Windows Service isolation
- E2: Implement role-based access control on dashboard; separate read-only and admin views
- E3: Validate and sanitise all packet fields before processing; keep Scapy pinned to a tested version

---

## 5. Attack Tree — Primary Attack Path

```
Goal: Evade IPS detection and maintain persistent access
│
├── 1. Evade signature detection
│   ├── 1.1 Fragment packets below threshold size
│   ├── 1.2 Slow scan — stay below port_scan_unique_ports threshold
│   ├── 1.3 Distribute scan across multiple source IPs
│   └── 1.4 Randomise scan timing to avoid rate detection
│
├── 2. Disable the IPS
│   ├── 2.1 Kill the Python process (requires local access)
│   ├── 2.2 Exhaust memory via D2 (unbounded state dicts)
│   ├── 2.3 Flood dashboard to crash Flask server
│   └── 2.4 Modify blocked_ips.json directly
│
└── 3. Abuse the IPS as a weapon
    ├── 3.1 Spoof legitimate IPs to trigger blocks (DoS via IPS)
    └── 3.2 Flood alerts to hide real attack in noise
```

---

## 6. Security Assumptions

The following assumptions are made about the deployment environment:

1. The host running the IPS is not already compromised
2. The network interface driver correctly delivers packets to Scapy
3. Windows Firewall is enabled and not overridden by group policy
4. The operator has reviewed and configured the whitelist before deployment
5. The dashboard is accessed only from trusted internal machines

---

## 7. Out of Scope

| Item | Reason |
|---|---|
| Layer 7 application attacks (SQLi, XSS) | IPS operates at L3/L4 only |
| Encrypted traffic inspection | No TLS termination implemented |
| IPv6 traffic | Current implementation targets IPv4 only |
| Physical security | Outside software scope |
| Zero-day Scapy vulnerabilities | Mitigated by keeping dependencies updated |

---

## 8. Residual Risks

| Risk | Likelihood | Impact | Accepted? |
|---|---|---|---|
| IP spoofing bypass | High | High | Partially — requires network-level ingress filtering outside IPS scope |
| Slow scan evasion | High | Medium | Yes — signature IPS has inherent threshold-based blind spots |
| No dashboard authentication | High | High | No — must be fixed before production deployment |
| Administrator privilege requirement | Medium | Critical | Partially — service account isolation recommended |
| Unbounded per-IP memory growth | Medium | High | No — LRU eviction should be implemented (tracked in Improvement 6) |

---

## 9. Recommendations (Priority Order)

1. **Add dashboard authentication** — HTTP Basic Auth minimum; token auth preferred
2. **Bind dashboard to localhost** — prevent LAN-wide exposure
3. **Implement LRU eviction** on per-IP state dicts to cap memory usage
4. **Add ingress filtering** at the network boundary to reduce IP spoofing risk
5. **Run as service account** with minimal privileges rather than full Administrator
6. **Add IPv6 support** to prevent evasion via IPv6 tunnelling
7. **Enable TLS** on the Flask dashboard

---

## 10. CVSS Summary

| ID | Threat | CVSS Score | Severity |
|---|---|---|---|
| I1 | Unauthenticated dashboard | 8.1 | High |
| E1 | Administrator process compromise | 9.0 | Critical |
| D1 | IP rotation evasion | 7.5 | High |
| S1 | Source IP spoofing | 7.5 | High |
| D4 | False positive DoS via spoofing | 6.8 | Medium |
| T4 | Dashboard HTTP tampering | 5.9 | Medium |

---

*This threat model should be reviewed whenever significant changes are made to the detection engine, blocking logic, or dashboard. Next review date: June 2026.*