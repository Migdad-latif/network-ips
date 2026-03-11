"""
packet_interceptor.py
---------------------
Module B: Core packet interception engine.
Captures every packet, makes allow/drop decisions,
and enforces blocks via the block engine.
"""

import os
import sys
import time
import threading
from datetime import datetime
from collections import defaultdict, deque

# ── Paths ──────────────────────────────────────────────────────────────────────

sys.path.insert(0, os.path.dirname(__file__))
from block_engine import BlockEngine

# ── Configuration ──────────────────────────────────────────────────────────────

# Sensitive ports — access attempts trigger immediate block
SENSITIVE_PORTS = {
    22   : 'SSH',
    23   : 'Telnet',
    25   : 'SMTP',
    445  : 'SMB',
    3306 : 'MySQL',
    3389 : 'RDP',
}

# Detection thresholds
THRESHOLDS = {
    'port_scan_unique_ports' : 10,
    'syn_flood_packet_count' : 20,
    'syn_flood_max_avg_size' : 100,
    'dns_amp_count'          : 10,
    'rate_limit_pps'         : 50,    # packets per second before rate limit
}

# ── IPS Engine ─────────────────────────────────────────────────────────────────

class IPSEngine:
    """
    Full IPS engine:
      - Captures packets via Scapy
      - Detects attacks per packet
      - Blocks attacker IPs instantly on first detection
      - Reports all events via callbacks to dashboard
    """

    def __init__(self, block_engine=None):
        self.block_engine   = block_engine or BlockEngine()
        self.running        = False

        # Per-IP tracking
        self.src_ports      = defaultdict(set)
        self.src_pkt_count  = defaultdict(int)
        self.src_pkt_sizes  = defaultdict(list)
        self.dns_count      = defaultdict(int)
        self.rate_counters  = defaultdict(deque)  # ip → deque of timestamps

        # Already-detected IPs (prevent duplicate alerts)
        self.detected       = defaultdict(set)

        # Session stats
        self.stats = {
            'total_packets'  : 0,
            'blocked_packets': 0,
            'allowed_packets': 0,
            'total_alerts'   : 0,
        }

        self.lock      = threading.Lock()
        self.callbacks = []   # dashboard notification callbacks

        # Register block engine callback → forwards to dashboard
        self.block_engine.register_callback(self._on_block_event)

    # ── Callbacks ──────────────────────────────────────────────────────────────

    def register_callback(self, fn):
        self.callbacks.append(fn)

    def _notify(self, event_type, data):
        for cb in self.callbacks:
            try:
                cb(event_type, data)
            except Exception:
                pass

    def _on_block_event(self, event_type, data):
        self._notify(event_type, data)

    # ── Rate Limiter ───────────────────────────────────────────────────────────

    def _is_rate_limited(self, ip):
        """
        Token bucket rate limiter.
        Returns True if the IP is sending more than
        RATE_LIMIT_PPS packets per second.
        """
        now = time.time()
        window = self.rate_counters[ip]

        # Add current timestamp
        window.append(now)

        # Remove timestamps older than 1 second
        while window and window[0] < now - 1.0:
            window.popleft()

        return len(window) > THRESHOLDS['rate_limit_pps']

    # ── Detection ──────────────────────────────────────────────────────────────

    def _detect_and_block(self, pkt_data):
        """
        Runs all detection signatures against the packet.
        Blocks the source IP immediately on first match.
        Returns alert dict if attack detected, None otherwise.
        """
        src_ip   = pkt_data['src_ip']
        proto    = pkt_data['protocol']
        dst_port = pkt_data.get('dst_port')
        size     = pkt_data['size']

        # Skip already-blocked IPs (already handled)
        if self.block_engine.is_blocked(src_ip):
            return None

        # Update per-IP counters
        with self.lock:
            self.src_pkt_count[src_ip]  += 1
            self.src_pkt_sizes[src_ip].append(size)
            if dst_port:
                self.src_ports[src_ip].add(dst_port)
            if proto == 'UDP' and dst_port == 53:
                self.dns_count[src_ip] += 1

        # ── Check rate limit
        if self._is_rate_limited(src_ip):
            if 'RATE_LIMIT' not in self.detected[src_ip]:
                self.detected[src_ip].add('RATE_LIMIT')
                alert = self._make_alert(
                    'RATE_LIMIT_EXCEEDED', 'HIGH', src_ip,
                    f"Rate limit exceeded — over "
                    f"{THRESHOLDS['rate_limit_pps']} pkt/s",
                    {'pps': THRESHOLDS['rate_limit_pps']}
                )
                self.block_engine.block(
                    src_ip, alert['description'], 'RATE_LIMIT'
                )
                return alert

        # ── Check port scan
        unique_ports = len(self.src_ports[src_ip])
        if (unique_ports >= THRESHOLDS['port_scan_unique_ports']
                and 'PORT_SCAN' not in self.detected[src_ip]):
            self.detected[src_ip].add('PORT_SCAN')
            alert = self._make_alert(
                'PORT_SCAN', 'HIGH', src_ip,
                f"Port scan — {unique_ports} unique ports",
                {'unique_ports': unique_ports}
            )
            self.block_engine.block(src_ip, alert['description'], 'PORT_SCAN')
            return alert

        # ── Check SYN flood
        pkt_count = self.src_pkt_count[src_ip]
        if pkt_count >= THRESHOLDS['syn_flood_packet_count']:
            sizes    = self.src_pkt_sizes[src_ip]
            avg_size = sum(sizes) / len(sizes)
            if (avg_size <= THRESHOLDS['syn_flood_max_avg_size']
                    and 'SYN_FLOOD' not in self.detected[src_ip]):
                self.detected[src_ip].add('SYN_FLOOD')
                alert = self._make_alert(
                    'SYN_FLOOD', 'CRITICAL', src_ip,
                    f"SYN flood — {pkt_count} packets avg {avg_size:.0f}B",
                    {'packet_count': pkt_count, 'avg_size': round(avg_size,1)}
                )
                self.block_engine.block(
                    src_ip, alert['description'], 'SYN_FLOOD'
                )
                return alert

        # ── Check DNS amplification
        dns_count = self.dns_count[src_ip]
        if (dns_count >= THRESHOLDS['dns_amp_count']
                and 'DNS_AMP' not in self.detected[src_ip]):
            self.detected[src_ip].add('DNS_AMP')
            alert = self._make_alert(
                'DNS_AMPLIFICATION', 'HIGH', src_ip,
                f"DNS amplification — {dns_count} UDP/53 packets",
                {'dns_count': dns_count}
            )
            self.block_engine.block(
                src_ip, alert['description'], 'DNS_AMPLIFICATION'
            )
            return alert

        # ── Check sensitive port access
        if dst_port in SENSITIVE_PORTS:
            key = f"SENSITIVE_{dst_port}"
            if key not in self.detected[src_ip]:
                self.detected[src_ip].add(key)
                service  = SENSITIVE_PORTS[dst_port]
                severity = 'CRITICAL' if dst_port in {22, 445, 3389} \
                           else 'HIGH'
                alert = self._make_alert(
                    'SENSITIVE_PORT_ACCESS', severity, src_ip,
                    f"Access to port {dst_port} ({service})",
                    {'port': dst_port, 'service': service}
                )
                self.block_engine.block(
                    src_ip, alert['description'], 'SENSITIVE_PORT_ACCESS'
                )
                return alert

        return None

    def _make_alert(self, attack_type, severity, src_ip, desc, evidence):
        with self.lock:
            self.stats['total_alerts'] += 1
        return {
            'timestamp'  : datetime.now().strftime('%H:%M:%S'),
            'attack_type': attack_type,
            'severity'   : severity,
            'src_ip'     : src_ip,
            'description': desc,
            'evidence'   : evidence,
            'action'     : 'BLOCKED',
        }

    # ── Packet Handler ─────────────────────────────────────────────────────────

    def handle_packet(self, packet):
        """
        Called by Scapy for every captured packet.
        Makes allow/drop decision and notifies dashboard.
        """
        try:
            from scapy.all import IP, TCP, UDP, ICMP
        except ImportError:
            return

        if not packet.haslayer(IP):
            return

        if packet.haslayer(TCP):
            proto    = 'TCP'
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            proto    = 'UDP'
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            proto    = 'ICMP'
            src_port = None
            dst_port = None
        else:
            proto    = 'OTHER'
            src_port = None
            dst_port = None

        pkt_data = {
            'timestamp' : datetime.now().strftime('%H:%M:%S'),
            'src_ip'    : str(packet[IP].src),
            'dst_ip'    : str(packet[IP].dst),
            'protocol'  : proto,
            'src_port'  : src_port,
            'dst_port'  : dst_port,
            'size'      : len(packet),
        }

        src_ip = pkt_data['src_ip']

        # ── Decision
        if self.block_engine.is_blocked(src_ip):
            pkt_data['action'] = 'BLOCKED'
            with self.lock:
                self.stats['blocked_packets'] += 1
                self.stats['total_packets']   += 1
        else:
            pkt_data['action'] = 'ALLOWED'
            with self.lock:
                self.stats['allowed_packets'] += 1
                self.stats['total_packets']   += 1

            # Run detection — may trigger a block
            alert = self._detect_and_block(pkt_data)
            if alert:
                pkt_data['action'] = 'BLOCKED'
                self._notify('new_alert', alert)

        # Always notify dashboard of packet
        self._notify('new_packet', pkt_data)

        # Stats update every 20 packets
        with self.lock:
            total = self.stats['total_packets']
        if total % 20 == 0:
            self._notify('stats_update', self._get_stats())

    def _get_stats(self):
        with self.lock:
            stats = dict(self.stats)
        stats['blocked_list'] = self.block_engine.get_blocked_list()
        return stats

    # ── Start / Stop ───────────────────────────────────────────────────────────

    def start(self):
        """Starts packet capture in a background thread."""
        t = threading.Thread(target=self._capture_loop, daemon=True)
        t.start()

    def stop(self):
        self.running = False

    def _capture_loop(self):
        print("[*] Waiting for server to start...")
        time.sleep(2)

        try:
            from scapy.all import sniff
            import logging
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        except ImportError as e:
            print(f"[✗] Scapy import failed: {e}")
            return

        self.running = True
        print("[✓] IPS engine active — intercepting packets...")

        try:
            sniff(
                prn         = self.handle_packet,
                store       = False,
                stop_filter = lambda p: not self.running,
            )
        except Exception as e:
            print(f"[✗] Capture error: {e}")
            print("    Run VS Code as Administrator.")
            self.running = False