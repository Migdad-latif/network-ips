"""
monitor.py
----------
Runs inside the Docker monitor container.
Sniffs traffic on all interfaces on the lab network and applies
the same signature detection logic as the IPS.
Logs all detections to stdout and /app/logs/monitor.log
"""

import os
import logging
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP, get_if_list

LOG_PATH = '/app/logs/monitor.log'
os.makedirs('/app/logs', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(),
    ]
)

log = logging.getLogger('monitor')

# Per-IP state
src_ports  = defaultdict(set)
pkt_count  = defaultdict(int)
detections = defaultdict(set)

THRESHOLDS = {
    'port_scan_unique_ports' : 10,
    'syn_flood_count'        : 50,
}

SENSITIVE_PORTS = {22, 23, 25, 445, 3306, 3389}

VICTIM_IP = '172.20.0.10'


def detect(pkt):
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    if dst != VICTIM_IP:
        return

    pkt_count[src] += 1

    if pkt.haslayer(TCP):
        dst_port = pkt[TCP].dport
        src_ports[src].add(dst_port)

        # Port scan
        if (len(src_ports[src]) >= THRESHOLDS['port_scan_unique_ports'] and
                'port_scan' not in detections[src]):
            detections[src].add('port_scan')
            log.warning(f"[!] PORT_SCAN detected from {src} "
                        f"- {len(src_ports[src])} unique ports probed")

        # SYN flood
        if (pkt[TCP].flags == 'S' and
                pkt_count[src] >= THRESHOLDS['syn_flood_count'] and
                'syn_flood' not in detections[src]):
            detections[src].add('syn_flood')
            log.warning(f"[!] SYN_FLOOD detected from {src} "
                        f"- {pkt_count[src]} SYN packets")

        # Sensitive port
        if dst_port in SENSITIVE_PORTS:
            key = f'sensitive_{dst_port}'
            if key not in detections[src]:
                detections[src].add(key)
                log.warning(f"[!] SENSITIVE_PORT {dst_port} accessed from {src}")

    elif pkt.haslayer(UDP):
        if pkt[UDP].dport == 53:
            if 'dns_query' not in detections[src]:
                detections[src].add('dns_query')
                log.info(f"[*] DNS query from {src}")


ifaces = get_if_list()
log.info(f"Monitor started - interfaces: {ifaces}")
log.info(f"Watching traffic to victim {VICTIM_IP}")

sniff(prn=detect, store=False, filter=f"dst host {VICTIM_IP}")