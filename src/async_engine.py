"""
async_engine.py
---------------
Improvement 6: Async packet queue + plugin-based signature detection.

Architecture:
    Sniffer thread  → puts packets onto a Queue
    Worker thread   → pulls from Queue, runs all plugins, emits alerts
    Plugin system   → each signature is an independent class

This decouples capture from detection so the sniffer never blocks
waiting for detection logic to complete. New signatures can be added
by subclassing BasePlugin without modifying the core engine.

Usage:
    from src.async_engine import AsyncEngine
    engine = AsyncEngine()
    engine.start()
    # engine runs in background threads
    engine.stop()

Plugins included:
    PortScanPlugin      — detects port scanning (unique dst ports per IP)
    SynFloodPlugin      — detects SYN floods (high packet rate + small size)
    DnsAmpPlugin        — detects DNS amplification (UDP/53 packet count)
    SensitivePortPlugin — detects access to sensitive service ports
    RateLimitPlugin     — detects general high packet rate
"""

import queue
import threading
import time
import logging
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Callable

log = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
# Packet dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Packet:
    """
    Normalised packet representation passed between threads.
    Populated by the sniffer from a Scapy packet object.
    """
    src_ip   : str
    dst_ip   : str
    src_port : int
    dst_port : int
    protocol : int        # 6=TCP, 17=UDP, 1=ICMP
    size     : int        # bytes
    flags    : str = ''   # TCP flags e.g. 'S', 'SA', 'F'
    timestamp: float = field(default_factory=time.time)


# ══════════════════════════════════════════════════════════════════════════════
# Alert dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Alert:
    """Emitted by a plugin when an attack is detected."""
    src_ip      : str
    attack_type : str
    description : str
    severity    : str       # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    timestamp   : float = field(default_factory=time.time)


# ══════════════════════════════════════════════════════════════════════════════
# BasePlugin
# ══════════════════════════════════════════════════════════════════════════════

class BasePlugin(ABC):
    """
    Base class for all detection plugins.

    Subclass this and implement analyse(packet) to add a new signature.
    Return an Alert if an attack is detected, None otherwise.

    The plugin is responsible for maintaining its own per-IP state.
    reset() is called on engine restart.
    """

    name     : str = 'base'
    enabled  : bool = True

    def reset(self):
        """Override to clear per-IP state on engine restart."""
        pass

    @abstractmethod
    def analyse(self, packet: Packet) -> Optional[Alert]:
        """
        Analyse one packet and return an Alert or None.
        Must be thread-safe — called from the worker thread only.
        """
        pass


# ══════════════════════════════════════════════════════════════════════════════
# Plugins
# ══════════════════════════════════════════════════════════════════════════════

class PortScanPlugin(BasePlugin):
    """
    Detects port scanning by tracking unique destination ports per source IP.
    Fires when a single source has contacted >= threshold unique ports.
    """

    name      = 'port_scan'
    THRESHOLD = 10          # unique dst ports

    def reset(self):
        self._src_ports  = defaultdict(set)
        self._alerted    = set()

    def __init__(self):
        self.reset()

    def analyse(self, packet: Packet) -> Optional[Alert]:
        if packet.protocol != 6:    # TCP only
            return None

        src = packet.src_ip
        self._src_ports[src].add(packet.dst_port)

        if (len(self._src_ports[src]) >= self.THRESHOLD and
                src not in self._alerted):
            self._alerted.add(src)
            return Alert(
                src_ip      = src,
                attack_type = 'PORT_SCAN',
                description = (f"{src} contacted {len(self._src_ports[src])} "
                               f"unique ports"),
                severity    = 'HIGH',
            )
        return None


class SynFloodPlugin(BasePlugin):
    """
    Detects SYN floods by tracking SYN packet rate per source IP.
    Uses a sliding deque window to count recent SYN packets.
    Fires when count >= threshold AND average packet size is small.
    """

    name           = 'syn_flood'
    THRESHOLD      = 20     # SYN packets in window
    MAX_AVG_SIZE   = 100    # bytes — SYN packets carry no payload
    WINDOW_SECONDS = 5

    def reset(self):
        self._syn_times = defaultdict(deque)
        self._alerted   = set()

    def __init__(self):
        self.reset()

    def analyse(self, packet: Packet) -> Optional[Alert]:
        if packet.protocol != 6 or packet.flags != 'S':
            return None

        src = packet.src_ip
        now = packet.timestamp
        window = self._syn_times[src]

        window.append((now, packet.size))

        # Evict entries outside the time window
        while window and window[0][0] < now - self.WINDOW_SECONDS:
            window.popleft()

        if (len(window) >= self.THRESHOLD and
                src not in self._alerted):
            avg_size = sum(s for _, s in window) / len(window)
            if avg_size <= self.MAX_AVG_SIZE:
                self._alerted.add(src)
                return Alert(
                    src_ip      = src,
                    attack_type = 'SYN_FLOOD',
                    description = (f"{src} sent {len(window)} SYN packets "
                                   f"in {self.WINDOW_SECONDS}s, "
                                   f"avg size {avg_size:.0f}B"),
                    severity    = 'CRITICAL',
                )
        return None


class DnsAmpPlugin(BasePlugin):
    """
    Detects DNS amplification attacks by counting UDP/53 packets per source.
    """

    name      = 'dns_amp'
    THRESHOLD = 10

    def reset(self):
        self._dns_count = defaultdict(int)
        self._alerted   = set()

    def __init__(self):
        self.reset()

    def analyse(self, packet: Packet) -> Optional[Alert]:
        if packet.protocol != 17 or packet.dst_port != 53:
            return None

        src = packet.src_ip
        self._dns_count[src] += 1

        if (self._dns_count[src] >= self.THRESHOLD and
                src not in self._alerted):
            self._alerted.add(src)
            return Alert(
                src_ip      = src,
                attack_type = 'DNS_AMP',
                description = (f"{src} sent {self._dns_count[src]} "
                               f"DNS queries"),
                severity    = 'MEDIUM',
            )
        return None


class SensitivePortPlugin(BasePlugin):
    """
    Detects access to sensitive service ports (SSH, Telnet, RDP, etc).
    Fires on first access — no threshold needed.
    """

    name            = 'sensitive_port'
    SENSITIVE_PORTS = {22, 23, 25, 445, 3306, 3389}

    def reset(self):
        self._alerted = set()

    def __init__(self):
        self.reset()

    def analyse(self, packet: Packet) -> Optional[Alert]:
        if packet.dst_port not in self.SENSITIVE_PORTS:
            return None

        key = (packet.src_ip, packet.dst_port)
        if key not in self._alerted:
            self._alerted.add(key)
            return Alert(
                src_ip      = packet.src_ip,
                attack_type = 'SENSITIVE_PORT',
                description = (f"{packet.src_ip} accessed sensitive "
                               f"port {packet.dst_port}"),
                severity    = 'MEDIUM',
            )
        return None


class RateLimitPlugin(BasePlugin):
    """
    Detects general high packet rate from a single source.
    Uses a sliding deque window to measure packets per second.
    """

    name           = 'rate_limit'
    THRESHOLD_PPS  = 50     # packets per second
    WINDOW_SECONDS = 1

    def reset(self):
        self._pkt_times = defaultdict(deque)
        self._alerted   = set()

    def __init__(self):
        self.reset()

    def analyse(self, packet: Packet) -> Optional[Alert]:
        src = packet.src_ip
        now = packet.timestamp
        window = self._pkt_times[src]

        window.append(now)

        while window and window[0] < now - self.WINDOW_SECONDS:
            window.popleft()

        pps = len(window) / self.WINDOW_SECONDS

        if pps >= self.THRESHOLD_PPS and src not in self._alerted:
            self._alerted.add(src)
            return Alert(
                src_ip      = src,
                attack_type = 'RATE_LIMIT',
                description = f"{src} sending {pps:.0f} pps",
                severity    = 'HIGH',
            )
        return None


# ══════════════════════════════════════════════════════════════════════════════
# PluginRegistry
# ══════════════════════════════════════════════════════════════════════════════

class PluginRegistry:
    """
    Manages the set of active detection plugins.
    Plugins can be added, removed, or toggled at runtime.
    """

    def __init__(self):
        self._plugins: list[BasePlugin] = []

    def register(self, plugin: BasePlugin) -> 'PluginRegistry':
        """Register a plugin. Returns self for chaining."""
        self._plugins.append(plugin)
        log.info(f"[plugin] registered: {plugin.name}")
        return self

    def unregister(self, name: str) -> None:
        self._plugins = [p for p in self._plugins if p.name != name]
        log.info(f"[plugin] unregistered: {name}")

    def disable(self, name: str) -> None:
        for p in self._plugins:
            if p.name == name:
                p.enabled = False
                log.info(f"[plugin] disabled: {name}")

    def enable(self, name: str) -> None:
        for p in self._plugins:
            if p.name == name:
                p.enabled = True
                log.info(f"[plugin] enabled: {name}")

    def run_all(self, packet: Packet) -> list[Alert]:
        """Run all enabled plugins on a packet. Returns list of alerts."""
        alerts = []
        for plugin in self._plugins:
            if not plugin.enabled:
                continue
            try:
                alert = plugin.analyse(packet)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                log.error(f"[plugin] {plugin.name} error: {e}")
        return alerts

    def reset_all(self) -> None:
        for plugin in self._plugins:
            plugin.reset()

    @property
    def names(self) -> list[str]:
        return [p.name for p in self._plugins]


# ══════════════════════════════════════════════════════════════════════════════
# AsyncEngine
# ══════════════════════════════════════════════════════════════════════════════

class AsyncEngine:
    """
    Core async engine.

    Two threads:
        sniffer_thread  — calls _capture() to put Packet objects onto the queue
        worker_thread   — pulls from queue, runs plugins, calls alert callbacks

    The sniffer never blocks on detection — it just enqueues and moves on.
    Queue overflow is handled by dropping packets with a warning (back-pressure).

    Usage:
        engine = AsyncEngine(queue_size=10000)
        engine.on_alert(lambda alert: print(alert))
        engine.start()
        ...
        engine.stop()
    """

    def __init__(self, queue_size: int = 10000):
        self._queue          = queue.Queue(maxsize=queue_size)
        self._registry       = PluginRegistry()
        self._alert_callbacks: list[Callable[[Alert], None]] = []
        self._running        = False
        self._worker_thread  : Optional[threading.Thread] = None
        self._dropped_packets = 0
        self._processed_packets = 0

        # Register default plugins
        self._registry \
            .register(PortScanPlugin()) \
            .register(SynFloodPlugin()) \
            .register(DnsAmpPlugin()) \
            .register(SensitivePortPlugin()) \
            .register(RateLimitPlugin())

        log.info(f"[engine] plugins: {self._registry.names}")

    def on_alert(self, callback: Callable[[Alert], None]) -> None:
        """Register a callback to be called when an alert is raised."""
        self._alert_callbacks.append(callback)

    def enqueue(self, packet: Packet) -> bool:
        """
        Called by the sniffer thread to add a packet to the queue.
        Returns True if enqueued, False if queue is full (packet dropped).
        """
        try:
            self._queue.put_nowait(packet)
            return True
        except queue.Full:
            self._dropped_packets += 1
            if self._dropped_packets % 1000 == 0:
                log.warning(f"[engine] queue full — "
                            f"{self._dropped_packets} packets dropped")
            return False

    def start(self) -> None:
        """Start the worker thread."""
        if self._running:
            return
        self._running = True
        self._registry.reset_all()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name='async-engine-worker',
            daemon=True,
        )
        self._worker_thread.start()
        log.info("[engine] started")

    def stop(self) -> None:
        """Stop the worker thread gracefully."""
        self._running = False
        # Unblock the worker if it's waiting on an empty queue
        try:
            self._queue.put_nowait(None)
        except queue.Full:
            pass
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        log.info(f"[engine] stopped — "
                 f"processed={self._processed_packets}, "
                 f"dropped={self._dropped_packets}")

    def _worker_loop(self) -> None:
        """
        Worker thread main loop.
        Pulls packets from the queue and runs all plugins.
        Sentinel value None signals shutdown.
        """
        while self._running:
            try:
                packet = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if packet is None:  # shutdown sentinel
                break

            alerts = self._registry.run_all(packet)
            self._processed_packets += 1

            for alert in alerts:
                self._dispatch_alert(alert)

            self._queue.task_done()

    def _dispatch_alert(self, alert: Alert) -> None:
        """Call all registered alert callbacks."""
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                log.error(f"[engine] alert callback error: {e}")

    @property
    def registry(self) -> PluginRegistry:
        """Access the plugin registry to add/remove/toggle plugins."""
        return self._registry

    @property
    def stats(self) -> dict:
        return {
            'queue_size'        : self._queue.qsize(),
            'processed_packets' : self._processed_packets,
            'dropped_packets'   : self._dropped_packets,
            'plugins'           : self._registry.names,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Scapy bridge — converts Scapy packets to Packet dataclass
# ══════════════════════════════════════════════════════════════════════════════

def scapy_to_packet(scapy_pkt) -> Optional[Packet]:
    """
    Converts a Scapy packet to a normalised Packet dataclass.
    Returns None if the packet is not IP.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP
        if not scapy_pkt.haslayer(IP):
            return None

        ip    = scapy_pkt[IP]
        proto = ip.proto
        size  = len(scapy_pkt)

        src_port = dst_port = 0
        flags    = ''

        if proto == 6 and scapy_pkt.haslayer(TCP):
            tcp      = scapy_pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            flags    = str(tcp.flags)

        elif proto == 17 and scapy_pkt.haslayer(UDP):
            udp      = scapy_pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport

        return Packet(
            src_ip   = ip.src,
            dst_ip   = ip.dst,
            src_port = src_port,
            dst_port = dst_port,
            protocol = proto,
            size     = size,
            flags    = flags,
        )
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Quick demo / smoke test
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import random

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(message)s'
    )

    print("=" * 55)
    print("  AsyncEngine — plugin smoke test")
    print("=" * 55)

    alerts_received = []

    def on_alert(alert: Alert):
        alerts_received.append(alert)
        print(f"  [ALERT] {alert.severity:<8} {alert.attack_type:<20} "
              f"from {alert.src_ip}")
        print(f"          {alert.description}")

    engine = AsyncEngine(queue_size=5000)
    engine.on_alert(on_alert)
    engine.start()

    ATTACKER = '192.168.1.99'
    VICTIM   = '10.0.0.1'

    print("\n[*] Simulating port scan (15 unique ports)...")
    for port in range(1, 16):
        engine.enqueue(Packet(
            src_ip=ATTACKER, dst_ip=VICTIM,
            src_port=54321, dst_port=port,
            protocol=6, size=60, flags='S'
        ))

    print("[*] Simulating SYN flood (25 packets)...")
    for _ in range(25):
        engine.enqueue(Packet(
            src_ip=ATTACKER, dst_ip=VICTIM,
            src_port=random.randint(1024, 65535), dst_port=80,
            protocol=6, size=40, flags='S',
            timestamp=time.time()
        ))

    print("[*] Simulating DNS amplification (12 queries)...")
    for _ in range(12):
        engine.enqueue(Packet(
            src_ip='10.0.0.50', dst_ip='8.8.8.8',
            src_port=random.randint(1024, 65535), dst_port=53,
            protocol=17, size=80, flags=''
        ))

    print("[*] Simulating sensitive port access (SSH)...")
    engine.enqueue(Packet(
        src_ip='172.16.0.5', dst_ip=VICTIM,
        src_port=54000, dst_port=22,
        protocol=6, size=60, flags='S'
    ))

    print("[*] Simulating benign HTTP traffic (10 packets)...")
    for _ in range(10):
        engine.enqueue(Packet(
            src_ip='10.0.0.200', dst_ip=VICTIM,
            src_port=random.randint(1024, 65535), dst_port=80,
            protocol=6, size=random.randint(200, 1400), flags='S'
        ))

    # Give worker time to process
    time.sleep(1)
    engine.stop()

    print(f"\n{'='*55}")
    print(f"  Results")
    print(f"{'='*55}")
    print(f"  Alerts raised : {len(alerts_received)}")
    print(f"  Stats         : {engine.stats}")
    print(f"{'='*55}")

    expected = {'PORT_SCAN', 'SYN_FLOOD', 'DNS_AMP', 'SENSITIVE_PORT'}
    found    = {a.attack_type for a in alerts_received}
    missing  = expected - found

    if not missing:
        print("\n  [✓] All expected attack types detected")
    else:
        print(f"\n  [✗] Missing detections: {missing}")