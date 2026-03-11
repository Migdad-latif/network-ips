"""
block_engine.py
---------------
Core blocking logic for the IPS.
Manages the blocked IP list, whitelist,
auto-unblock timers, and Windows Firewall rules.
"""

import os
import json
import subprocess
import threading
import time
from datetime import datetime, timedelta

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR      = os.path.join(os.path.dirname(__file__), '..')
BLOCKED_FILE  = os.path.join(BASE_DIR, 'data', 'blocked_ips.json')
HISTORY_FILE  = os.path.join(BASE_DIR, 'data', 'block_history.json')

# ── Configuration ──────────────────────────────────────────────────────────────

BLOCK_DURATION_SECONDS = 300   # 5 minutes auto-unblock

# IPs that must NEVER be blocked (your own PC, gateway, DNS)
DEFAULT_WHITELIST = {
    '127.0.0.1',
    '0.0.0.0',
}

# ── Block Engine ───────────────────────────────────────────────────────────────

class BlockEngine:
    """
    Manages the full lifecycle of IP blocks:
      block()    → add to block list + firewall rule
      unblock()  → remove from block list + firewall rule
      is_blocked() → check if an IP is currently blocked
      auto-unblock → background thread releases blocks after timeout
    """

    def __init__(self, auto_unblock_seconds=BLOCK_DURATION_SECONDS):
        self.blocked     = {}        # ip → {blocked_at, reason, attack_type}
        self.whitelist   = set(DEFAULT_WHITELIST)
        self.history     = []        # full block/unblock event log
        self.lock        = threading.Lock()
        self.auto_unblock_seconds = auto_unblock_seconds
        self.callbacks   = []        # functions called on block/unblock events

        os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)

        self._load_state()

        # Start auto-unblock background thread
        t = threading.Thread(target=self._auto_unblock_thread, daemon=True)
        t.start()

        print(f"[✓] Block engine started — "
              f"auto-unblock after {auto_unblock_seconds}s")

    # ── Public API ─────────────────────────────────────────────────────────────

    def block(self, ip, reason, attack_type='UNKNOWN'):
        """
        Blocks an IP address.
        Adds to internal block list and adds a Windows Firewall rule.
        """
        if ip in self.whitelist:
            print(f"  [~] {ip} is whitelisted — block ignored")
            return False

        with self.lock:
            if ip in self.blocked:
                return False   # already blocked

            entry = {
                'ip'          : ip,
                'blocked_at'  : datetime.now().isoformat(),
                'unblock_at'  : (
                    datetime.now() +
                    timedelta(seconds=self.auto_unblock_seconds)
                ).isoformat(),
                'reason'      : reason,
                'attack_type' : attack_type,
                'status'      : 'BLOCKED',
            }

            self.blocked[ip] = entry
            self.history.append({**entry, 'event': 'BLOCK'})

        # Add Windows Firewall rule
        self._add_firewall_rule(ip)
        self._save_state()

        print(f"  [🚫] BLOCKED {ip} — {attack_type} — "
              f"auto-unblock in {self.auto_unblock_seconds}s")

        # Notify all registered callbacks (dashboard, logger)
        for cb in self.callbacks:
            try:
                cb('block', entry)
            except Exception:
                pass

        return True

    def unblock(self, ip, reason='manual'):
        """Unblocks an IP and removes the firewall rule."""
        with self.lock:
            if ip not in self.blocked:
                return False

            entry = self.blocked.pop(ip)
            self.history.append({
                **entry,
                'event'      : 'UNBLOCK',
                'unblocked_at': datetime.now().isoformat(),
                'unblock_reason': reason,
            })

        self._remove_firewall_rule(ip)
        self._save_state()

        print(f"  [✓] UNBLOCKED {ip} — reason: {reason}")

        for cb in self.callbacks:
            try:
                cb('unblock', {'ip': ip, 'reason': reason})
            except Exception:
                pass

        return True

    def is_blocked(self, ip):
        with self.lock:
            return ip in self.blocked

    def is_whitelisted(self, ip):
        return ip in self.whitelist

    def add_to_whitelist(self, ip):
        self.whitelist.add(ip)
        if self.is_blocked(ip):
            self.unblock(ip, reason='whitelisted')
        print(f"  [✓] {ip} added to whitelist")

    def get_blocked_list(self):
        with self.lock:
            return list(self.blocked.values())

    def get_history(self, limit=50):
        with self.lock:
            return self.history[-limit:]

    def register_callback(self, fn):
        """Register a function to be called on block/unblock events."""
        self.callbacks.append(fn)

    # ── Windows Firewall ───────────────────────────────────────────────────────

    def _add_firewall_rule(self, ip):
        """
        Adds an inbound block rule to Windows Firewall using netsh.
        Rule name is prefixed with IPS_ for easy identification.
        Requires Administrator privileges.
        """
        rule_name = f"IPS_BLOCK_{ip.replace('.', '_')}"
        cmd = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={rule_name}',
            'dir=in',
            'action=block',
            f'remoteip={ip}',
            'enable=yes',
            'profile=any',
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                print(f"  [🔥] Firewall rule added for {ip}")
            else:
                print(f"  [!] Firewall rule failed: {result.stderr.strip()}")
                print(f"      (Ensure VS Code is running as Administrator)")
        except Exception as e:
            print(f"  [!] Firewall error: {e}")

    def _remove_firewall_rule(self, ip):
        """Removes the Windows Firewall block rule for an IP."""
        rule_name = f"IPS_BLOCK_{ip.replace('.', '_')}"
        cmd = [
            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
            f'name={rule_name}',
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            print(f"  [✓] Firewall rule removed for {ip}")
        except Exception as e:
            print(f"  [!] Firewall remove error: {e}")

    # ── Auto-unblock Thread ────────────────────────────────────────────────────

    def _auto_unblock_thread(self):
        """
        Runs every 10 seconds, checks if any blocked IPs
        have exceeded their block duration and unblocks them.
        """
        while True:
            time.sleep(10)
            now = datetime.now()
            to_unblock = []

            with self.lock:
                for ip, entry in self.blocked.items():
                    unblock_at = datetime.fromisoformat(entry['unblock_at'])
                    if now >= unblock_at:
                        to_unblock.append(ip)

            for ip in to_unblock:
                self.unblock(ip, reason='auto-unblock timeout')

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save_state(self):
        """Saves blocked list and history to JSON files."""
        try:
            with self.lock:
                blocked_copy = dict(self.blocked)
                history_copy = list(self.history)

            with open(BLOCKED_FILE, 'w') as f:
                json.dump(blocked_copy, f, indent=2)

            with open(HISTORY_FILE, 'w') as f:
                json.dump(history_copy[-200:], f, indent=2)
        except Exception as e:
            print(f"  [!] Save state error: {e}")

    def _load_state(self):
        """Loads persisted block list on startup."""
        try:
            if os.path.exists(BLOCKED_FILE):
                with open(BLOCKED_FILE) as f:
                    self.blocked = json.load(f)
                print(f"[✓] Loaded {len(self.blocked)} blocked IPs from disk")
        except Exception:
            self.blocked = {}