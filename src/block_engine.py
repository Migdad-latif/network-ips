"""
block_engine.py
---------------
Core blocking logic for the IPS.
Manages blocked IP list, whitelist, auto-unblock timers,
and Windows Firewall rules (inbound + outbound, verified).
"""

import os
import json
import subprocess
import threading
import time
from datetime import datetime, timedelta

# ── Paths ──────────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.join(os.path.dirname(__file__), '..')
BLOCKED_FILE = os.path.join(BASE_DIR, 'data', 'blocked_ips.json')
HISTORY_FILE = os.path.join(BASE_DIR, 'data', 'block_history.json')
FW_LOG_FILE  = os.path.join(BASE_DIR, 'logs',  'firewall.log')

# ── Configuration ──────────────────────────────────────────────────────────────

BLOCK_DURATION_SECONDS = 300   # 5 minutes auto-unblock
RULE_PREFIX            = 'IPS_BLOCK'

DEFAULT_WHITELIST = {
    '127.0.0.1',
    '0.0.0.0',
}

# ── Block Engine ───────────────────────────────────────────────────────────────

class BlockEngine:
    """
    Manages the full lifecycle of IP blocks:
      block()      → add to block list + verified firewall rules (in + out)
      unblock()    → remove from block list + remove firewall rules
      is_blocked() → check if an IP is currently blocked
      auto-unblock → background thread releases blocks after timeout
      startup      → cleans up any stale IPS_ rules from previous session
    """

    def __init__(self, auto_unblock_seconds=BLOCK_DURATION_SECONDS):
        self.blocked   = {}
        self.whitelist = set(DEFAULT_WHITELIST)
        self.history   = []
        self.lock      = threading.Lock()
        self.callbacks = []
        self.auto_unblock_seconds = auto_unblock_seconds

        os.makedirs(os.path.join(BASE_DIR, 'data'), exist_ok=True)
        os.makedirs(os.path.join(BASE_DIR, 'logs'), exist_ok=True)

        self._fw_log(f"Block engine starting — "
                     f"auto-unblock: {auto_unblock_seconds}s")

        # Clean up stale rules from any previous IPS session
        self._cleanup_stale_rules()

        self._load_state()

        threading.Thread(
            target=self._auto_unblock_thread, daemon=True
        ).start()

        print(f"[✓] Block engine started — "
              f"auto-unblock after {auto_unblock_seconds}s")

    # ── Public API ─────────────────────────────────────────────────────────────

    def block(self, ip, reason, attack_type='UNKNOWN'):
        if ip in self.whitelist:
            print(f"  [~] {ip} is whitelisted — block ignored")
            return False

        with self.lock:
            if ip in self.blocked:
                return False

            entry = {
                'ip'         : ip,
                'blocked_at' : datetime.now().isoformat(),
                'unblock_at' : (
                    datetime.now() +
                    timedelta(seconds=self.auto_unblock_seconds)
                ).isoformat(),
                'reason'     : reason,
                'attack_type': attack_type,
                'status'     : 'BLOCKED',
                'fw_inbound' : False,   # confirmed firewall status
                'fw_outbound': False,
            }
            self.blocked[ip] = entry
            self.history.append({**entry, 'event': 'BLOCK'})

        # Add and verify both firewall directions
        inbound_ok  = self._add_firewall_rule(ip, 'in')
        outbound_ok = self._add_firewall_rule(ip, 'out')

        with self.lock:
            self.blocked[ip]['fw_inbound']  = inbound_ok
            self.blocked[ip]['fw_outbound'] = outbound_ok

        fw_status = self._fw_status_string(inbound_ok, outbound_ok)
        print(f"  [🚫] BLOCKED {ip} — {attack_type} — {fw_status} — "
              f"auto-unblock in {self.auto_unblock_seconds}s")

        self._fw_log(
            f"BLOCK {ip} | attack={attack_type} | "
            f"inbound={inbound_ok} | outbound={outbound_ok} | "
            f"reason={reason}"
        )

        self._save_state()

        for cb in self.callbacks:
            try:
                cb('block', self.blocked[ip])
            except Exception:
                pass

        return True

    def unblock(self, ip, reason='manual'):
        with self.lock:
            if ip not in self.blocked:
                return False
            entry = self.blocked.pop(ip)
            self.history.append({
                **entry,
                'event'          : 'UNBLOCK',
                'unblocked_at'   : datetime.now().isoformat(),
                'unblock_reason' : reason,
            })

        self._remove_firewall_rule(ip, 'in')
        self._remove_firewall_rule(ip, 'out')

        print(f"  [✓] UNBLOCKED {ip} — reason: {reason}")
        self._fw_log(f"UNBLOCK {ip} | reason={reason}")
        self._save_state()

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
        self.callbacks.append(fn)

    # ── Firewall — Add Rule ────────────────────────────────────────────────────

    def _add_firewall_rule(self, ip, direction):
        """
        Adds a Windows Firewall block rule for one direction.
        Verifies the rule is active after adding.
        Returns True if rule is confirmed active, False otherwise.
        Requires Administrator privileges.
        """
        rule_name = self._rule_name(ip, direction)

        cmd_add = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={rule_name}',
            f'dir={direction}',
            'action=block',
            f'remoteip={ip}',
            'enable=yes',
            'profile=any',
            'protocol=any',
        ]

        try:
            result = subprocess.run(
                cmd_add,
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                print(f"  [!] Firewall add failed ({direction}) for {ip}: "
                      f"{result.stderr.strip()}")
                self._fw_log(
                    f"ADD_FAILED {ip} dir={direction} | "
                    f"stderr={result.stderr.strip()}"
                )
                return False

            # Verify rule is actually active
            confirmed = self._verify_rule(rule_name)

            if confirmed:
                print(f"  [🔥] Firewall rule confirmed: {direction.upper()} "
                      f"BLOCK {ip}")
            else:
                print(f"  [!] Firewall rule added but NOT confirmed "
                      f"({direction}) for {ip}")

            return confirmed

        except subprocess.TimeoutExpired:
            print(f"  [!] Firewall add timed out ({direction}) for {ip}")
            return False
        except Exception as e:
            print(f"  [!] Firewall add error ({direction}) for {ip}: {e}")
            return False

    # ── Firewall — Remove Rule ─────────────────────────────────────────────────

    def _remove_firewall_rule(self, ip, direction):
        """Removes a Windows Firewall rule and verifies removal."""
        rule_name = self._rule_name(ip, direction)

        cmd = [
            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
            f'name={rule_name}',
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )

            still_exists = self._verify_rule(rule_name)

            if not still_exists:
                print(f"  [✓] Firewall rule removed: "
                      f"{direction.upper()} {ip}")
            else:
                print(f"  [!] Firewall rule removal unconfirmed "
                      f"({direction}) for {ip}")

        except Exception as e:
            print(f"  [!] Firewall remove error ({direction}) for {ip}: {e}")

    # ── Firewall — Verify Rule ─────────────────────────────────────────────────

    def _verify_rule(self, rule_name):
        """
        Queries Windows Firewall to confirm a rule exists and is enabled.
        Returns True if rule is active, False otherwise.
        """
        cmd = [
            'netsh', 'advfirewall', 'firewall', 'show', 'rule',
            f'name={rule_name}',
            'verbose',
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )

            output = result.stdout.lower()

            # Rule exists and is enabled if both strings present
            return (rule_name.lower() in output and
                    'enabled:                              yes' in output)

        except Exception:
            return False

    # ── Firewall — Cleanup Stale Rules ────────────────────────────────────────

    def _cleanup_stale_rules(self):
        """
        On startup, removes any IPS_BLOCK_ rules left over from
        a previous session that did not shut down cleanly.
        Prevents accumulation of orphaned firewall rules.
        """
        print("[*] Checking for stale firewall rules...")

        cmd_show = [
            'netsh', 'advfirewall', 'firewall', 'show', 'rule',
            f'name={RULE_PREFIX}*',
        ]

        try:
            result = subprocess.run(
                cmd_show,
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Parse rule names from output
            stale_rules = []
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('Rule Name:'):
                    name = line.split(':', 1)[1].strip()
                    if name.startswith(RULE_PREFIX):
                        stale_rules.append(name)

            if not stale_rules:
                print("[✓] No stale firewall rules found")
                return

            print(f"[*] Removing {len(stale_rules)} stale rules...")

            removed = 0
            for rule_name in stale_rules:
                cmd_del = [
                    'netsh', 'advfirewall', 'firewall',
                    'delete', 'rule', f'name={rule_name}',
                ]
                r = subprocess.run(
                    cmd_del,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if r.returncode == 0:
                    removed += 1

            print(f"[✓] Removed {removed}/{len(stale_rules)} stale rules")
            self._fw_log(f"STARTUP_CLEANUP removed={removed} "
                         f"found={len(stale_rules)}")

        except Exception as e:
            print(f"[!] Stale rule cleanup error: {e}")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _rule_name(self, ip, direction):
        """Generates a consistent, identifiable rule name."""
        safe_ip = ip.replace('.', '_')
        return f"{RULE_PREFIX}_{direction.upper()}_{safe_ip}"

    def _fw_status_string(self, inbound_ok, outbound_ok):
        inb = "✓IN" if inbound_ok  else "✗IN"
        out = "✓OUT" if outbound_ok else "✗OUT"
        return f"FW:[{inb}|{out}]"

    def _fw_log(self, message):
        """Appends a timestamped entry to the firewall log."""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(FW_LOG_FILE, 'a') as f:
                f.write(f"[{timestamp}] {message}\n")
        except Exception:
            pass

    # ── Auto-unblock Thread ────────────────────────────────────────────────────

    def _auto_unblock_thread(self):
        while True:
            time.sleep(10)
            now        = datetime.now()
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
        try:
            if os.path.exists(BLOCKED_FILE):
                with open(BLOCKED_FILE) as f:
                    self.blocked = json.load(f)
                print(f"[✓] Loaded {len(self.blocked)} blocked IPs from disk")
        except Exception:
            self.blocked = {}