"""
app.py
------
IPS SIEM Dashboard Server.
Flask + SocketIO backend serving the live IPS dashboard.
Provides block/unblock controls via WebSocket events.
"""

import os
import sys
import threading
import time
from datetime import datetime
from collections import defaultdict, deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask          import Flask, render_template_string
from flask_socketio import SocketIO, emit
from block_engine       import BlockEngine
from packet_interceptor import IPSEngine
from rate_limiter       import RateLimiter

# ── App Setup ──────────────────────────────────────────────────────────────────

app      = Flask(__name__)
app.config['SECRET_KEY'] = 'ips-siem-secret'

socketio = SocketIO(
    app,
    async_mode          = 'threading',
    cors_allowed_origins= '*',
    logger              = False,
    engineio_logger     = False,
    ping_timeout        = 60,
    ping_interval       = 25,
)

HTML_FILE = os.path.join(os.path.dirname(__file__), 'ips.html')

# ── Core Engines ───────────────────────────────────────────────────────────────

block_engine  = BlockEngine(auto_unblock_seconds=300)
rate_limiter  = RateLimiter(pps_limit=50)
ips_engine    = IPSEngine(block_engine=block_engine)

# ── Shared Dashboard State ─────────────────────────────────────────────────────

dash = {
    'packets'          : deque(maxlen=500),
    'alerts'           : deque(maxlen=200),
    'protocol_counts'  : defaultdict(int),
    'top_talkers'      : defaultdict(int),
    'timeline'         : deque(maxlen=60),
    'total_packets'    : 0,
    'blocked_packets'  : 0,
    'allowed_packets'  : 0,
    'total_alerts'     : 0,
    'lock'             : threading.Lock(),
}

# ── Safe Background Emit ───────────────────────────────────────────────────────

def bg_emit(event, data):
    try:
        socketio.emit(event, data, namespace='/')
    except Exception:
        pass

# ── IPS Engine Callback ────────────────────────────────────────────────────────

def ips_callback(event_type, data):
    """
    Receives events from the IPS engine and
    forwards them to all connected browser clients.
    """
    if event_type == 'new_packet':
        pkt = data
        with dash['lock']:
            dash['packets'].append(pkt)
            dash['protocol_counts'][pkt['protocol']] += 1
            dash['top_talkers'][pkt['src_ip']]       += 1
            dash['total_packets'] += 1
            if pkt.get('action') == 'BLOCKED':
                dash['blocked_packets'] += 1
            else:
                dash['allowed_packets'] += 1

        bg_emit('new_packet', pkt)

        with dash['lock']:
            total = dash['total_packets']
        if total % 20 == 0:
            push_stats()

    elif event_type == 'new_alert':
        alert = data
        with dash['lock']:
            dash['alerts'].append(alert)
            dash['total_alerts'] += 1
        bg_emit('new_alert', alert)
        print(f"  [!] {alert['severity']} — "
              f"{alert['attack_type']} from {alert['src_ip']}")

    elif event_type == 'block':
        bg_emit('ip_blocked', data)
        push_blocked_list()

    elif event_type == 'unblock':
        bg_emit('ip_unblocked', data)
        push_blocked_list()

    elif event_type == 'stats_update':
        push_stats()

ips_engine.register_callback(ips_callback)
block_engine.register_callback(ips_callback)

# ── Stats Helpers ──────────────────────────────────────────────────────────────

def push_stats():
    with dash['lock']:
        top = sorted(
            dash['top_talkers'].items(),
            key=lambda x: -x[1]
        )[:8]
        stats = {
            'total_packets'   : dash['total_packets'],
            'blocked_packets' : dash['blocked_packets'],
            'allowed_packets' : dash['allowed_packets'],
            'total_alerts'    : dash['total_alerts'],
            'protocol_counts' : dict(dash['protocol_counts']),
            'top_talkers'     : [{'ip': ip, 'count': c} for ip, c in top],
        }
    bg_emit('stats_update', stats)

def push_blocked_list():
    blocked = block_engine.get_blocked_list()
    bg_emit('blocked_list_update', {'blocked': blocked})

# ── Timeline Thread ────────────────────────────────────────────────────────────

def timeline_thread():
    last_count = 0
    while True:
        time.sleep(1)
        with dash['lock']:
            current = dash['total_packets']
        delta      = current - last_count
        last_count = current
        tick = {
            'time' : datetime.now().strftime('%H:%M:%S'),
            'count': delta,
        }
        with dash['lock']:
            dash['timeline'].append(tick)
        bg_emit('timeline_tick', tick)

# ── SocketIO Events ────────────────────────────────────────────────────────────

@socketio.on('connect', namespace='/')
def on_connect():
    print(f"[→] Browser connected")

    with dash['lock']:
        recent_packets = list(dash['packets'])[-50:]
        recent_alerts  = list(dash['alerts'])[-20:]
        top = sorted(
            dash['top_talkers'].items(),
            key=lambda x: -x[1]
        )[:8]
        initial = {
            'total_packets'   : dash['total_packets'],
            'blocked_packets' : dash['blocked_packets'],
            'allowed_packets' : dash['allowed_packets'],
            'total_alerts'    : dash['total_alerts'],
            'protocol_counts' : dict(dash['protocol_counts']),
            'top_talkers'     : [{'ip': ip, 'count': c} for ip, c in top],
            'recent_packets'  : recent_packets,
            'recent_alerts'   : recent_alerts,
            'timeline'        : list(dash['timeline']),
            'blocked_list'    : block_engine.get_blocked_list(),
            'block_history'   : block_engine.get_history(20),
        }
    emit('initial_state', initial)

@socketio.on('disconnect', namespace='/')
def on_disconnect():
    print(f"[←] Browser disconnected")

@socketio.on('ping_check', namespace='/')
def on_ping():
    emit('pong_check', {'status': 'alive'})

# ── Control Events (from dashboard buttons) ────────────────────────────────────

@socketio.on('manual_block', namespace='/')
def on_manual_block(data):
    """Browser requests manual block of an IP."""
    ip = data.get('ip', '').strip()
    if not ip:
        emit('control_response', {'success': False, 'msg': 'No IP provided'})
        return

    success = block_engine.block(ip, reason='Manual block via dashboard',
                                  attack_type='MANUAL')
    emit('control_response', {
        'success': success,
        'msg'    : f"{'Blocked' if success else 'Already blocked'}: {ip}",
    })
    push_blocked_list()

@socketio.on('manual_unblock', namespace='/')
def on_manual_unblock(data):
    """Browser requests manual unblock of an IP."""
    ip = data.get('ip', '').strip()
    if not ip:
        emit('control_response', {'success': False, 'msg': 'No IP provided'})
        return

    success = block_engine.unblock(ip, reason='Manual unblock via dashboard')
    emit('control_response', {
        'success': success,
        'msg'    : f"{'Unblocked' if success else 'Not found'}: {ip}",
    })
    push_blocked_list()

@socketio.on('whitelist_ip', namespace='/')
def on_whitelist(data):
    """Browser requests whitelisting an IP."""
    ip = data.get('ip', '').strip()
    if ip:
        block_engine.add_to_whitelist(ip)
        emit('control_response', {'success': True, 'msg': f"Whitelisted: {ip}"})
        push_blocked_list()

@socketio.on('request_history', namespace='/')
def on_request_history():
    emit('block_history', {'history': block_engine.get_history(50)})

# ── Route ──────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    with open(HTML_FILE, 'r', encoding='utf-8') as f:
        return render_template_string(f.read())

# ── Entry Point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("=" * 70)
    print("  NETWORK IPS — SIEM DASHBOARD")
    print("=" * 70)
    print(f"  URL     : http://localhost:5001")
    print(f"  Wait for '[✓] IPS engine active' before opening browser")
    print(f"  Ctrl+C  : stop server")
    print("=" * 70 + "\n")

    # Start background threads
    ips_engine.start()
    threading.Thread(target=timeline_thread, daemon=True).start()

    socketio.run(
        app,
        host        = '0.0.0.0',
        port        = 5001,
        debug       = False,
        use_reloader= False,
    )