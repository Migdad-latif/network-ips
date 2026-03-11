"""
benchmark.py
------------
Improvement 3: Performance benchmarking of the IPS detection engine.
Measures throughput, latency distribution, and resource usage.

Outputs:
    results/benchmark/throughput.png
    results/benchmark/latency_distribution.png
    results/benchmark/benchmark_report.txt
"""

import os
import sys
import time
import json
import random
import statistics
import platform
import threading
import psutil
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

BASE_DIR      = os.path.join(os.path.dirname(__file__), '..')
OUTPUT_DIR    = os.path.join(BASE_DIR, 'results', 'benchmark')
os.makedirs(OUTPUT_DIR, exist_ok=True)

plt.rcParams.update({
    'figure.facecolor' : '#0d1117',
    'axes.facecolor'   : '#0d1117',
    'axes.edgecolor'   : '#30363d',
    'axes.labelcolor'  : '#c9d1d9',
    'text.color'       : '#c9d1d9',
    'xtick.color'      : '#8b949e',
    'ytick.color'      : '#8b949e',
    'grid.color'       : '#21262d',
    'grid.alpha'       : 0.5,
    'font.family'      : 'monospace',
})

# ── Packet generator ───────────────────────────────────────────────────────────

def generate_packets(n: int) -> list:
    """
    Generates n synthetic packet dicts covering:
      benign HTTP/HTTPS/DNS, port scan probes, SYN floods, DNS amp
    """
    templates = [
        # Benign HTTP
        lambda: {'src_ip': f'10.0.{random.randint(0,255)}.{random.randint(1,254)}',
                 'dst_port': 80, 'protocol': 6,
                 'fwd_packets': random.randint(2, 20),
                 'bwd_packets': random.randint(2, 20),
                 'fwd_pkt_mean': random.uniform(200, 1400),
                 'flow_duration': random.uniform(10000, 5000000),
                 'flow_pps': random.uniform(10, 200)},
        # Benign HTTPS
        lambda: {'src_ip': f'192.168.{random.randint(0,10)}.{random.randint(1,254)}',
                 'dst_port': 443, 'protocol': 6,
                 'fwd_packets': random.randint(3, 30),
                 'bwd_packets': random.randint(3, 30),
                 'fwd_pkt_mean': random.uniform(300, 1200),
                 'flow_duration': random.uniform(50000, 10000000),
                 'flow_pps': random.uniform(5, 100)},
        # Port scan probe
        lambda: {'src_ip': '192.168.1.99',
                 'dst_port': random.randint(1, 65535), 'protocol': 6,
                 'fwd_packets': 1, 'bwd_packets': 1,
                 'fwd_pkt_mean': random.uniform(0, 2),
                 'flow_duration': random.uniform(20, 90),
                 'flow_pps': random.uniform(30000, 150000)},
        # SYN flood
        lambda: {'src_ip': f'172.16.{random.randint(0,255)}.1',
                 'dst_port': 80, 'protocol': 6,
                 'fwd_packets': random.randint(100, 500),
                 'bwd_packets': 0,
                 'fwd_pkt_mean': random.uniform(40, 60),
                 'flow_duration': random.uniform(10, 200),
                 'flow_pps': random.uniform(50000, 500000)},
        # DNS amplification
        lambda: {'src_ip': f'10.1.{random.randint(0,255)}.1',
                 'dst_port': 53, 'protocol': 17,
                 'fwd_packets': random.randint(50, 200),
                 'bwd_packets': random.randint(50, 200),
                 'fwd_pkt_mean': random.uniform(50, 100),
                 'flow_duration': random.uniform(1000, 50000),
                 'flow_pps': random.uniform(1000, 10000)},
    ]
    return [random.choice(templates)() for _ in range(n)]


# ── Latency benchmark ─────────────────────────────────────────────────────────

def benchmark_latency(detector, packets: list) -> list:
    """Times each individual predict() call. Returns list of ns latencies."""
    latencies = []
    for pkt in packets:
        t0 = time.perf_counter_ns()
        detector.predict(pkt)
        latencies.append(time.perf_counter_ns() - t0)
    return latencies


# ── Throughput benchmark ──────────────────────────────────────────────────────

def benchmark_throughput(detector, packets: list, duration_sec: int = 5) -> dict:
    """
    Runs detection in a tight loop for duration_sec seconds.
    Returns packets_per_second and total packets processed.
    """
    count     = 0
    n         = len(packets)
    deadline  = time.perf_counter() + duration_sec

    while time.perf_counter() < deadline:
        detector.predict(packets[count % n])
        count += 1

    pps = count / duration_sec
    return {'packets_processed': count, 'duration_sec': duration_sec,
            'packets_per_second': pps}


# ── Resource monitor ──────────────────────────────────────────────────────────

class ResourceMonitor:
    """Samples CPU and memory in a background thread."""

    def __init__(self, interval: float = 0.1):
        self.interval = interval
        self.cpu      = []
        self.mem      = []
        self._stop    = threading.Event()
        self._thread  = threading.Thread(target=self._sample, daemon=True)

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join()

    def _sample(self):
        while not self._stop.is_set():
            self.cpu.append(psutil.cpu_percent(interval=None))
            self.mem.append(psutil.Process().memory_info().rss / 1024 / 1024)
            time.sleep(self.interval)

    def summary(self) -> dict:
        return {
            'cpu_mean_pct'  : round(statistics.mean(self.cpu), 2) if self.cpu else 0,
            'cpu_max_pct'   : round(max(self.cpu), 2) if self.cpu else 0,
            'mem_mean_mb'   : round(statistics.mean(self.mem), 2) if self.mem else 0,
            'mem_max_mb'    : round(max(self.mem), 2) if self.mem else 0,
        }


# ── Plots ─────────────────────────────────────────────────────────────────────

def plot_latency(latencies: list) -> None:
    lat_us = [l / 1000 for l in latencies]   # ns → µs

    fig, axes = plt.subplots(1, 2, figsize=(12, 4))

    # Histogram
    axes[0].hist(lat_us, bins=60, color='#00ff41', alpha=0.8, edgecolor='#0d1117')
    axes[0].axvline(statistics.median(lat_us), color='#ffaa00',
                    linestyle='--', label=f'p50={statistics.median(lat_us):.1f}µs')
    axes[0].axvline(
        sorted(lat_us)[int(len(lat_us)*0.99)], color='#ff4444',
        linestyle='--',
        label=f'p99={sorted(lat_us)[int(len(lat_us)*0.99)]:.1f}µs')
    axes[0].set_title('Latency Distribution', color='#00ff41')
    axes[0].set_xlabel('Latency (µs)')
    axes[0].set_ylabel('Count')
    axes[0].legend(facecolor='#0d1117', edgecolor='#30363d', labelcolor='#c9d1d9')
    axes[0].grid(True, alpha=0.3)

    # CDF
    sorted_lat = sorted(lat_us)
    cdf = [i / len(sorted_lat) for i in range(len(sorted_lat))]
    axes[1].plot(sorted_lat, cdf, color='#00ff41', linewidth=2)
    axes[1].axhline(0.99, color='#ff4444', linestyle='--', alpha=0.7, label='p99')
    axes[1].axhline(0.95, color='#ffaa00', linestyle='--', alpha=0.7, label='p95')
    axes[1].set_title('Latency CDF', color='#00ff41')
    axes[1].set_xlabel('Latency (µs)')
    axes[1].set_ylabel('Cumulative Probability')
    axes[1].legend(facecolor='#0d1117', edgecolor='#30363d', labelcolor='#c9d1d9')
    axes[1].grid(True, alpha=0.3)
    axes[1].set_xlim(left=0, right=sorted(lat_us)[int(len(lat_us)*0.999)])

    path = os.path.join(OUTPUT_DIR, 'latency_distribution.png')
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='#0d1117')
    plt.close()
    print(f"[✓] Latency plot       -> {path}")


def plot_throughput(results: list) -> None:
    """Plots throughput across different packet set sizes."""
    sizes = [r['packet_count'] for r in results]
    pps   = [r['packets_per_second'] for r in results]

    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(range(len(sizes)), pps, color='#00ff41', alpha=0.8,
           edgecolor='#0d1117')
    ax.set_xticks(range(len(sizes)))
    ax.set_xticklabels([f"{s:,}" for s in sizes])
    ax.set_title('Throughput by Packet Pool Size', color='#00ff41', fontsize=13)
    ax.set_xlabel('Packet Pool Size')
    ax.set_ylabel('Packets / Second')
    ax.grid(True, alpha=0.3, axis='y')

    for i, v in enumerate(pps):
        ax.text(i, v + max(pps)*0.01, f'{v/1000:.0f}k', ha='center',
                color='#c9d1d9', fontsize=9)

    path = os.path.join(OUTPUT_DIR, 'throughput.png')
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor='#0d1117')
    plt.close()
    print(f"[✓] Throughput plot    -> {path}")


# ── Report ─────────────────────────────────────────────────────────────────────

def save_report(latencies, throughput_results, resources) -> None:
    lat_us     = sorted(l / 1000 for l in latencies)
    n          = len(lat_us)

    report = {
        'system': {
            'platform'  : platform.system(),
            'processor' : platform.processor(),
            'python'    : platform.python_version(),
            'cpu_count' : os.cpu_count(),
        },
        'latency_us': {
            'p50'  : round(lat_us[int(n*0.50)], 3),
            'p75'  : round(lat_us[int(n*0.75)], 3),
            'p95'  : round(lat_us[int(n*0.95)], 3),
            'p99'  : round(lat_us[int(n*0.99)], 3),
            'p999' : round(lat_us[int(n*0.999)], 3),
            'mean' : round(statistics.mean(lat_us), 3),
            'max'  : round(lat_us[-1], 3),
        },
        'throughput': throughput_results,
        'resources' : resources,
    }

    path = os.path.join(OUTPUT_DIR, 'benchmark_report.txt')
    with open(path, 'w') as f:
        f.write("NETWORK IPS — PERFORMANCE BENCHMARK\n")
        f.write(f"Generated : {__import__('datetime').datetime.now().isoformat()}\n")
        f.write("="*55 + "\n\n")

        f.write("SYSTEM\n")
        for k, v in report['system'].items():
            f.write(f"  {k:<12}: {v}\n")

        f.write("\nLATENCY (µs per decision)\n")
        for k, v in report['latency_us'].items():
            f.write(f"  {k:<6}: {v}\n")

        f.write("\nTHROUGHPUT\n")
        for r in report['throughput']:
            f.write(f"  {r['packet_count']:>8,} packet pool -> "
                    f"{r['packets_per_second']:>10,.0f} pps\n")

        f.write("\nRESOURCES (during throughput test)\n")
        for k, v in report['resources'].items():
            f.write(f"  {k:<16}: {v}\n")

    json_path = os.path.join(OUTPUT_DIR, 'benchmark_report.json')
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"[✓] Report saved       -> {path}")
    print(f"[✓] JSON saved         -> {json_path}")

    # Print summary
    print("\n" + "="*55)
    print("  BENCHMARK RESULTS")
    print("="*55)
    print(f"  Latency  p50  : {report['latency_us']['p50']} µs")
    print(f"  Latency  p95  : {report['latency_us']['p95']} µs")
    print(f"  Latency  p99  : {report['latency_us']['p99']} µs")
    print(f"  Throughput    : {throughput_results[-1]['packets_per_second']:,.0f} pps")
    print(f"  CPU (mean)    : {resources['cpu_mean_pct']} %")
    print(f"  Memory (max)  : {resources['mem_max_mb']} MB")
    print("="*55)


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    sys.path.insert(0, os.path.join(BASE_DIR, 'src'))
    from evaluator import SignatureDetector

    detector = SignatureDetector()

    print("[*] Generating synthetic packets...")
    latency_packets    = generate_packets(10_000)
    throughput_packets = generate_packets(50_000)

    # ── Latency benchmark
    print("[*] Running latency benchmark (10,000 packets)...")
    latencies = benchmark_latency(detector, latency_packets)
    lat_us = sorted(l / 1000 for l in latencies)
    print(f"    p50={lat_us[5000]:.2f}µs  "
          f"p95={lat_us[9500]:.2f}µs  "
          f"p99={lat_us[9900]:.2f}µs")

    # ── Throughput benchmark across pool sizes
    print("[*] Running throughput benchmark (5s each)...")
    throughput_results = []
    for pool_size in [1_000, 5_000, 10_000, 50_000]:
        pool   = generate_packets(pool_size)
        result = benchmark_throughput(detector, pool, duration_sec=5)
        result['packet_count'] = pool_size
        throughput_results.append(result)
        print(f"    Pool {pool_size:>6,}: {result['packets_per_second']:>10,.0f} pps")

    # ── Resource monitoring during final throughput test
    print("[*] Monitoring resources during sustained load (10s)...")
    monitor = ResourceMonitor(interval=0.2).start()
    benchmark_throughput(detector, throughput_packets, duration_sec=10)
    monitor.stop()
    resources = monitor.summary()

    # ── Save outputs
    plot_latency(latencies)
    plot_throughput(throughput_results)
    save_report(latencies, throughput_results, resources)


if __name__ == '__main__':
    main()