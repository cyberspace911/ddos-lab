#!/bin/bash

# ============================================================================
# COMPREHENSIVE DDoS LAB MONITOR v3.0
# Real-time monitoring for both attacker and target
# ============================================================================

# Configuration
LOG_DIR="$HOME/ddos-enterprise-lab/shared/logs"
mkdir -p "$LOG_DIR"

# Target IP (Ubuntu)
TARGET_IP="192.168.1.5"

# Attacker IP (Kali)
ATTACKER_IP="192.168.1.6"

# Current machine IP
CURRENT_IP=$(hostname -I | cut -d' ' -f1)

# Determine if we're on target or attacker
if [ "$CURRENT_IP" = "$TARGET_IP" ]; then
    ROLE="TARGET"
elif [ "$CURRENT_IP" = "$ATTACKER_IP" ]; then
    ROLE="ATTACKER"
else
    ROLE="UNKNOWN"
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging function
log_monitor() {
    local message=$1
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" >> "$LOG_DIR/comprehensive_monitor.log"
}

# Function to calculate metrics with bc for precision
calculate_precise() {
    local value1=$1
    local value2=$2
    local operation=$3
    
    case $operation in
        "percent")
            if [ "$(echo "$value2 > 0" | bc -l)" = "1" ]; then
                echo "scale=2; ($value1 / $value2) * 100" | bc -l
            else
                echo "0"
            fi
            ;;
        "ratio")
            if [ "$(echo "$value2 > 0" | bc -l)" = "1" ]; then
                echo "scale=2; $value1 / $value2" | bc -l
            else
                echo "0"
            fi
            ;;
        *)
            echo "0"
            ;;
    esac
}

# Function to get target metrics via SSH or API
get_target_metrics() {
    # Try to get metrics from target
    # This is a simplified version - in real implementation would use SSH or API
    
    local metrics=""
    
    # If we're on the target, get local metrics
    if [ "$ROLE" = "TARGET" ]; then
        # Get connection statistics
        total_conn=$(netstat -ant 2>/dev/null | wc -l)
        syn_conn=$(netstat -ant 2>/dev/null | grep -c SYN_RECV)
        established_conn=$(netstat -ant 2>/dev/null | grep -c ESTABLISHED)
        
        # Get system load
        load1=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' ')
        
        # Get memory usage
        mem_total=$(free -m | awk '/^Mem:/ {print $2}')
        mem_used=$(free -m | awk '/^Mem:/ {print $3}')
        mem_percent=$(calculate_precise "$mem_used" "$mem_total" "percent")
        
        # Get network traffic (simplified)
        rx_bytes=0
        tx_bytes=0
        interface=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}')
        if [ -n "$interface" ] && [ -f "/sys/class/net/$interface/statistics/rx_bytes" ]; then
            rx_bytes=$(cat "/sys/class/net/$interface/statistics/rx_bytes")
            tx_bytes=$(cat "/sys/class/net/$interface/statistics/tx_bytes")
        fi
        
        # Calculate rates
        if [ -f /tmp/last_target_rx ]; then
            last_rx=$(cat /tmp/last_target_rx)
            last_tx=$(cat /tmp/last_target_tx)
            last_time=$(cat /tmp/last_target_time)
            current_time=$(date +%s)
            
            if [ $current_time -gt $last_time ]; then
                time_diff=$((current_time - last_time))
                rx_rate=$(((rx_bytes - last_rx) / time_diff))
                tx_rate=$(((tx_bytes - last_tx) / time_diff))
            else
                rx_rate=0
                tx_rate=0
            fi
        else
            rx_rate=0
            tx_rate=0
        fi
        
        # Save current values
        echo $rx_bytes > /tmp/last_target_rx
        echo $tx_bytes > /tmp/last_target_tx
        echo $(date +%s) > /tmp/last_target_time
        
        metrics="$total_conn:$syn_conn:$established_conn:$load1:$mem_percent:$rx_rate:$tx_rate"
    else
        # Try to get via API
        if curl -s --max-time 2 "http://$TARGET_IP/api/status" > /tmp/target_status.json 2>/dev/null; then
            # Parse JSON response (simplified)
            total_conn=$(grep -o '"connections":[0-9]*' /tmp/target_status.json | cut -d: -f2)
            load_val=$(grep -o '"cpu_load":[0-9.]*' /tmp/target_status.json | cut -d: -f2)
            
            if [ -z "$total_conn" ]; then
                total_conn=0
            fi
            if [ -z "$load_val" ]; then
                load_val=0
            fi
            
            # Estimate other values
            syn_conn=$((total_conn / 10))
            established_conn=$((total_conn - syn_conn))
            mem_percent=50
            rx_rate=1000000
            tx_rate=500000
            
            metrics="$total_conn:$syn_conn:$established_conn:$load_val:$mem_percent:$rx_rate:$tx_rate"
        else
            # Default values if cannot connect
            metrics="0:0:0:0:0:0:0"
        fi
    fi
    
    echo "$metrics"
}

# Function to get attacker metrics
get_attacker_metrics() {
    # If we're on the attacker, get local metrics
    if [ "$ROLE" = "ATTACKER" ]; then
        # Count attack processes
        syn_procs=$(ps aux | grep -c "[s]yn_flood")
        http_procs=$(ps aux | grep -c "[h]ttp_flood")
        udp_procs=$(ps aux | grep -c "[u]dp_flood")
        icmp_procs=$(ps aux | grep -c "[i]cmp_flood")
        hping_procs=$(ps aux | grep -c "[h]ping3")
        
        total_attacks=$((syn_procs + http_procs + udp_procs + icmp_procs + hping_procs))
        
        # Get system load
        load1=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' ')
        
        # Get network traffic to target
        connections_to_target=$(netstat -ant 2>/dev/null | grep -c "$TARGET_IP")
        
        metrics="$total_attacks:$syn_procs:$http_procs:$udp_procs:$icmp_procs:$load1:$connections_to_target"
    else
        # Default values if not on attacker
        metrics="0:0:0:0:0:0:0"
    fi
    
    echo "$metrics"
}

# Function to format bytes to human readable
format_bytes() {
    local bytes=$1
    
    if [ $bytes -gt 1073741824 ]; then
        echo "scale=2; $bytes / 1073741824" | bc -l
        echo " GB"
    elif [ $bytes -gt 1048576 ]; then
        echo "scale=2; $bytes / 1048576" | bc -l
        echo " MB"
    elif [ $bytes -gt 1024 ]; then
        echo "scale=2; $bytes / 1024" | bc -l
        echo " KB"
    else
        echo "$bytes"
        echo " B"
    fi
}

# Function to display comprehensive dashboard
display_dashboard() {
    while true; do
        clear
        
        # Get metrics
        target_metrics=$(get_target_metrics)
        attacker_metrics=$(get_attacker_metrics)
        
        IFS=':' read -r target_total target_syn target_est target_load target_mem target_rx target_tx <<< "$target_metrics"
        IFS=':' read -r attacker_total attacker_syn attacker_http attacker_udp attacker_icmp attacker_load attacker_conn <<< "$attacker_metrics"
        
        # Calculate SYN percentage
        if [ "$(echo "$target_total > 0" | bc -l)" = "1" ]; then
            syn_percent=$(calculate_precise "$target_syn" "$target_total" "percent")
        else
            syn_percent=0
        fi
        
        # Format traffic rates
        rx_formatted=$(format_bytes "$target_rx")
        tx_formatted=$(format_bytes "$target_tx")
        
        # Display header
        echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║                     COMPREHENSIVE DDoS LAB MONITOR v3.0                      ║${NC}"
        echo -e "${BLUE}║                     $(date)                                                  ║${NC}"
        echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        # System roles
        echo -e "${CYAN}🔧 SYSTEM ROLES${NC}"
        echo "────────────────────────────────────────────────────────────────"
        echo -e "Target (Ubuntu):   ${YELLOW}$TARGET_IP${NC} $(if [ "$ROLE" = "TARGET" ]; then echo -e "${GREEN}← CURRENT${NC}"; fi)"
        echo -e "Attacker (Kali):   ${YELLOW}$ATTACKER_IP${NC} $(if [ "$ROLE" = "ATTACKER" ]; then echo -e "${GREEN}← CURRENT${NC}"; fi)"
        echo ""
        
        # Target status
        echo -e "${CYAN}🎯 TARGET STATUS ($TARGET_IP)${NC}"
        echo "────────────────────────────────────────────────────────────────"
        
        # Connection analysis
        if [ "$(echo "$syn_percent > 50" | bc -l)" = "1" ]; then
            echo -e "Connections: ${RED}$target_total (SYN: $target_syn - ${syn_percent}%) ⚠️ POSSIBLE ATTACK${NC}"
            log_monitor "ALERT: High SYN connections detected on target: $target_syn (${syn_percent}%)"
        elif [ "$(echo "$syn_percent > 20" | bc -l)" = "1" ]; then
            echo -e "Connections: ${YELLOW}$target_total (SYN: $target_syn - ${syn_percent}%) ⚠️ MONITORING${NC}"
        else
            echo -e "Connections: ${GREEN}$target_total (SYN: $target_syn - ${syn_percent}%) ✅ NORMAL${NC}"
        fi
        
        echo -e "Established: $target_est"
        echo ""
        
        # System metrics
        echo -e "System Load: $(if [ "$(echo "$target_load > 2" | bc -l)" = "1" ]; then echo -e "${RED}$target_load ⚠️ HIGH${NC}"; \
                              elif [ "$(echo "$target_load > 1" | bc -l)" = "1" ]; then echo -e "${YELLOW}$target_load ⚠️ MODERATE${NC}"; \
                              else echo -e "${GREEN}$target_load ✅ NORMAL${NC}"; fi)"
        
        echo -e "Memory Usage: $(if [ "$(echo "$target_mem > 80" | bc -l)" = "1" ]; then echo -e "${RED}$target_mem% ⚠️ HIGH${NC}"; \
                               elif [ "$(echo "$target_mem > 60" | bc -l)" = "1" ]; then echo -e "${YELLOW}$target_mem% ⚠️ MODERATE${NC}"; \
                               else echo -e "${GREEN}$target_mem% ✅ NORMAL${NC}"; fi)"
        
        echo -e "Network In:  $rx_formatted/s"
        echo -e "Network Out: $tx_formatted/s"
        echo ""
        
        # Attacker status
        echo -e "${CYAN}⚡ ATTACKER STATUS ($ATTACKER_IP)${NC}"
        echo "────────────────────────────────────────────────────────────────"
        
        if [ $attacker_total -gt 0 ]; then
            echo -e "Active Attacks: ${RED}$attacker_total${NC}"
            
            if [ $attacker_syn -gt 0 ]; then
                echo -e "  • SYN Flood:    ${RED}$attacker_syn active${NC}"
            fi
            
            if [ $attacker_http -gt 0 ]; then
                echo -e "  • HTTP Flood:   ${RED}$attacker_http active${NC}"
            fi
            
            if [ $attacker_udp -gt 0 ]; then
                echo -e "  • UDP Flood:    ${RED}$attacker_udp active${NC}"
            fi
            
            if [ $attacker_icmp -gt 0 ]; then
                echo -e "  • ICMP Flood:   ${RED}$attacker_icmp active${NC}"
            fi
            
            echo -e "Connections to Target: $attacker_conn"
            echo -e "Attacker Load: $attacker_load"
            
        else
            echo -e "Active Attacks: ${GREEN}None${NC}"
        fi
        
        echo ""
        
        # Top connections analysis
        echo -e "${CYAN}📈 TOP CONNECTIONS ANALYSIS${NC}"
        echo "────────────────────────────────────────────────────────────────"
        
        if [ "$ROLE" = "TARGET" ]; then
            echo "Top Source IPs to Target:"
            netstat -ant 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -3 | while read count ip; do
                if [ "$ip" != "Address" ] && [ -n "$ip" ]; then
                    echo -e "  $count connections from $ip"
                fi
            done
        elif [ "$ROLE" = "ATTACKER" ]; then
            echo "Connections from Attacker to Target:"
            netstat -ant 2>/dev/null | grep "$TARGET_IP" | head -3 | while read line; do
                echo "  $line"
            done
            
            if [ $(netstat -ant 2>/dev/null | grep -c "$TARGET_IP") -eq 0 ]; then
                echo "  No active connections to target"
            fi
        fi
        
        echo ""
        
        # Recommendations
        echo -e "${CYAN}💡 RECOMMENDATIONS${NC}"
        echo "────────────────────────────────────────────────────────────────"
        
        if [ "$(echo "$syn_percent > 50" | bc -l)" = "1" ] && [ $attacker_total -gt 0 ]; then
            echo -e "${RED}✅ Attack is having significant impact on target${NC}"
            echo "  • Target shows high SYN connections"
            echo "  • Multiple attack vectors active"
            echo "  • Consider stopping attacks for analysis"
        elif [ "$(echo "$syn_percent > 20" | bc -l)" = "1" ]; then
            echo -e "${YELLOW}⚠️  Target is under moderate stress${NC}"
            echo "  • SYN connection percentage is elevated"
            echo "  • Monitor target response times"
        elif [ $attacker_total -gt 0 ]; then
            echo -e "${GREEN}✅ Attacks are running but target is handling them well${NC}"
            echo "  • Target metrics appear normal"
            echo "  • Consider increasing attack intensity"
        else
            echo -e "${BLUE}🔍 No active attacks detected${NC}"
            echo "  • Lab is idle"
            echo "  • Start attacks from Kali attacker"
        fi
        
        echo ""
        
        # Footer
        echo -e "${BLUE}════════════════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}Role: $ROLE | Refreshing every 3 seconds | Press Ctrl+C to exit${NC}"
        echo -e "${YELLOW}Logs: $LOG_DIR/comprehensive_monitor.log${NC}"
        
        sleep 3
    done
}

# Main execution
main() {
    echo -e "${BLUE}[+] Starting Comprehensive DDoS Lab Monitor${NC}"
    echo -e "${BLUE}[+] Detected role: $ROLE${NC}"
    echo -e "${BLUE}[+] Target: $TARGET_IP${NC}"
    echo -e "${BLUE}[+] Attacker: $ATTACKER_IP${NC}"
    echo ""
    
    log_monitor "Comprehensive monitor started"
    log_monitor "Role: $ROLE"
    log_monitor "Target: $TARGET_IP"
    log_monitor "Attacker: $ATTACKER_IP"
    
    display_dashboard
}

# Trap Ctrl+C
trap 'echo ""; echo -e "${RED}[+] Monitor stopped${NC}"; exit 0' INT

# Run main function
main
