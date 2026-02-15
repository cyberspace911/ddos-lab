#!/bin/bash

# ============================================================================
# ENTERPRISE DDoS DEFENSE CONTROLLER v3.0
# Ubuntu Server - 192.168.1.5
# ============================================================================

# Configuration
CONFIG_DIR="$HOME/ddos-enterprise-lab/ubuntu-server"
LOG_DIR="$CONFIG_DIR/logs"
BACKUP_DIR="$CONFIG_DIR/backup"
MONITOR_DIR="$CONFIG_DIR/monitoring"
FORENSIC_DIR="$CONFIG_DIR/forensic"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Ensure directories exist
mkdir -p "$LOG_DIR" "$BACKUP_DIR" "$MONITOR_DIR" "$FORENSIC_DIR"

# Logging function
log_event() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO") color=$GREEN ;;
        "WARN") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "DEBUG") color=$CYAN ;;
        *) color=$NC ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}"
    echo "[$timestamp] [$level] $message" >> "$LOG_DIR/defense_controller.log"
}

# Check root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_event "ERROR" "This script requires root privileges. Use: sudo $0"
        exit 1
    fi
}

# Backup current system state
backup_current_state() {
    log_event "INFO" "Backing up current system state..."
    
    local backup_file="$BACKUP_DIR/system_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
    
    # Backup iptables rules
    iptables-save > "$BACKUP_DIR/iptables_backup.rules"
    
    # Backup sysctl settings
    sysctl -a > "$BACKUP_DIR/sysctl_backup.conf" 2>/dev/null
    
    # Backup important config files
    tar -czf "$backup_file" \
        /etc/iptables/ \
        /etc/sysctl.d/ \
        /etc/network/ \
        /etc/ssh/ \
        2>/dev/null
    
    log_event "INFO" "Backup saved to: $backup_file"
    log_event "INFO" "To restore: tar -xzf $backup_file -C /"
}

# Set defense level: 0=None, 1=Medium, 2=Enterprise
set_defense_level() {
    local level=$1
    
    log_event "INFO" "Setting defense level: $level"
    
    case $level in
        0)
            # NO DEFENSE - Vulnerable state
            log_event "WARN" "Setting NO DEFENSE state - SERVER IS VULNERABLE!"
            
            # Flush all rules
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            iptables -t mangle -F
            iptables -t mangle -X
            
            # Accept all traffic
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT
            
            # Disable SYN cookies
            sysctl -w net.ipv4.tcp_syncookies=0
            
            # Save rules
            iptables-save > /etc/iptables/rules.v4
            
            log_event "INFO" "NO DEFENSE state activated"
            ;;
            
        1)
            # MEDIUM DEFENSE - Basic protection
            log_event "INFO" "Setting MEDIUM DEFENSE state"
            
            # Flush existing rules
            iptables -F
            iptables -X
            
            # Default policies
            iptables -P INPUT ACCEPT
            iptables -P FORWARD DROP
            iptables -P OUTPUT ACCEPT
            
            # Allow established connections
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            
            # Basic SYN protection
            iptables -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
            iptables -A INPUT -p tcp --syn -j DROP
            
            # Web server protection
            iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m limit --limit 50/min --limit-burst 100 -j ACCEPT
            iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j DROP
            
            # SSH protection
            iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
            iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT
            
            # ICMP protection
            iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 2/s -j ACCEPT
            iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
            
            # Enable SYN cookies
            sysctl -w net.ipv4.tcp_syncookies=1
            
            # Save rules
            iptables-save > /etc/iptables/rules.v4
            
            log_event "INFO" "MEDIUM DEFENSE state activated"
            ;;
            
        2)
            # ENTERPRISE DEFENSE - Maximum protection
            log_event "INFO" "Setting ENTERPRISE DEFENSE state"
            
            # Flush all rules
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            iptables -t mangle -F
            iptables -t mangle -X
            
            # Default policies
            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT ACCEPT
            
            # Allow established connections
            iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            
            # SYN flood protection chain
            iptables -N SYN_FLOOD
            iptables -A INPUT -p tcp --syn -j SYN_FLOOD
            
            # Rate limiting per IP for SYN
            iptables -A SYN_FLOOD -m recent --name synflood --set --rsource
            iptables -A SYN_FLOOD -m recent --name synflood --update --seconds 60 --hitcount 50 --rsource -j DROP
            iptables -A SYN_FLOOD -j ACCEPT
            
            # Web server protection with strict limits
            iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m limit --limit 20/s --limit-burst 40 -j ACCEPT
            iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m limit --limit 20/s --limit-burst 40 -j ACCEPT
            iptables -A INPUT -p tcp -m multiport --dports 80,443 -m state --state NEW -j DROP
            
            # SSH protection with aggressive limits
            iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH --rsource
            iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 300 --hitcount 3 --rsource -j DROP
            iptables -A INPUT -p tcp --dport 22 -j ACCEPT
            
            # ICMP protection
            iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT
            iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
            
            # UDP protection
            iptables -A INPUT -p udp -m state --state NEW -m limit --limit 100/s --limit-burst 200 -j ACCEPT
            iptables -A INPUT -p udp -m state --state NEW -j DROP
            
            # Connection limiting
            iptables -A INPUT -p tcp -m state --state NEW -m connlimit --connlimit-above 30 --connlimit-mask 32 -j DROP
            
            # Attack logging
            iptables -A INPUT -p tcp --tcp-flags ALL SYN -j LOG --log-prefix "[SYN_ATTACK] " --log-level 4
            iptables -A INPUT -p tcp --tcp-flags ALL ACK -j LOG --log-prefix "[ACK_ATTACK] " --log-level 4
            iptables -A INPUT -p udp -j LOG --log-prefix "[UDP_ATTACK] " --log-level 4
            iptables -A INPUT -p icmp -j LOG --log-prefix "[ICMP_ATTACK] " --log-level 4
            
            # Block malicious patterns
            iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
            iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
            iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
            
            # Final drop with logging
            iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[IPTABLES_DROP] " --log-level 4
            iptables -A INPUT -j DROP
            
            # Kernel hardening
            cat > /etc/sysctl.d/99-ddos-protection.conf << 'SYSCTL'
# SYN Flood Protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 2048

# TCP Stack Hardening
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300

# IP Spoofing Protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0

# ICMP Protection
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Network Optimization
net.core.netdev_max_backlog = 30000
net.core.somaxconn = 65535
net.ipv4.tcp_max_tw_buckets = 1440000

# Connection Tracking
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
SYSCTL
            
            sysctl -p /etc/sysctl.d/99-ddos-protection.conf
            
            # Save rules
            iptables-save > /etc/iptables/rules.v4
            
            log_event "INFO" "ENTERPRISE DEFENSE state activated"
            ;;
            
        *)
            log_event "ERROR" "Invalid defense level: $level"
            return 1
            ;;
    esac
    
    return 0
}

# Show current defense status
show_defense_status() {
    log_event "INFO" "Checking current defense status..."
    
    echo ""
    echo -e "${BLUE}===============================================${NC}"
    echo -e "${BLUE}           CURRENT DEFENSE STATUS             ${NC}"
    echo -e "${BLUE}===============================================${NC}"
    echo ""
    
    # Check iptables default policy
    INPUT_POLICY=$(iptables -L INPUT -n 2>/dev/null | head -1 | awk '{print $4}' | tr -d ')')
    
    echo -e "${CYAN}Firewall Status:${NC}"
    echo "-----------------"
    iptables -L INPUT -n --line-numbers | head -20
    
    echo ""
    echo -e "${CYAN}Connection Statistics:${NC}"
    echo "-------------------------"
    echo "Total Connections: $(netstat -ant 2>/dev/null | wc -l)"
    echo "SYN_RECV: $(netstat -ant 2>/dev/null | grep -c SYN_RECV)"
    echo "ESTABLISHED: $(netstat -ant 2>/dev/null | grep -c ESTABLISHED)"
    echo "LISTEN: $(netstat -ant 2>/dev/null | grep -c LISTEN)"
    
    echo ""
    echo -e "${CYAN}Top Source IPs:${NC}"
    echo "-----------------"
    netstat -ant 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -5
    
    echo ""
    echo -e "${CYAN}System Metrics:${NC}"
    echo "-----------------"
    echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
    echo "Memory Usage: $(free -h | awk '/^Mem:/ {print $3"/"$2 " ("int($3/$2*100)"%)"}')"
    
    echo ""
    echo -e "${CYAN}Defense Level Detection:${NC}"
    echo "--------------------------"
    
    SYN_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -c "syn")
    DROP_RULES=$(iptables -L INPUT -n 2>/dev/null | grep -c "DROP")
    
    if [ "$INPUT_POLICY" = "DROP" ] && [ $SYN_RULES -gt 2 ]; then
        echo -e "${GREEN}✅ ENTERPRISE DEFENSE (Maximum Protection)${NC}"
    elif [ "$INPUT_POLICY" = "ACCEPT" ] && [ $SYN_RULES -gt 0 ]; then
        echo -e "${YELLOW}⚠️  MEDIUM DEFENSE (Basic Protection)${NC}"
    elif [ "$INPUT_POLICY" = "ACCEPT" ]; then
        echo -e "${RED}🚨 NO DEFENSE (Vulnerable)${NC}"
    else
        echo -e "${BLUE}🔧 CUSTOM DEFENSE${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}===============================================${NC}"
}

# Collect forensic evidence
collect_evidence() {
    local incident_id=$1
    
    log_event "INFO" "Collecting forensic evidence for incident: $incident_id"
    
    local evidence_dir="$FORENSIC_DIR/incident_$incident_id"
    mkdir -p "$evidence_dir"
    
    echo ""
    echo -e "${BLUE}Collecting Forensic Evidence${NC}"
    echo "=============================="
    
    # System information
    log_event "DEBUG" "Collecting system information..."
    uname -a > "$evidence_dir/system_info.txt"
    cat /etc/os-release >> "$evidence_dir/system_info.txt"
    
    # Network information
    log_event "DEBUG" "Collecting network information..."
    ip addr show > "$evidence_dir/network_info.txt"
    route -n >> "$evidence_dir/network_info.txt"
    
    # Current connections
    log_event "DEBUG" "Collecting network connections..."
    netstat -ant > "$evidence_dir/connections.txt"
    ss -tuln > "$evidence_dir/sockets.txt"
    
    # Process information
    log_event "DEBUG" "Collecting process information..."
    ps aux > "$evidence_dir/processes.txt"
    top -b -n 1 > "$evidence_dir/top_output.txt"
    
    # System metrics
    log_event "DEBUG" "Collecting system metrics..."
    uptime > "$evidence_dir/uptime.txt"
    free -h > "$evidence_dir/memory.txt"
    df -h > "$evidence_dir/disk.txt"
    
    # Firewall state
    log_event "DEBUG" "Collecting firewall state..."
    iptables -L -n -v > "$evidence_dir/firewall_rules.txt"
    iptables-save > "$evidence_dir/firewall_backup.rules"
    
    # System logs
    log_event "DEBUG" "Collecting system logs..."
    dmesg | tail -100 > "$evidence_dir/dmesg.log"
    tail -100 /var/log/syslog > "$evidence_dir/syslog_tail.log"
    tail -100 /var/log/kern.log > "$evidence_dir/kern.log"
    
    # Create incident report
    log_event "DEBUG" "Creating incident report..."
    cat > "$evidence_dir/incident_report.md" << 'REPORT'
# DDoS INCIDENT FORENSIC REPORT

## Incident Details
- ID: $incident_id
- Date: $(date)
- Host: $(hostname)
- IP Address: $(hostname -I | cut -d' ' -f1)

## Evidence Collected
1. System Information
2. Network Configuration
3. Active Connections
4. Running Processes
5. System Performance Metrics
6. Firewall Rules
7. System Logs

## Analysis Summary
$(date): Incident detected and evidence collected.

## Timeline
- $(date): Evidence collection started
- $(date): System state captured
- $(date): Network traffic analyzed
- $(date): Forensic report generated

## Recommendations
1. Review firewall rules for effectiveness
2. Monitor for recurring attack patterns
3. Implement additional rate limiting if needed
4. Regular security audits

## Status
INCIDENT DOCUMENTED - EVIDENCE PRESERVED
REPORT
    
    log_event "INFO" "Evidence collected in: $evidence_dir"
    echo ""
    ls -la "$evidence_dir"
    echo ""
}

# Start real-time monitoring
start_monitoring() {
    log_event "INFO" "Starting real-time monitoring..."
    
    # Create monitoring script
    cat > "$MONITOR_DIR/realtime_monitor.sh" << 'MONITOR'
#!/bin/bash

# Real-time DDoS Monitoring Dashboard

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Log file
LOG_FILE="$HOME/ddos-enterprise-lab/ubuntu-server/logs/monitor.log"

# Function to log to file
log_monitor() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Function to calculate metrics
calculate_metrics() {
    # Connection statistics
    total_conn=$(netstat -ant 2>/dev/null | wc -l)
    syn_conn=$(netstat -ant 2>/dev/null | grep -c SYN_RECV)
    established_conn=$(netstat -ant 2>/dev/null | grep -c ESTABLISHED)
    
    # Calculate SYN percentage
    if [ $total_conn -gt 0 ]; then
        syn_percent=$((syn_conn * 100 / total_conn))
    else
        syn_percent=0
    fi
    
    # System load
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F, '{print $1}' | tr -d ' ')
    
    # Memory usage
    mem_total=$(free -m | awk '/^Mem:/ {print $2}')
    mem_used=$(free -m | awk '/^Mem:/ {print $3}')
    if [ $mem_total -gt 0 ]; then
        mem_percent=$((mem_used * 100 / mem_total))
    else
        mem_percent=0
    fi
    
    # Network traffic (simplified)
    rx_bytes=$(cat /sys/class/net/$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}')/statistics/rx_bytes 2>/dev/null || echo 0)
    tx_bytes=$(cat /sys/class/net/$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}')/statistics/tx_bytes 2>/dev/null || echo 0)
    
    # Calculate traffic rate (bytes per second)
    if [ -f /tmp/last_rx ]; then
        last_rx=$(cat /tmp/last_rx)
        last_tx=$(cat /tmp/last_tx)
        last_time=$(cat /tmp/last_time)
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
    echo $rx_bytes > /tmp/last_rx
    echo $tx_bytes > /tmp/last_tx
    echo $(date +%s) > /tmp/last_time
    
    # Return metrics
    echo "$total_conn:$syn_conn:$established_conn:$syn_percent:$load_avg:$mem_percent:$rx_rate:$tx_rate"
}

# Main monitoring loop
while true; do
    clear
    
    # Get metrics
    metrics=$(calculate_metrics)
    IFS=':' read -r total_conn syn_conn established_conn syn_percent load_avg mem_percent rx_rate tx_rate <<< "$metrics"
    
    # Convert traffic rates to human readable
    if [ $rx_rate -gt 1048576 ]; then
        rx_display=$(echo "scale=2; $rx_rate / 1048576" | bc)
        rx_unit="MB/s"
    elif [ $rx_rate -gt 1024 ]; then
        rx_display=$(echo "scale=2; $rx_rate / 1024" | bc)
        rx_unit="KB/s"
    else
        rx_display=$rx_rate
        rx_unit="B/s"
    fi
    
    if [ $tx_rate -gt 1048576 ]; then
        tx_display=$(echo "scale=2; $tx_rate / 1048576" | bc)
        tx_unit="MB/s"
    elif [ $tx_rate -gt 1024 ]; then
        tx_display=$(echo "scale=2; $tx_rate / 1024" | bc)
        tx_unit="KB/s"
    else
        tx_display=$tx_rate
        tx_unit="B/s"
    fi
    
    # Display header
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                ENTERPRISE DDoS MONITORING DASHBOARD           ║${NC}"
    echo -e "${BLUE}║                $(date)                                         ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Connection statistics
    echo -e "${CYAN}📊 NETWORK CONNECTIONS${NC}"
    echo "────────────────────────────────"
    echo -e "Total Connections: ${YELLOW}$total_conn${NC}"
    
    if [ $syn_percent -gt 50 ]; then
        echo -e "SYN_RECV: ${RED}$syn_conn (${syn_percent}%) ⚠️ POSSIBLE ATTACK${NC}"
        log_monitor "WARNING: High SYN connections detected: $syn_conn (${syn_percent}%)"
    elif [ $syn_percent -gt 20 ]; then
        echo -e "SYN_RECV: ${YELLOW}$syn_conn (${syn_percent}%) ⚠️ WATCHING${NC}"
    else
        echo -e "SYN_RECV: ${GREEN}$syn_conn (${syn_percent}%) ✅ NORMAL${NC}"
    fi
    
    echo -e "ESTABLISHED: ${GREEN}$established_conn${NC}"
    echo ""
    
    # Top source IPs
    echo -e "${CYAN}👥 TOP SOURCE IPs${NC}"
    echo "────────────────────────────────"
    netstat -ant 2>/dev/null | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -5
    echo ""
    
    # System metrics
    echo -e "${CYAN}⚡ SYSTEM METRICS${NC}"
    echo "────────────────────────────────"
    
    # Load average
    load_val=$(echo $load_avg | bc)
    if (( $(echo "$load_val > 2.0" | bc -l) )); then
        echo -e "Load Average: ${RED}$load_avg ⚠️ HIGH LOAD${NC}"
    elif (( $(echo "$load_val > 1.0" | bc -l) )); then
        echo -e "Load Average: ${YELLOW}$load_avg ⚠️ MODERATE${NC}"
    else
        echo -e "Load Average: ${GREEN}$load_avg ✅ NORMAL${NC}"
    fi
    
    # Memory usage
    if [ $mem_percent -gt 80 ]; then
        echo -e "Memory Usage: ${RED}${mem_percent}% ⚠️ HIGH USAGE${NC}"
    elif [ $mem_percent -gt 60 ]; then
        echo -e "Memory Usage: ${YELLOW}${mem_percent}% ⚠️ MODERATE${NC}"
    else
        echo -e "Memory Usage: ${GREEN}${mem_percent}% ✅ NORMAL${NC}"
    fi
    
    echo ""
    
    # Network traffic
    echo -e "${CYAN}🌐 NETWORK TRAFFIC${NC}"
    echo "────────────────────────────────"
    echo -e "Incoming: ${CYAN}${rx_display} ${rx_unit}${NC}"
    echo -e "Outgoing: ${CYAN}${tx_display} ${tx_unit}${NC}"
    echo ""
    
    # Recent alerts from logs
    echo -e "${CYAN}🚨 RECENT ALERTS${NC}"
    echo "────────────────────────────────"
    tail -5 "$LOG_FILE" 2>/dev/null | grep -i "warning\|attack\|error" || echo "No recent alerts"
    echo ""
    
    # Firewall statistics
    echo -e "${CYAN}🛡️ FIREWALL STATS${NC}"
    echo "────────────────────────────────"
    iptables -L INPUT -vn 2>/dev/null | grep -E "(pkts|DROP|ACCEPT)" | head -3
    echo ""
    
    # Footer
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Monitoring... (Press Ctrl+C to exit) | Refreshing every 2 seconds${NC}"
    
    sleep 2
done
MONITOR
    
    chmod +x "$MONITOR_DIR/realtime_monitor.sh"
    
    # Start monitoring in background
    "$MONITOR_DIR/realtime_monitor.sh" &
    MONITOR_PID=$!
    
    echo $MONITOR_PID > "$MONITOR_DIR/monitor.pid"
    log_event "INFO" "Monitoring started with PID: $MONITOR_PID"
}

# Stop monitoring
stop_monitoring() {
    if [ -f "$MONITOR_DIR/monitor.pid" ]; then
        monitor_pid=$(cat "$MONITOR_DIR/monitor.pid")
        if kill -0 $monitor_pid 2>/dev/null; then
            kill $monitor_pid
            log_event "INFO" "Monitoring stopped (PID: $monitor_pid)"
            rm -f "$MONITOR_DIR/monitor.pid"
        fi
    fi
}

# Display main menu
show_menu() {
    while true; do
        clear
        echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${BLUE}║         ENTERPRISE DDoS DEFENSE CONTROLLER v3.0         ║${NC}"
        echo -e "${BLUE}║               Ubuntu Server - $(hostname)               ║${NC}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        echo -e "${CYAN}🎯 TARGET INFORMATION${NC}"
        echo "────────────────────────────"
        echo "IP Address: $(hostname -I | cut -d' ' -f1)"
        echo "Hostname: $(hostname)"
        echo ""
        
        echo -e "${GREEN}MAIN MENU${NC}"
        echo "──────────"
        echo "1. 🛡️  Set Defense Level"
        echo "2. 📊 Show Defense Status"
        echo "3. 📈 Start Real-time Monitoring"
        echo "4. 🛑 Stop Monitoring"
        echo "5. 🔍 Collect Forensic Evidence"
        echo "6. 💾 Backup System State"
        echo "7. 📋 View Logs"
        echo "8. 🚪 Exit"
        echo ""
        
        read -p "Select option [1-8]: " choice
        
        case $choice in
            1)
                echo ""
                echo -e "${YELLOW}Select Defense Level:${NC}"
                echo "1. 🚨 NO DEFENSE (Vulnerable - for testing)"
                echo "2. ⚠️  MEDIUM DEFENSE (Basic protection)"
                echo "3. ✅ ENTERPRISE DEFENSE (Maximum protection)"
                echo ""
                read -p "Choice [1-3]: " defense_choice
                
                case $defense_choice in
                    1) set_defense_level 0 ;;
                    2) set_defense_level 1 ;;
                    3) set_defense_level 2 ;;
                    *) echo "Invalid choice" ;;
                esac
                
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            2)
                show_defense_status
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            3)
                start_monitoring
                echo ""
                echo -e "${GREEN}Monitoring started in background${NC}"
                echo -e "Check logs in: $LOG_DIR"
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            4)
                stop_monitoring
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            5)
                incident_id=$(date +%s)
                collect_evidence $incident_id
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            6)
                backup_current_state
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            7)
                echo ""
                echo -e "${CYAN}Available Logs:${NC}"
                echo "───────────────"
                ls -la "$LOG_DIR"/*.log 2>/dev/null || echo "No logs found"
                echo ""
                echo "Select log to view:"
                echo "1. Defense Controller Log"
                echo "2. Monitor Log"
                echo "3. System Logs"
                echo "4. Back to Menu"
                echo ""
                
                read -p "Choice: " log_choice
                
                case $log_choice in
                    1) tail -50 "$LOG_DIR/defense_controller.log" ;;
                    2) tail -50 "$LOG_DIR/monitor.log" 2>/dev/null || echo "No monitor log" ;;
                    3) sudo tail -50 /var/log/syslog ;;
                esac
                
                echo ""
                read -p "Press Enter to continue..."
                ;;
                
            8)
                stop_monitoring
                echo ""
                echo -e "${GREEN}Exiting Defense Controller...${NC}"
                echo -e "Thank you for using Enterprise DDoS Lab"
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
    check_root
    
    # Create necessary directories
    mkdir -p "$LOG_DIR" "$BACKUP_DIR" "$MONITOR_DIR" "$FORENSIC_DIR"
    
    # Initialize log
    log_event "INFO" "DDoS Defense Controller started"
    log_event "INFO" "Host: $(hostname)"
    log_event "INFO" "IP: $(hostname -I | cut -d' ' -f1)"
    
    # Show menu
    show_menu
}

# Run main function
main "$@"
