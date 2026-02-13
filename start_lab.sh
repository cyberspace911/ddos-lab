#!/bin/bash

# Enterprise DDoS Lab - Startup Script

echo "==============================================="
echo "   ENTERPRISE DDoS LAB - STARTUP v3.0"
echo "==============================================="
echo ""

# Check if setup is complete
if [ ! -f ~/ddos-enterprise-lab/setup_lab.sh ]; then
    echo "[!] Lab setup not found."
    echo "[+] Please run the setup script first."
    echo ""
    read -p "Run setup now? (y/N): " run_setup
    if [[ $run_setup == [yY] ]]; then
        ./setup_lab.sh
    else
        exit 1
    fi
fi

# Get system info
CURRENT_IP=$(hostname -I | cut -d' ' -f1)
OS=$(grep -E '^(NAME)=' /etc/os-release | cut -d'=' -f2 | tr -d '"')

echo "System: $OS"
echo "IP: $CURRENT_IP"
echo ""

# Determine role
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    ROLE="target"
elif [[ "$OS" == *"Kali"* ]]; then
    ROLE="attacker"
else
    echo "[!] Unknown system type"
    read -p "Are you on Target (t) or Attacker (a)? " manual_role
    if [[ "$manual_role" == "t" ]]; then
        ROLE="target"
    elif [[ "$manual_role" == "a" ]]; then
        ROLE="attacker"
    else
        echo "[!] Invalid choice"
        exit 1
    fi
fi

echo "Detected role: $ROLE"
echo ""

# Main menu
echo "Select startup option:"
echo "1. 🎮 Start Main Controller"
echo "2. 📊 Start Comprehensive Monitor"
echo "3. ⚡ Quick Test"
echo "4. 📋 Check System Status"
echo "5. 🚪 Exit"
echo ""
read -p "Choice [1-5]: " choice

case $choice in
    1)
        if [ "$ROLE" = "target" ]; then
            echo ""
            echo "[+] Starting Defense Controller..."
            cd ~/ddos-enterprise-lab/ubuntu-server
            sudo ./ddos_defense_controller.sh
        else
            echo ""
            echo "[+] Starting Attack Controller..."
            cd ~/ddos-enterprise-lab/kali-attacker
            ./ddos_attack_controller.sh
        fi
        ;;
        
    2)
        echo ""
        echo "[+] Starting Comprehensive Monitor..."
        cd ~/ddos-enterprise-lab/shared
        ./comprehensive_monitor.sh
        ;;
        
    3)
        echo ""
        echo "[+] Quick Test Options:"
        if [ "$ROLE" = "target" ]; then
            echo "1. Check web server"
            echo "2. Check firewall status"
            echo "3. Run system diagnostics"
            echo ""
            read -p "Choice [1-3]: " test_choice
            
            case $test_choice in
                1)
                    echo ""
                    echo "[+] Testing web server..."
                    curl -I http://localhost/
                    ;;
                2)
                    echo ""
                    echo "[+] Checking firewall..."
                    sudo iptables -L -n -v
                    ;;
                3)
                    echo ""
                    echo "[+] System diagnostics..."
                    uptime
                    free -h
                    netstat -ant | wc -l
                    ;;
            esac
        else
            echo "1. Test target connectivity"
            echo "2. Quick SYN test (5 seconds)"
            echo "3. Quick HTTP test (5 seconds)"
            echo ""
            read -p "Choice [1-3]: " test_choice
            
            case $test_choice in
                1)
                    echo ""
                    read -p "Enter target IP [192.168.1.5]: " target
                    target=${target:-192.168.1.5}
                    ping -c 4 $target
                    curl -I http://$target/ --max-time 3
                    ;;
                2)
                    echo ""
                    echo "[+] Quick SYN test (5 seconds)..."
                    sudo timeout 5 hping3 -S -p 80 --flood 192.168.1.5 2>/dev/null
                    echo "[+] Test completed"
                    ;;
                3)
                    echo ""
                    echo "[+] Quick HTTP test (5 seconds)..."
                    timeout 5 python3 ~/ddos-enterprise-lab/kali-attacker/attacks/http_flood.py http://192.168.1.5 5 10
                    ;;
            esac
        fi
        echo ""
        read -p "Press Enter to continue..."
        ;;
        
    4)
        echo ""
        echo "[+] System Status:"
        echo "-----------------"
        echo "IP Address: $(hostname -I | cut -d' ' -f1)"
        echo "Hostname: $(hostname)"
        echo "Uptime: $(uptime -p)"
        echo "Load: $(uptime | awk -F'load average:' '{print $2}')"
        echo "Memory: $(free -h | awk '/^Mem:/ {print $3"/"$2}')"
        echo ""
        
        if [ "$ROLE" = "target" ]; then
            echo "Web Server: $(systemctl is-active apache2 2>/dev/null || echo 'Not installed')"
            echo "Connections: $(netstat -ant 2>/dev/null | wc -l)"
        else
            echo "Attack Tools:"
            echo "  hping3: $(command -v hping3 >/dev/null && echo 'Installed' || echo 'Missing')"
            echo "  nmap: $(command -v nmap >/dev/null && echo 'Installed' || echo 'Missing')"
            echo "  python3: $(command -v python3 >/dev/null && echo 'Installed' || echo 'Missing')"
        fi
        echo ""
        read -p "Press Enter to continue..."
        ;;
        
    5)
        echo ""
        echo "[+] Exiting..."
        exit 0
        ;;
        
    *)
        echo "[!] Invalid choice"
        sleep 1
        ;;
esac
