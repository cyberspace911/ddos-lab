#!/bin/bash

# ============================================================================
# ENTERPRISE DDoS LAB SETUP SCRIPT v3.0
# Sets up both Ubuntu (target) and Kali (attacker) systems
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get current IP and hostname
CURRENT_IP=$(hostname -I | cut -d' ' -f1)
HOSTNAME=$(hostname)
OS=$(grep -E '^(NAME|VERSION)=' /etc/os-release | cut -d'=' -f2 | tr -d '"' | head -1)

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         ENTERPRISE DDoS LAB SETUP v3.0                  ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}System Information:${NC}"
echo "────────────────────────────"
echo "Hostname: $HOSTNAME"
echo "IP Address: $CURRENT_IP"
echo "OS: $OS"
echo ""

# Detect if we're on Ubuntu or Kali
if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
    ROLE="TARGET"
    echo -e "${GREEN}[+] Detected Ubuntu/Debian system${NC}"
    echo -e "${GREEN}[+] Configuring as TARGET (Victim)${NC}"
elif [[ "$OS" == *"Kali"* ]] || [[ "$HOSTNAME" == *"kali"* ]]; then
    ROLE="ATTACKER"
    echo -e "${RED}[+] Detected Kali Linux system${NC}"
    echo -e "${RED}[+] Configuring as ATTACKER${NC}"
else
    echo -e "${YELLOW}[!] Unknown system type${NC}"
    echo -e "${YELLOW}[!] Please specify role manually${NC}"
    read -p "Enter role (target/attacker): " manual_role
    if [[ "$manual_role" == "target" ]]; then
        ROLE="TARGET"
    elif [[ "$manual_role" == "attacker" ]]; then
        ROLE="ATTACKER"
    else
        echo -e "${RED}[!] Invalid role. Exiting.${NC}"
        exit 1
    fi
fi

echo ""
echo -e "${CYAN}Setup Options:${NC}"
echo "────────────────────────────"
echo "1. Quick Setup (Recommended)"
echo "2. Custom Setup"
echo "3. Exit"
echo ""
read -p "Select option [1-3]: " setup_choice

case $setup_choice in
    1)
        echo ""
        echo -e "${GREEN}[+] Starting Quick Setup...${NC}"
        
        if [ "$ROLE" = "TARGET" ]; then
            # Ubuntu Target Setup
            echo -e "${CYAN}[1] Installing required packages...${NC}"
            sudo apt update
            sudo apt install -y \
                apache2 \
                iptables-persistent \
                net-tools \
                curl \
                wget \
                python3 \
                python3-pip \
                bc \
                jq
            
            echo -e "${CYAN}[2] Setting up web server...${NC}"
            cd ~/ddos-enterprise-lab/ubuntu-server
            chmod +x *.sh
            sudo ./setup_web_server.sh
            
            echo -e "${CYAN}[3] Setting up defense controller...${NC}"
            chmod +x ddos_defense_controller.sh
            
            echo -e "${CYAN}[4] Creating startup scripts...${NC}"
            cat > ~/start_ddos_lab.sh << 'START_TARGET'
#!/bin/bash
cd ~/ddos-enterprise-lab/ubuntu-server
sudo ./ddos_defense_controller.sh
START_TARGET
            chmod +x ~/start_ddos_lab.sh
            
            echo ""
            echo -e "${GREEN}✅ Ubuntu Target Setup Complete!${NC}"
            echo ""
            echo -e "${YELLOW}Next Steps:${NC}"
            echo "1. Run the defense controller:"
            echo "   cd ~/ddos-enterprise-lab/ubuntu-server"
            echo "   sudo ./ddos_defense_controller.sh"
            echo ""
            echo "2. Or use the shortcut:"
            echo "   ~/start_ddos_lab.sh"
            echo ""
            echo "3. Set defense level to 'NO DEFENSE' for initial testing"
            
        else
            # Kali Attacker Setup
            echo -e "${CYAN}[1] Installing required packages...${NC}"
            sudo apt update
            sudo apt install -y \
                hping3 \
                nmap \
                curl \
                wget \
                python3 \
                python3-pip \
                netcat \
                bc \
                jq
            
            echo -e "${CYAN}[2] Installing Python dependencies...${NC}"
            pip3 install requests colorama
            
            echo -e "${CYAN}[3] Setting up attack controller...${NC}"
            cd ~/ddos-enterprise-lab/kali-attacker
            chmod +x *.sh
            chmod +x attacks/*.py attacks/*.sh
            
            echo -e "${CYAN}[4] Creating startup scripts...${NC}"
            cat > ~/start_ddos_lab.sh << 'START_ATTACKER'
#!/bin/bash
cd ~/ddos-enterprise-lab/kali-attacker
./ddos_attack_controller.sh
START_ATTACKER
            chmod +x ~/start_ddos_lab.sh
            
            echo ""
            echo -e "${GREEN}✅ Kali Attacker Setup Complete!${NC}"
            echo ""
            echo -e "${YELLOW}Next Steps:${NC}"
            echo "1. Run the attack controller:"
            echo "   cd ~/ddos-enterprise-lab/kali-attacker"
            echo "   ./ddos_attack_controller.sh"
            echo ""
            echo "2. Or use the shortcut:"
            echo "   ~/start_ddos_lab.sh"
            echo ""
            echo "3. First, check target connectivity"
            echo "4. Start with quick test attacks"
        fi
        ;;
        
    2)
        echo ""
        echo -e "${YELLOW}[+] Starting Custom Setup...${NC}"
        
        echo ""
        echo -e "${CYAN}Custom Setup Options:${NC}"
        echo "──────────────────────────────"
        
        if [ "$ROLE" = "TARGET" ]; then
            echo "1. Install Apache web server only"
            echo "2. Install defense tools only"
            echo "3. Setup monitoring only"
            echo "4. Full setup (everything)"
            echo ""
            read -p "Select option [1-4]: " target_choice
            
            case $target_choice in
                1)
                    cd ~/ddos-enterprise-lab/ubuntu-server
                    sudo ./setup_web_server.sh
                    ;;
                2)
                    cd ~/ddos-enterprise-lab/ubuntu-server
                    chmod +x ddos_defense_controller.sh
                    echo -e "${GREEN}[+] Defense controller ready${NC}"
                    echo -e "${YELLOW}[+] Run with: sudo ./ddos_defense_controller.sh${NC}"
                    ;;
                3)
                    echo -e "${YELLOW}[+] Monitoring setup included in defense controller${NC}"
                    ;;
                4)
                    sudo apt update
                    sudo apt install -y apache2 iptables-persistent net-tools curl wget python3 python3-pip bc jq
                    cd ~/ddos-enterprise-lab/ubuntu-server
                    chmod +x *.sh
                    sudo ./setup_web_server.sh
                    echo -e "${GREEN}[+] Full setup complete!${NC}"
                    ;;
            esac
            
        else
            echo "1. Install attack tools only"
            echo "2. Setup attack scripts only"
            echo "3. Full setup (everything)"
            echo ""
            read -p "Select option [1-3]: " attacker_choice
            
            case $attacker_choice in
                1)
                    sudo apt update
                    sudo apt install -y hping3 nmap curl wget python3 python3-pip netcat bc jq
                    pip3 install requests colorama
                    ;;
                2)
                    cd ~/ddos-enterprise-lab/kali-attacker
                    chmod +x *.sh
                    chmod +x attacks/*.py attacks/*.sh
                    echo -e "${GREEN}[+] Attack scripts ready${NC}"
                    ;;
                3)
                    sudo apt update
                    sudo apt install -y hping3 nmap curl wget python3 python3-pip netcat bc jq
                    pip3 install requests colorama
                    cd ~/ddos-enterprise-lab/kali-attacker
                    chmod +x *.sh
                    chmod +x attacks/*.py attacks/*.sh
                    echo -e "${GREEN}[+] Full setup complete!${NC}"
                    ;;
            esac
        fi
        ;;
        
    3)
        echo ""
        echo -e "${YELLOW}[+] Setup cancelled${NC}"
        exit 0
        ;;
        
    *)
        echo -e "${RED}[!] Invalid choice${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Setup Complete!${NC}"
echo ""
echo -e "${CYAN}Project Structure:${NC}"
echo "~/ddos-enterprise-lab/"
echo "├── ubuntu-server/     # Target system"
echo "├── kali-attacker/     # Attacker system"
echo "├── shared/           # Cross-platform tools"
echo "└── documentation/    # Guides and reports"
echo ""
echo -e "${CYAN}Quick Start Commands:${NC}"
echo "Target (Ubuntu):  cd ~/ddos-enterprise-lab/ubuntu-server && sudo ./ddos_defense_controller.sh"
echo "Attacker (Kali):  cd ~/ddos-enterprise-lab/kali-attacker && ./ddos_attack_controller.sh"
echo "Monitor:          cd ~/ddos-enterprise-lab/shared && ./comprehensive_monitor.sh"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: For educational purposes only!${NC}"
echo -e "${YELLOW}⚠️  Only use in controlled lab environments${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════${NC}"
