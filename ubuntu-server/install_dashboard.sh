#!/bin/bash

# Installation script for DDoS Web Dashboard

echo "==============================================="
echo "   Enterprise DDoS Web Dashboard Installer"
echo "==============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges. Use: sudo $0"
    exit 1
fi

echo "[+] Checking system requirements..."

# Check Python version
python3 --version >/dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[!] Python3 not found. Installing..."
    apt update
    apt install -y python3 python3-pip
fi

# Check Flask
if ! python3 -c "import flask" 2>/dev/null; then
    echo "[+] Installing Flask and dependencies..."
    pip3 install flask flask-socketio psutil pyjwt
fi

echo "[+] Setting up dashboard directory..."

# Create dashboard directory
DASHBOARD_DIR="/root/ddos-enterprise-lab/ubuntu-server/web-dashboard"
mkdir -p "$DASHBOARD_DIR"/{static/css,static/js,static/img,templates,api,logs,config}

# Set permissions
chmod -R 755 "$DASHBOARD_DIR"

echo "[+] Installing systemd service..."
cp ddos-dashboard.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable ddos-dashboard.service

echo "[+] Creating startup script..."
cat > /usr/local/bin/start-ddos-dashboard << 'SCRIPT'
#!/bin/bash
cd /root/ddos-enterprise-lab/ubuntu-server/web-dashboard
python3 app.py
SCRIPT

chmod +x /usr/local/bin/start-ddos-dashboard

echo "[+] Creating firewall rule for dashboard..."
# Allow port 5000 for dashboard
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
iptables-save > /etc/iptables/rules.v4

echo "[+] Installation complete!"
echo ""
echo "Dashboard will be available at:"
echo "  • http://$(hostname -I | awk '{print $1}'):5000"
echo ""
echo "To start the dashboard:"
echo "  systemctl start ddos-dashboard"
echo ""
echo "To view logs:"
echo "  journalctl -u ddos-dashboard -f"
echo ""
echo "Default credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "==============================================="
