#!/bin/bash

echo "==============================================="
echo "       FIXING WEB INTERFACE ISSUES"
echo "==============================================="

# Stop nginx if running
sudo systemctl stop nginx 2>/dev/null

# Stop anything using port 80
sudo fuser -k 80/tcp 2>/dev/null
sudo fuser -k 8080/tcp 2>/dev/null

# Fix Apache configuration
echo "[+] Fixing Apache configuration..."
sudo sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf
sudo sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8080>/' /etc/apache2/sites-available/000-default.conf

# Update web interface URL in config
sudo sed -i "s|/ddos-monitor/|http://$(hostname -I | cut -d' ' -f1):8080/ddos-monitor/|" \
    /var/www/html/ddos-monitor/index.php 2>/dev/null || true

# Restart Apache
echo "[+] Restarting Apache on port 8080..."
sudo systemctl restart apache2

# Restart Flask backend
echo "[+] Restarting monitoring backend..."
sudo systemctl restart ddos-monitor

# Check services
echo ""
echo "✅ Services Status:"
echo "-------------------"
echo "Apache (port 8080): $(sudo systemctl is-active apache2)"
echo "Flask Backend: $(sudo systemctl is-active ddos-monitor)"

# Show access URLs
IP=$(hostname -I | cut -d' ' -f1)
echo ""
echo "🌐 ACCESS URLs:"
echo "---------------"
echo "1. Web Interface: http://$IP:8080/ddos-monitor/"
echo "   Password: ddoslab2024"
echo ""
echo "2. Direct API Access:"
echo "   Status API: curl http://localhost:5000/api/status"
echo "   Metrics API: curl http://localhost:5000/api/metrics"
echo ""
echo "3. Quick test in browser:"
echo "   http://$IP:8080/ddos-monitor/"
echo ""
echo "4. If still not working, try SSH tunnel from host:"
echo "   ssh -L 8080:localhost:8080 ubuntu@$IP"
echo "   Then open: http://localhost:8080/ddos-monitor/"
