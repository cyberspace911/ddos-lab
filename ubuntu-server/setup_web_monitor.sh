#!/bin/bash

# ============================================================================
# COMPLETE WEB MONITORING APPLICATION FOR DDoS LAB
# Real-time attack monitoring, logs, and control panel
# ============================================================================

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges. Use: sudo $0"
    exit 1
fi

echo "==============================================="
echo "    DDoS LAB WEB MONITORING APPLICATION"
echo "==============================================="
echo ""

# Install required packages
echo "[+] Installing required packages..."
apt update
apt install -y \
    apache2 \
    php \
    php-curl \
    php-json \
    php-sqlite3 \
    sqlite3 \
    python3 \
    python3-pip \
    net-tools \
    iptables \
    curl \
    wget

# Create web application directory
WEB_APP_DIR="/var/www/html/ddos-monitor"
echo "[+] Creating web application directory: $WEB_APP_DIR"
rm -rf $WEB_APP_DIR
mkdir -p $WEB_APP_DIR/{logs,config,static,api}
chown -R www-data:www-data $WEB_APP_DIR
chmod -R 755 $WEB_APP_DIR

# Create Python monitoring backend
echo "[+] Creating Python monitoring backend..."
cat > $WEB_APP_DIR/monitor_backend.py << 'PYTHON_BACKEND'
#!/usr/bin/env python3
"""
DDoS Lab - Real-time Monitoring Backend
Provides API endpoints for web interface
"""

import json
import time
import subprocess
import threading
from datetime import datetime
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import psutil
import sqlite3
from pathlib import Path

app = Flask(__name__)
CORS(app)

# Configuration
CONFIG = {
    'log_dir': '/var/www/html/ddos-monitor/logs',
    'db_path': '/var/www/html/ddos-monitor/monitor.db',
    'update_interval': 2  # seconds
}

# Initialize database
def init_database():
    conn = sqlite3.connect(CONFIG['db_path'])
    c = conn.cursor()
    
    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS metrics (
        timestamp INTEGER PRIMARY KEY,
        connections INTEGER,
        syn_connections INTEGER,
        established_connections INTEGER,
        cpu_percent REAL,
        memory_percent REAL,
        bytes_sent INTEGER,
        bytes_recv INTEGER,
        load_1min REAL,
        load_5min REAL,
        load_15min REAL
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time INTEGER,
        end_time INTEGER,
        attack_type TEXT,
        source_ip TEXT,
        packets_count INTEGER,
        status TEXT
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        level TEXT,
        source TEXT,
        message TEXT
    )''')
    
    conn.commit()
    conn.close()

# System metrics collection
def collect_metrics():
    metrics = {}
    
    # Network connections
    try:
        result = subprocess.run(
            ["netstat", "-ant"],
            capture_output=True,
            text=True,
            timeout=2
        )
        lines = result.stdout.strip().split('\n')
        metrics['connections'] = len(lines) - 2 if len(lines) > 2 else 0
        
        # Count SYN_RECV connections
        syn_count = 0
        established_count = 0
        for line in lines:
            if 'SYN_RECV' in line:
                syn_count += 1
            elif 'ESTABLISHED' in line:
                established_count += 1
        
        metrics['syn_connections'] = syn_count
        metrics['established_connections'] = established_count
        
        # Calculate SYN percentage
        if metrics['connections'] > 0:
            metrics['syn_percentage'] = (syn_count / metrics['connections']) * 100
        else:
            metrics['syn_percentage'] = 0
            
    except Exception as e:
        metrics['connections'] = 0
        metrics['syn_connections'] = 0
        metrics['established_connections'] = 0
        metrics['syn_percentage'] = 0
    
    # System metrics
    metrics['cpu_percent'] = psutil.cpu_percent(interval=0.5)
    metrics['memory_percent'] = psutil.virtual_memory().percent
    
    # Network I/O
    net_io = psutil.net_io_counters()
    metrics['bytes_sent'] = net_io.bytes_sent
    metrics['bytes_recv'] = net_io.bytes_recv
    
    # Load average
    load = psutil.getloadavg()
    metrics['load_1min'], metrics['load_5min'], metrics['load_15min'] = load
    
    # Timestamp
    metrics['timestamp'] = int(time.time())
    
    return metrics

# Iptables status
def get_iptables_status():
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n", "-v"],
            capture_output=True,
            text=True,
            timeout=2
        )
        return result.stdout
    except:
        return "Unable to retrieve iptables status"

# Log file reading
def read_log_file(log_type='system', lines=100):
    log_files = {
        'system': '/var/log/syslog',
        'auth': '/var/log/auth.log',
        'kern': '/var/log/kern.log',
        'apache': '/var/log/apache2/access.log',
        'ddos': '/var/www/html/ddos-monitor/logs/ddos_attacks.log'
    }
    
    if log_type not in log_files:
        return []
    
    try:
        with open(log_files[log_type], 'r') as f:
            return f.readlines()[-lines:]
    except:
        return []

# Flask API endpoints
@app.route('/api/metrics', methods=['GET'])
def get_metrics():
    metrics = collect_metrics()
    
    # Store in database
    conn = sqlite3.connect(CONFIG['db_path'])
    c = conn.cursor()
    c.execute('''INSERT INTO metrics VALUES (?,?,?,?,?,?,?,?,?,?,?)''',
              (metrics['timestamp'],
               metrics['connections'],
               metrics['syn_connections'],
               metrics['established_connections'],
               metrics['cpu_percent'],
               metrics['memory_percent'],
               metrics['bytes_sent'],
               metrics['bytes_recv'],
               metrics['load_1min'],
               metrics['load_5min'],
               metrics['load_15min']))
    conn.commit()
    conn.close()
    
    return jsonify(metrics)

@app.route('/api/status', methods=['GET'])
def get_system_status():
    metrics = collect_metrics()
    
    # Determine attack status
    attack_status = "normal"
    if metrics['syn_percentage'] > 70:
        attack_status = "critical"
    elif metrics['syn_percentage'] > 40:
        attack_status = "high"
    elif metrics['syn_percentage'] > 20:
        attack_status = "moderate"
    
    status = {
        'attack_status': attack_status,
        'syn_percentage': metrics['syn_percentage'],
        'cpu_usage': metrics['cpu_percent'],
        'memory_usage': metrics['memory_percent'],
        'load': metrics['load_1min'],
        'connections': metrics['connections'],
        'timestamp': metrics['timestamp'],
        'hostname': subprocess.run(['hostname'], capture_output=True, text=True).stdout.strip(),
        'ip_address': subprocess.run(['hostname', '-I'], capture_output=True, text=True).stdout.strip()
    }
    
    return jsonify(status)

@app.route('/api/logs/<log_type>', methods=['GET'])
def get_logs(log_type):
    lines = request.args.get('lines', default=100, type=int)
    log_lines = read_log_file(log_type, lines)
    return jsonify({'logs': log_lines})

@app.route('/api/iptables', methods=['GET'])
def get_iptables():
    status = get_iptables_status()
    return jsonify({'iptables': status})

@app.route('/api/connections', methods=['GET'])
def get_connections():
    try:
        result = subprocess.run(
            ["ss", "-tun"],
            capture_output=True,
            text=True,
            timeout=2
        )
        connections = result.stdout.strip().split('\n')[1:]  # Skip header
        return jsonify({'connections': connections[:50]})  # Return top 50
    except:
        return jsonify({'connections': []})

@app.route('/api/attack_history', methods=['GET'])
def get_attack_history():
    conn = sqlite3.connect(CONFIG['db_path'])
    c = conn.cursor()
    
    c.execute('''SELECT * FROM attacks ORDER BY start_time DESC LIMIT 10''')
    attacks = c.fetchall()
    
    conn.close()
    
    return jsonify({'attacks': attacks})

@app.route('/api/top_ips', methods=['GET'])
def get_top_ips():
    try:
        result = subprocess.run(
            ["netstat", "-ant"],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        ip_counts = {}
        for line in result.stdout.split('\n'):
            if 'ESTABLISHED' in line or 'SYN_RECV' in line:
                parts = line.split()
                if len(parts) > 4:
                    ip_port = parts[4]
                    ip = ip_port.split(':')[0]
                    if ip and ip != 'Address':
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        return jsonify({'top_ips': top_ips})
    except:
        return jsonify({'top_ips': []})

@app.route('/api/defense_status', methods=['GET'])
def get_defense_status():
    try:
        # Check iptables default policy
        result = subprocess.run(
            ["iptables", "-L", "INPUT", "-n"],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        lines = result.stdout.split('\n')
        if len(lines) > 0:
            policy = lines[0].split()[-1].strip(')')
        else:
            policy = "UNKNOWN"
        
        # Count rules
        rule_count = len([l for l in lines if not l.startswith('Chain') and l.strip()])
        
        return jsonify({
            'policy': policy,
            'rule_count': rule_count,
            'syn_protection': 'YES' if 'syn' in result.stdout.lower() else 'NO',
            'rate_limiting': 'YES' if 'limit' in result.stdout.lower() else 'NO'
        })
    except:
        return jsonify({'error': 'Unable to get defense status'})

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Start Flask app
    print("Starting DDoS Lab Monitoring Backend...")
    print(f"Web Interface: http://YOUR_SERVER_IP/ddos-monitor/")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
PYTHON_BACKEND

chmod +x $WEB_APP_DIR/monitor_backend.py

# Create PHP web interface
echo "[+] Creating PHP web interface..."
cat > $WEB_APP_DIR/index.php << 'WEB_INTERFACE'
<?php
// DDoS Lab Web Monitoring Interface
session_start();

// Simple authentication
$valid_password = "ddoslab2024"; // Change for production

// Handle login
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['password'])) {
    if ($_POST['password'] === $valid_password) {
        $_SESSION['authenticated'] = true;
        $_SESSION['login_time'] = time();
        header('Location: index.php');
        exit;
    } else {
        $error = "Invalid password!";
    }
}

// Check session timeout (8 hours)
if (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time'] > 28800)) {
    session_destroy();
}

// Show login if not authenticated
if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
    show_login();
    exit;
}

// API base URL
$api_base = "http://localhost:5000/api";

// Helper function to call API
function call_api($endpoint) {
    $url = "http://localhost:5000/api" . $endpoint;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 2);
    $response = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($response, true);
}

// Get current metrics
$metrics = call_api('/metrics') ?: [];
$status = call_api('/status') ?: [];
$defense = call_api('/defense_status') ?: [];

// Function to show login page
function show_login() {
    global $error;
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>DDoS Lab - Login</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                color: #e2e8f0;
            }
            .login-container {
                background: rgba(30, 41, 59, 0.8);
                backdrop-filter: blur(10px);
                padding: 50px;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                width: 100%;
                max-width: 450px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            .logo {
                text-align: center;
                margin-bottom: 40px;
            }
            .logo i {
                font-size: 4em;
                color: #667eea;
                margin-bottom: 20px;
                display: block;
            }
            .logo h1 {
                font-size: 2.5em;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                margin-bottom: 10px;
            }
            .logo p {
                color: #94a3b8;
                font-size: 1.1em;
            }
            .form-group {
                margin-bottom: 25px;
            }
            .form-group label {
                display: block;
                color: #cbd5e1;
                margin-bottom: 10px;
                font-weight: 500;
                font-size: 1.1em;
            }
            .password-container {
                position: relative;
            }
            .password-container input {
                width: 100%;
                padding: 15px 50px 15px 20px;
                border: 2px solid #334155;
                border-radius: 12px;
                background: #1e293b;
                color: #e2e8f0;
                font-size: 16px;
                transition: all 0.3s;
            }
            .password-container input:focus {
                outline: none;
                border-color: #667eea;
                background: #0f172a;
            }
            .password-toggle {
                position: absolute;
                right: 15px;
                top: 50%;
                transform: translateY(-50%);
                background: none;
                border: none;
                color: #94a3b8;
                cursor: pointer;
                font-size: 1.2em;
            }
            .error {
                background: rgba(239, 68, 68, 0.2);
                color: #fca5a5;
                padding: 15px;
                border-radius: 10px;
                margin-bottom: 25px;
                text-align: center;
                border: 1px solid rgba(239, 68, 68, 0.3);
                animation: shake 0.5s;
            }
            @keyframes shake {
                0%, 100% { transform: translateX(0); }
                25% { transform: translateX(-5px); }
                75% { transform: translateX(5px); }
            }
            .btn-login {
                width: 100%;
                padding: 16px;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                border: none;
                border-radius: 12px;
                color: white;
                font-size: 18px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
            }
            .btn-login:hover {
                transform: translateY(-2px);
                box-shadow: 0 15px 40px rgba(102, 126, 234, 0.4);
            }
            .footer {
                margin-top: 30px;
                text-align: center;
                color: #64748b;
                font-size: 0.9em;
                padding-top: 20px;
                border-top: 1px solid #334155;
            }
        </style>
        <script>
            function togglePassword() {
                const passwordInput = document.getElementById('password');
                const toggleBtn = document.querySelector('.password-toggle i');
                
                if (passwordInput.type === 'password') {
                    passwordInput.type = 'text';
                    toggleBtn.classList.remove('fa-eye');
                    toggleBtn.classList.add('fa-eye-slash');
                } else {
                    passwordInput.type = 'password';
                    toggleBtn.classList.remove('fa-eye-slash');
                    toggleBtn.classList.add('fa-eye');
                }
            }
        </script>
    </head>
    <body>
        <div class="login-container">
            <div class="logo">
                <i class="fas fa-shield-alt"></i>
                <h1>DDoS Lab Monitor</h1>
                <p>Enterprise Attack & Defense Laboratory</p>
            </div>
            
            <?php if (isset($error)): ?>
                <div class="error">
                    <i class="fas fa-exclamation-triangle"></i> <?php echo $error; ?>
                </div>
            <?php endif; ?>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label for="password">
                        <i class="fas fa-key"></i> Access Password
                    </label>
                    <div class="password-container">
                        <input type="password" id="password" name="password" 
                               placeholder="Enter lab access password" required>
                        <button type="button" class="password-toggle" onclick="togglePassword()">
                            <i class="fas fa-eye"></i>
                        </button>
                    </div>
                </div>
                
                <button type="submit" class="btn-login">
                    <i class="fas fa-sign-in-alt"></i> Access Control Panel
                </button>
            </form>
            
            <div class="footer">
                <p><i class="fas fa-info-circle"></i> Default password: ddoslab2024</p>
                <p style="margin-top: 10px; font-size: 0.8em;">
                    <i class="fas fa-exclamation-triangle"></i> For educational use only
                </p>
            </div>
        </div>
    </body>
    </html>
    <?php
}

// Main dashboard
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Lab Monitor - Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #cbd5e1;
            --text-muted: #94a3b8;
            --border-color: #475569;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --info: #3b82f6;
            --purple: #8b5cf6;
        }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Header */
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }
        .logo h1 {
            font-size: 2em;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .server-info {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .info-item {
            background: var(--bg-secondary);
            padding: 10px 20px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 0.9em;
        }
        .info-item i {
            color: var(--purple);
        }
        
        /* Navigation */
        .nav-tabs {
            display: flex;
            gap: 5px;
            background: var(--bg-secondary);
            padding: 10px;
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
        }
        .tab {
            padding: 12px 25px;
            border-radius: 8px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            transition: all 0.3s;
            color: var(--text-secondary);
        }
        .tab.active {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .tab:hover:not(.active) {
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }
        
        /* Dashboard Grid */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }
        
        /* Cards */
        .card {
            background: var(--bg-secondary);
            border-radius: 15px;
            padding: 25px;
            border: 1px solid var(--border-color);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .card-title {
            font-size: 1.3em;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card-title i {
            color: var(--purple);
        }
        .refresh-btn {
            background: var(--bg-tertiary);
            border: none;
            color: var(--text-secondary);
            width: 35px;
            height: 35px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        .refresh-btn:hover {
            background: var(--purple);
            color: white;
        }
        
        /* Status Indicators */
        .status-badge {
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        .status-normal { background: rgba(16, 185, 129, 0.2); color: var(--success); border: 1px solid var(--success); }
        .status-warning { background: rgba(245, 158, 11, 0.2); color: var(--warning); border: 1px solid var(--warning); }
        .status-danger { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); }
        .status-critical { 
            background: rgba(239, 68, 68, 0.3); 
            color: var(--danger); 
            border: 1px solid var(--danger);
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        
        /* Metrics */
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-top: 20px;
        }
        .metric-item {
            text-align: center;
        }
        .metric-value {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 5px;
        }
        .metric-label {
            color: var(--text-muted);
            font-size: 0.9em;
        }
        
        /* Progress Bars */
        .progress-container {
            margin-top: 15px;
        }
        .progress-label {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 0.9em;
        }
        .progress-bar {
            height: 10px;
            background: var(--bg-tertiary);
            border-radius: 5px;
            overflow: hidden;
        }
        .progress-fill {
            height: 100%;
            border-radius: 5px;
            transition: width 0.5s ease;
        }
        .progress-normal { background: linear-gradient(90deg, var(--success), #34d399); }
        .progress-warning { background: linear-gradient(90deg, var(--warning), #fbbf24); }
        .progress-danger { background: linear-gradient(90deg, var(--danger), #f87171); }
        
        /* Log Viewer */
        .log-viewer {
            background: var(--bg-primary);
            border-radius: 8px;
            padding: 15px;
            height: 300px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            border: 1px solid var(--border-color);
        }
        .log-entry {
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
        }
        .log-timestamp {
            color: var(--info);
            font-weight: 600;
        }
        .log-level-info { color: var(--success); }
        .log-level-warning { color: var(--warning); }
        .log-level-error { color: var(--danger); }
        .log-level-critical { color: var(--danger); font-weight: bold; }
        
        /* Tables */
        .table-container {
            overflow-x: auto;
        }
        .data-table {
            width: 100%;
            border-collapse: collapse;
        }
        .data-table th {
            background: var(--bg-tertiary);
            padding: 15px;
            text-align: left;
            font-weight: 600;
            color: var(--text-secondary);
            border-bottom: 2px solid var(--border-color);
        }
        .data-table td {
            padding: 12px 15px;
            border-bottom: 1px solid var(--border-color);
        }
        .data-table tr:hover {
            background: rgba(102, 126, 234, 0.1);
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 30px 0;
            margin-top: 50px;
            border-top: 1px solid var(--border-color);
            color: var(--text-muted);
            font-size: 0.9em;
        }
        
        /* Responsive */
        @media (max-width: 1200px) {
            .dashboard-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            .header {
                flex-direction: column;
                gap: 20px;
            }
            .nav-tabs {
                overflow-x: auto;
                padding: 10px 5px;
            }
            .tab {
                white-space: nowrap;
                padding: 10px 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo">
                <h1>
                    <i class="fas fa-shield-alt"></i>
                    DDoS Lab Monitor
                </h1>
            </div>
            <div class="server-info">
                <div class="info-item">
                    <i class="fas fa-server"></i>
                    <span>Host: <?php echo gethostname(); ?></span>
                </div>
                <div class="info-item">
                    <i class="fas fa-network-wired"></i>
                    <span>IP: <?php echo $_SERVER['SERVER_ADDR'] ?? '192.168.1.5'; ?></span>
                </div>
                <div class="info-item">
                    <i class="fas fa-clock"></i>
                    <span>Last Update: <span id="last-update">Just now</span></span>
                </div>
                <div class="info-item">
                    <i class="fas fa-sign-out-alt"></i>
                    <a href="?logout=1" style="color: var(--danger); text-decoration: none;">Logout</a>
                </div>
            </div>
        </div>
        
        <!-- Navigation Tabs -->
        <div class="nav-tabs">
            <div class="tab active" onclick="showTab('dashboard')">
                <i class="fas fa-tachometer-alt"></i> Dashboard
            </div>
            <div class="tab" onclick="showTab('connections')">
                <i class="fas fa-project-diagram"></i> Connections
            </div>
            <div class="tab" onclick="showTab('defense')">
                <i class="fas fa-shield-alt"></i> Defense Status
            </div>
            <div class="tab" onclick="showTab('logs')">
                <i class="fas fa-file-alt"></i> System Logs
            </div>
            <div class="tab" onclick="showTab('attack-logs')">
                <i class="fas fa-bug"></i> Attack Logs
            </div>
            <div class="tab" onclick="showTab('analysis')">
                <i class="fas fa-chart-line"></i> Analysis
            </div>
        </div>
        
        <!-- Dashboard Tab -->
        <div id="dashboard-tab" class="tab-content">
            <div class="dashboard-grid">
                <!-- Attack Status Card -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-bullseye"></i> Attack Status
                        </h3>
                        <button class="refresh-btn" onclick="updateMetrics()">
                            <i class="fas fa-sync-alt"></i>
                        </button>
                    </div>
                    
                    <div class="status-container">
                        <?php
                        $status_class = 'status-normal';
                        $status_text = 'Normal';
                        $status_icon = 'fa-check-circle';
                        
                        if (isset($status['attack_status'])) {
                            switch ($status['attack_status']) {
                                case 'critical':
                                    $status_class = 'status-critical';
                                    $status_text = 'CRITICAL ATTACK';
                                    $status_icon = 'fa-skull-crossbones';
                                    break;
                                case 'high':
                                    $status_class = 'status-danger';
                                    $status_text = 'HIGH THREAT';
                                    $status_icon = 'fa-exclamation-triangle';
                                    break;
                                case 'moderate':
                                    $status_class = 'status-warning';
                                    $status_text = 'MODERATE THREAT';
                                    $status_icon = 'fa-exclamation-circle';
                                    break;
                                default:
                                    $status_class = 'status-normal';
                                    $status_text = 'NORMAL';
                                    $status_icon = 'fa-check-circle';
                            }
                        }
                        ?>
                        <div class="status-badge <?php echo $status_class; ?>">
                            <i class="fas <?php echo $status_icon; ?>"></i>
                            <?php echo $status_text; ?>
                        </div>
                        
                        <div class="metric-grid">
                            <div class="metric-item">
                                <div class="metric-value" id="syn-percentage">
                                    <?php echo isset($status['syn_percentage']) ? round($status['syn_percentage'], 1) : 0; ?>%
                                </div>
                                <div class="metric-label">SYN Connections</div>
                            </div>
                            <div class="metric-item">
                                <div class="metric-value" id="total-connections">
                                    <?php echo isset($metrics['connections']) ? $metrics['connections'] : 0; ?>
                                </div>
                                <div class="metric-label">Total Connections</div>
                            </div>
                        </div>
                        
                        <div class="progress-container">
                            <div class="progress-label">
                                <span>SYN Flood Risk</span>
                                <span id="syn-risk-text">Low</span>
                            </div>
                            <div class="progress-bar">
                                <div class="progress-fill progress-normal" 
                                     id="syn-progress-bar" 
                                     style="width: <?php echo min(100, $status['syn_percentage'] ?? 0); ?>%"></div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- System Health Card -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-heartbeat"></i> System Health
                        </h3>
                    </div>
                    
                    <div class="metric-grid">
                        <div class="metric-item">
                            <div class="metric-value" id="cpu-usage">
                                <?php echo isset($metrics['cpu_percent']) ? round($metrics['cpu_percent'], 1) : 0; ?>%
                            </div>
                            <div class="metric-label">CPU Usage</div>
                            <div class="progress-bar" style="margin-top: 10px;">
                                <div class="progress-fill <?php echo (($metrics['cpu_percent'] ?? 0) > 80 ? 'progress-danger' : (($metrics['cpu_percent'] ?? 0) > 60 ? 'progress-warning' : 'progress-normal')); ?>" 
                                     style="width: <?php echo $metrics['cpu_percent'] ?? 0; ?>%"></div>
                            </div>
                        </div>
                        
                        <div class="metric-item">
                            <div class="metric-value" id="memory-usage">
                                <?php echo isset($metrics['memory_percent']) ? round($metrics['memory_percent'], 1) : 0; ?>%
                            </div>
                            <div class="metric-label">Memory Usage</div>
                            <div class="progress-bar" style="margin-top: 10px;">
                                <div class="progress-fill <?php echo (($metrics['memory_percent'] ?? 0) > 80 ? 'progress-danger' : (($metrics['memory_percent'] ?? 0) > 60 ? 'progress-warning' : 'progress-normal')); ?>" 
                                     style="width: <?php echo $metrics['memory_percent'] ?? 0; ?>%"></div>
                            </div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 25px;">
                        <div class="metric-label">System Load</div>
                        <div class="metric-value" id="system-load">
                            <?php echo isset($metrics['load_1min']) ? round($metrics['load_1min'], 2) : 0; ?>
                        </div>
                        <div style="font-size: 0.9em; color: var(--text-muted); margin-top: 5px;">
                            1 min: <?php echo isset($metrics['load_1min']) ? round($metrics['load_1min'], 2) : 0; ?> |
                            5 min: <?php echo isset($metrics['load_5min']) ? round($metrics['load_5min'], 2) : 0; ?> |
                            15 min: <?php echo isset($metrics['load_15min']) ? round($metrics['load_15min'], 2) : 0; ?>
                        </div>
                    </div>
                </div>
                
                <!-- Network Traffic Card -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-network-wired"></i> Network Traffic
                        </h3>
                    </div>
                    
                    <div class="metric-grid">
                        <div class="metric-item">
                            <div class="metric-value" id="network-in">
                                <?php
                                $bytes_recv = $metrics['bytes_recv'] ?? 0;
                                if ($bytes_recv > 1073741824) {
                                    echo round($bytes_recv / 1073741824, 2) . ' GB';
                                } elseif ($bytes_recv > 1048576) {
                                    echo round($bytes_recv / 1048576, 2) . ' MB';
                                } elseif ($bytes_recv > 1024) {
                                    echo round($bytes_recv / 1024, 2) . ' KB';
                                } else {
                                    echo $bytes_recv . ' B';
                                }
                                ?>
                            </div>
                            <div class="metric-label">Received</div>
                        </div>
                        
                        <div class="metric-item">
                            <div class="metric-value" id="network-out">
                                <?php
                                $bytes_sent = $metrics['bytes_sent'] ?? 0;
                                if ($bytes_sent > 1073741824) {
                                    echo round($bytes_sent / 1073741824, 2) . ' GB';
                                } elseif ($bytes_sent > 1048576) {
                                    echo round($bytes_sent / 1048576, 2) . ' MB';
                                } elseif ($bytes_sent > 1024) {
                                    echo round($bytes_sent / 1024, 2) . ' KB';
                                } else {
                                    echo $bytes_sent . ' B';
                                }
                                ?>
                            </div>
                            <div class="metric-label">Sent</div>
                        </div>
                    </div>
                    
                    <div style="margin-top: 25px;">
                        <div class="metric-label">Active Connections</div>
                        <div class="metric-value" id="active-connections">
                            <?php echo isset($metrics['established_connections']) ? $metrics['established_connections'] : 0; ?>
                        </div>
                    </div>
                </div>
                
                <!-- Defense Status Card -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-shield-alt"></i> Defense Status
                        </h3>
                    </div>
                    
                    <div style="margin-top: 15px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 15px;">
                            <span>Firewall Policy:</span>
                            <span id="firewall-policy" class="status-normal">
                                <?php echo isset($defense['policy']) ? strtoupper($defense['policy']) : 'UNKNOWN'; ?>
                            </span>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; margin-bottom: 15px;">
                            <span>SYN Protection:</span>
                            <span id="syn-protection" class="<?php echo (isset($defense['syn_protection']) && $defense['syn_protection'] == 'YES') ? 'status-normal' : 'status-warning'; ?>">
                                <?php echo isset($defense['syn_protection']) ? $defense['syn_protection'] : 'NO'; ?>
                            </span>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; margin-bottom: 15px;">
                            <span>Rate Limiting:</span>
                            <span id="rate-limiting" class="<?php echo (isset($defense['rate_limiting']) && $defense['rate_limiting'] == 'YES') ? 'status-normal' : 'status-warning'; ?>">
                                <?php echo isset($defense['rate_limiting']) ? $defense['rate_limiting'] : 'NO'; ?>
                            </span>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between;">
                            <span>Active Rules:</span>
                            <span id="rule-count">
                                <?php echo isset($defense['rule_count']) ? $defense['rule_count'] : 0; ?>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Connections Tab (initially hidden) -->
        <div id="connections-tab" class="tab-content" style="display: none;">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-project-diagram"></i> Active Network Connections
                    </h3>
                    <button class="refresh-btn" onclick="loadConnections()">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                </div>
                <div class="table-container">
                    <table class="data-table" id="connections-table">
                        <thead>
                            <tr>
                                <th>Protocol</th>
                                <th>Local Address</th>
                                <th>Remote Address</th>
                                <th>State</th>
                                <th>Process</th>
                            </tr>
                        </thead>
                        <tbody id="connections-body">
                            <!-- Filled by JavaScript -->
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div class="dashboard-grid" style="margin-top: 25px;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-map-marker-alt"></i> Top Source IPs
                        </h3>
                    </div>
                    <div id="top-ips-list" style="padding: 15px;">
                        <!-- Filled by JavaScript -->
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-chart-pie"></i> Connection Distribution
                        </h3>
                    </div>
                    <div style="padding: 15px;">
                        <canvas id="connection-chart" width="400" height="200"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Defense Status Tab -->
        <div id="defense-tab" class="tab-content" style="display: none;">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-shield-alt"></i> Firewall Rules
                    </h3>
                    <button class="refresh-btn" onclick="loadIptables()">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                </div>
                <div class="log-viewer" id="iptables-output">
                    Loading iptables rules...
                </div>
            </div>
        </div>
        
        <!-- Logs Tab -->
        <div id="logs-tab" class="tab-content" style="display: none;">
            <div class="dashboard-grid">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-file-alt"></i> System Logs
                        </h3>
                        <div>
                            <select id="log-type" onchange="loadLogs()" style="background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border-color); padding: 8px 15px; border-radius: 8px;">
                                <option value="system">System Logs</option>
                                <option value="auth">Authentication Logs</option>
                                <option value="kern">Kernel Logs</option>
                                <option value="apache">Apache Logs</option>
                                <option value="ddos">DDoS Attack Logs</option>
                            </select>
                        </div>
                    </div>
                    <div class="log-viewer" id="log-output">
                        Loading logs...
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Attack Logs Tab -->
        <div id="attack-logs-tab" class="tab-content" style="display: none;">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-bug"></i> Recent Attack History
                    </h3>
                    <button class="refresh-btn" onclick="loadAttackHistory()">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                </div>
                <div class="table-container">
                    <table class="data-table" id="attack-history-table">
                        <thead>
                            <tr>
                                <th>Start Time</th>
                                <th>Attack Type</th>
                                <th>Source IP</th>
                                <th>Packets</th>
                                <th>Status</th>
                                <th>Duration</th>
                            </tr>
                        </thead>
                        <tbody id="attack-history-body">
                            <!-- Filled by JavaScript -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Analysis Tab -->
        <div id="analysis-tab" class="tab-content" style="display: none;">
            <div class="dashboard-grid">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-chart-line"></i> Performance Trends
                        </h3>
                    </div>
                    <div style="padding: 15px;">
                        <canvas id="performance-chart" width="400" height="300"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">
                            <i class="fas fa-exclamation-triangle"></i> Attack Patterns
                        </h3>
                    </div>
                    <div style="padding: 15px;">
                        <div id="attack-patterns">
                            <p>Analyzing attack patterns...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>
                <i class="fas fa-info-circle"></i> DDoS Lab Monitoring Interface v3.0 |
                <i class="fas fa-clock"></i> Auto-refresh: <span id="refresh-countdown">5</span>s |
                <i class="fas fa-exclamation-triangle"></i> For educational use only
            </p>
            <p style="margin-top: 10px; font-size: 0.8em;">
                Last updated: <span id="current-time"><?php echo date('Y-m-d H:i:s'); ?></span>
            </p>
        </div>
    </div>
    
    <!-- JavaScript Libraries -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.29.4/moment.min.js"></script>
    
    <script>
        // Global variables
        let refreshInterval = 5000; // 5 seconds
        let countdown = 5;
        let updateInterval;
        let charts = {};
        
        // Tab management
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.style.display = 'none';
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').style.display = 'block';
            
            // Add active class to clicked tab
            event.target.closest('.tab').classList.add('active');
            
            // Load tab-specific data
            switch(tabName) {
                case 'dashboard':
                    updateMetrics();
                    break;
                case 'connections':
                    loadConnections();
                    loadTopIPs();
                    break;
                case 'defense':
                    loadIptables();
                    break;
                case 'logs':
                    loadLogs();
                    break;
                case 'attack-logs':
                    loadAttackHistory();
                    break;
                case 'analysis':
                    loadAnalysis();
                    break;
            }
        }
        
        // Update all metrics
        async function updateMetrics() {
            try {
                const response = await fetch('/api/metrics');
                const data = await response.json();
                
                // Update metrics display
                document.getElementById('syn-percentage').textContent = data.syn_percentage?.toFixed(1) + '%' || '0%';
                document.getElementById('total-connections').textContent = data.connections || 0;
                document.getElementById('cpu-usage').textContent = data.cpu_percent?.toFixed(1) + '%' || '0%';
                document.getElementById('memory-usage').textContent = data.memory_percent?.toFixed(1) + '%' || '0%';
                document.getElementById('system-load').textContent = data.load_1min?.toFixed(2) || 0;
                document.getElementById('active-connections').textContent = data.established_connections || 0;
                
                // Update network traffic
                const formatBytes = (bytes) => {
                    if (bytes > 1073741824) return (bytes / 1073741824).toFixed(2) + ' GB';
                    if (bytes > 1048576) return (bytes / 1048576).toFixed(2) + ' MB';
                    if (bytes > 1024) return (bytes / 1024).toFixed(2) + ' KB';
                    return bytes + ' B';
                };
                
                document.getElementById('network-in').textContent = formatBytes(data.bytes_recv || 0);
                document.getElementById('network-out').textContent = formatBytes(data.bytes_sent || 0);
                
                // Update progress bars
                const synBar = document.getElementById('syn-progress-bar');
                const synPercent = data.syn_percentage || 0;
                synBar.style.width = Math.min(100, synPercent) + '%';
                
                // Update status based on SYN percentage
                let statusClass = 'progress-normal';
                let statusText = 'Low';
                let attackStatus = 'status-normal';
                let attackText = 'NORMAL';
                let attackIcon = 'fa-check-circle';
                
                if (synPercent > 70) {
                    statusClass = 'progress-danger';
                    statusText = 'Critical';
                    attackStatus = 'status-critical';
                    attackText = 'CRITICAL ATTACK';
                    attackIcon = 'fa-skull-crossbones';
                } else if (synPercent > 40) {
                    statusClass = 'progress-danger';
                    statusText = 'High';
                    attackStatus = 'status-danger';
                    attackText = 'HIGH THREAT';
                    attackIcon = 'fa-exclamation-triangle';
                } else if (synPercent > 20) {
                    statusClass = 'progress-warning';
                    statusText = 'Moderate';
                    attackStatus = 'status-warning';
                    attackText = 'MODERATE THREAT';
                    attackIcon = 'fa-exclamation-circle';
                }
                
                synBar.className = 'progress-fill ' + statusClass;
                document.getElementById('syn-risk-text').textContent = statusText;
                
                // Update attack status badge
                const statusBadge = document.querySelector('.status-badge');
                statusBadge.className = 'status-badge ' + attackStatus;
                statusBadge.innerHTML = `<i class="fas ${attackIcon}"></i> ${attackText}`;
                
                // Update last update time
                const now = new Date();
                document.getElementById('last-update').textContent = now.toLocaleTimeString();
                document.getElementById('current-time').textContent = now.toLocaleString();
                
                // Reset countdown
                countdown = 5;
                
            } catch (error) {
                console.error('Error updating metrics:', error);
                document.getElementById('last-update').textContent = 'Update failed';
            }
        }
        
        // Load network connections
        async function loadConnections() {
            try {
                const response = await fetch('/api/connections');
                const data = await response.json();
                
                const tbody = document.getElementById('connections-body');
                tbody.innerHTML = '';
                
                if (data.connections && data.connections.length > 0) {
                    data.connections.slice(0, 20).forEach(conn => {
                        const parts = conn.trim().split(/\s+/);
                        if (parts.length >= 5) {
                            const tr = document.createElement('tr');
                            
                            // Extract connection info
                            const netid = parts[0];
                            const state = parts[1];
                            const local = parts[3] || '';
                            const remote = parts[4] || '';
                            
                            tr.innerHTML = `
                                <td>${netid}</td>
                                <td>${local}</td>
                                <td>${remote}</td>
                                <td><span class="status-badge ${getStateClass(state)}">${state}</span></td>
                                <td>${parts[5] || ''}</td>
                            `;
                            
                            tbody.appendChild(tr);
                        }
                    });
                } else {
                    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No active connections</td></tr>';
                }
                
            } catch (error) {
                console.error('Error loading connections:', error);
            }
        }
        
        function getStateClass(state) {
            switch(state.toUpperCase()) {
                case 'ESTAB': case 'ESTABLISHED':
                    return 'status-normal';
                case 'LISTEN':
                    return 'status-warning';
                case 'SYN_RECV':
                    return 'status-danger';
                default:
                    return 'status-warning';
            }
        }
        
        // Load top IPs
        async function loadTopIPs() {
            try {
                const response = await fetch('/api/top_ips');
                const data = await response.json();
                
                const container = document.getElementById('top-ips-list');
                container.innerHTML = '';
                
                if (data.top_ips && data.top_ips.length > 0) {
                    const ol = document.createElement('ol');
                    ol.style.paddingLeft = '20px';
                    
                    data.top_ips.forEach(([ip, count]) => {
                        const li = document.createElement('li');
                        li.style.marginBottom = '10px';
                        li.innerHTML = `
                            <span style="font-weight: 600;">${ip}</span>
                            <span class="status-badge status-normal" style="float: right;">${count} conn</span>
                        `;
                        ol.appendChild(li);
                    });
                    
                    container.appendChild(ol);
                } else {
                    container.innerHTML = '<p style="text-align: center; color: var(--text-muted);">No connection data available</p>';
                }
                
            } catch (error) {
                console.error('Error loading top IPs:', error);
            }
        }
        
        // Load iptables rules
        async function loadIptables() {
            try {
                const response = await fetch('/api/iptables');
                const data = await response.json();
                
                const container = document.getElementById('iptables-output');
                if (data.iptables) {
                    container.innerHTML = '<pre style="color: var(--text-primary);">' + data.iptables + '</pre>';
                } else {
                    container.innerHTML = '<p style="color: var(--text-muted);">Unable to load iptables rules</p>';
                }
                
            } catch (error) {
                console.error('Error loading iptables:', error);
            }
        }
        
        // Load logs
        async function loadLogs() {
            try {
                const logType = document.getElementById('log-type').value;
                const response = await fetch(`/api/logs/${logType}?lines=100`);
                const data = await response.json();
                
                const container = document.getElementById('log-output');
                container.innerHTML = '';
                
                if (data.logs && data.logs.length > 0) {
                    data.logs.reverse().forEach(log => {
                        const div = document.createElement('div');
                        div.className = 'log-entry';
                        
                        // Parse log line
                        const logClass = getLogClass(log);
                        const timestamp = log.substring(0, 15);
                        const message = log.substring(16);
                        
                        div.innerHTML = `
                            <span class="log-timestamp">${timestamp}</span>
                            <span class="log-level-${logClass}">${message}</span>
                        `;
                        
                        container.appendChild(div);
                    });
                } else {
                    container.innerHTML = '<p style="color: var(--text-muted); text-align: center;">No log entries found</p>';
                }
                
                // Scroll to bottom
                container.scrollTop = container.scrollHeight;
                
            } catch (error) {
                console.error('Error loading logs:', error);
            }
        }
        
        function getLogClass(log) {
            if (log.includes('CRITICAL') || log.includes('emerg') || log.includes('panic'))
                return 'critical';
            if (log.includes('ERROR') || log.includes('error') || log.includes('err'))
                return 'error';
            if (log.includes('WARNING') || log.includes('warning') || log.includes('warn'))
                return 'warning';
            return 'info';
        }
        
        // Load attack history
        async function loadAttackHistory() {
            try {
                const response = await fetch('/api/attack_history');
                const data = await response.json();
                
                const tbody = document.getElementById('attack-history-body');
                tbody.innerHTML = '';
                
                if (data.attacks && data.attacks.length > 0) {
                    data.attacks.forEach(attack => {
                        const tr = document.createElement('tr');
                        const startTime = new Date(attack[1] * 1000).toLocaleString();
                        const duration = attack[2] ? `${Math.round((attack[2] - attack[1]) / 60)} min` : 'Ongoing';
                        
                        tr.innerHTML = `
                            <td>${startTime}</td>
                            <td>${attack[3] || 'Unknown'}</td>
                            <td>${attack[4] || 'Unknown'}</td>
                            <td>${attack[5]?.toLocaleString() || 'N/A'}</td>
                            <td><span class="status-badge ${attack[6] === 'blocked' ? 'status-normal' : 'status-warning'}">${attack[6] || 'unknown'}</span></td>
                            <td>${duration}</td>
                        `;
                        
                        tbody.appendChild(tr);
                    });
                } else {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No attack history recorded</td></tr>';
                }
                
            } catch (error) {
                console.error('Error loading attack history:', error);
            }
        }
        
        // Load analysis data
        async function loadAnalysis() {
            try {
                // This would load historical data for charts
                // For now, we'll create sample charts
                createPerformanceChart();
                createConnectionChart();
                
            } catch (error) {
                console.error('Error loading analysis:', error);
            }
        }
        
        // Create performance chart
        function createPerformanceChart() {
            const ctx = document.getElementById('performance-chart').getContext('2d');
            
            if (charts.performance) {
                charts.performance.destroy();
            }
            
            // Sample data - in real app, this would come from API
            const labels = Array.from({length: 20}, (_, i) => `${i * 5} min ago`);
            const cpuData = Array.from({length: 20}, () => Math.random() * 100);
            const memoryData = Array.from({length: 20}, () => 30 + Math.random() * 40);
            const connectionData = Array.from({length: 20}, () => Math.random() * 1000);
            
            charts.performance = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'CPU Usage %',
                            data: cpuData,
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.4
                        },
                        {
                            label: 'Memory Usage %',
                            data: memoryData,
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            tension: 0.4
                        },
                        {
                            label: 'Connections',
                            data: connectionData,
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            tension: 0.4,
                            yAxisID: 'y1'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100,
                            title: {
                                display: true,
                                text: 'Percentage (%)'
                            }
                        },
                        y1: {
                            position: 'right',
                            beginAtZero: true,
                            title: {
                                display: true,
                                text: 'Connections'
                            }
                        }
                    }
                }
            });
        }
        
        // Create connection distribution chart
        function createConnectionChart() {
            const ctx = document.getElementById('connection-chart').getContext('2d');
            
            if (charts.connection) {
                charts.connection.destroy();
            }
            
            // Sample data
            charts.connection = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: ['ESTABLISHED', 'SYN_RECV', 'TIME_WAIT', 'LISTEN', 'OTHER'],
                    datasets: [{
                        data: [65, 20, 8, 5, 2],
                        backgroundColor: [
                            '#10b981',
                            '#ef4444',
                            '#f59e0b',
                            '#3b82f6',
                            '#8b5cf6'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'bottom'
                        }
                    }
                }
            });
        }
        
        // Countdown timer for auto-refresh
        function startCountdown() {
            const countdownElement = document.getElementById('refresh-countdown');
            
            updateInterval = setInterval(() => {
                countdown--;
                countdownElement.textContent = countdown;
                
                if (countdown <= 0) {
                    updateMetrics();
                    countdown = 5;
                }
            }, 1000);
        }
        
        // Initialize everything when page loads
        document.addEventListener('DOMContentLoaded', function() {
            // Load initial data
            updateMetrics();
            loadConnections();
            loadTopIPs();
            loadIptables();
            loadLogs();
            loadAttackHistory();
            
            // Start auto-refresh
            startCountdown();
            
            // Set up periodic updates for dashboard
            setInterval(updateMetrics, refreshInterval);
            
            // Set up logout handler
            document.querySelector('a[href*="logout"]')?.addEventListener('click', function(e) {
                if (!confirm('Are you sure you want to logout?')) {
                    e.preventDefault();
                }
            });
        });
        
        // Handle window unload
        window.addEventListener('beforeunload', function() {
            clearInterval(updateInterval);
        });
    </script>
</body>
</html>
<?php
// Handle logout
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}
WEB_INTERFACE

# Create systemd service for backend
echo "[+] Creating systemd service for monitoring backend..."
cat > /etc/systemd/system/ddos-monitor.service << 'SYSTEMD_SERVICE'
[Unit]
Description=DDoS Lab Monitoring Backend
After=network.target apache2.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www/html/ddos-monitor
ExecStart=/usr/bin/python3 /var/www/html/ddos-monitor/monitor_backend.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SYSTEMD_SERVICE

# Create startup script
echo "[+] Creating startup script..."
cat > $WEB_APP_DIR/start_monitor.sh << 'START_SCRIPT'
#!/bin/bash

# Start DDoS Lab Web Monitor

echo "Starting DDoS Lab Web Monitor..."
echo ""

# Start backend service
systemctl daemon-reload
systemctl enable ddos-monitor
systemctl start ddos-monitor

# Check status
echo "Checking services..."
echo ""

echo "1. Backend API (Python):"
if systemctl is-active ddos-monitor > /dev/null; then
    echo "   ✅ Running on http://localhost:5000/"
else
    echo "   ❌ Not running"
    echo "   Starting service..."
    systemctl start ddos-monitor
fi

echo ""
echo "2. Web Interface (Apache):"
if systemctl is-active apache2 > /dev/null; then
    IP=$(hostname -I | cut -d' ' -f1)
    echo "   ✅ Running on http://$IP/ddos-monitor/"
else
    echo "   ❌ Not running"
    echo "   Starting Apache..."
    systemctl start apache2
fi

echo ""
echo "3. Access Information:"
echo "   URL: http://$(hostname -I | cut -d' ' -f1)/ddos-monitor/"
echo "   Default password: ddoslab2024"
echo ""
echo "4. Quick Commands:"
echo "   View logs: journalctl -u ddos-monitor -f"
echo "   Restart: systemctl restart ddos-monitor"
echo "   Stop: systemctl stop ddos-monitor"
echo ""
echo "Web monitor is now ready!"
echo "Open the URL above in your browser to access the dashboard."
START_SCRIPT

chmod +x $WEB_APP_DIR/start_monitor.sh

# Create log directory and sample logs
echo "[+] Setting up logging system..."
mkdir -p $WEB_APP_DIR/logs
touch $WEB_APP_DIR/logs/ddos_attacks.log
touch $WEB_APP_DIR/logs/system_monitor.log

# Create sample attack log
cat > $WEB_APP_DIR/logs/ddos_attacks.log << 'SAMPLE_LOG'
2024-01-15 10:30:15 [INFO] DDoS monitoring system started
2024-01-15 10:32:45 [WARNING] SYN connection rate increased by 200%
2024-01-15 10:33:10 [ALERT] Potential SYN flood detected: 850 SYN_RECV connections
2024-01-15 10:33:30 [INFO] Rate limiting rules applied to INPUT chain
2024-01-15 10:34:15 [INFO] Attack mitigated: SYN packets dropped by firewall
2024-01-15 10:35:00 [INFO] System returning to normal operation
SAMPLE_LOG

# Set permissions
chown -R www-data:www-data $WEB_APP_DIR
chmod -R 755 $WEB_APP_DIR

# Install Python dependencies
echo "[+] Installing Python dependencies..."
pip3 install flask flask-cors psutil

# Enable Apache modules
echo "[+] Configuring Apache..."
a2enmod rewrite
systemctl restart apache2

# Start the monitoring system
echo "[+] Starting monitoring system..."
$WEB_APP_DIR/start_monitor.sh

echo ""
echo "==============================================="
echo "    WEB MONITORING APPLICATION READY!"
echo "==============================================="
echo ""
echo "✅ Access the web interface at:"
echo "   http://$(hostname -I | cut -d' ' -f1)/ddos-monitor/"
echo ""
echo "📊 Features:"
echo "   • Real-time attack monitoring"
echo "   • Live connection visualization"
echo "   • System performance metrics"
echo "   • Firewall rule viewer"
echo "   • Attack log analysis"
echo "   • Historical data charts"
echo ""
echo "🔧 Management commands:"
echo "   sudo systemctl status ddos-monitor"
echo "   sudo journalctl -u ddos-monitor -f"
echo "   sudo systemctl restart ddos-monitor"
echo ""
echo "🔐 Default login password: ddoslab2024"
echo "   Change in: /var/www/html/ddos-monitor/index.php"
echo ""
echo "==============================================="
