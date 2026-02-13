#!/usr/bin/python3
"""
ENTERPRISE DDoS MONITORING SYSTEM - WORKING VERSION
No numpy required, all real data with historical tracking
"""
from flask import Flask, jsonify, render_template_string
from flask_socketio import SocketIO
import psutil
import time
import os
import sqlite3
from datetime import datetime, timedelta
import threading
import socket
import random

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database
def init_database():
    conn = sqlite3.connect('enterprise_monitor.db', check_same_thread=False)
    c = conn.cursor()
    
    # Create metrics table
    c.execute('''CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        cpu_percent REAL,
        memory_percent REAL,
        connections INTEGER,
        network_rx INTEGER,
        network_tx INTEGER,
        disk_usage REAL,
        load_avg REAL,
        attack_detected BOOLEAN DEFAULT 0,
        attack_type TEXT,
        attack_confidence REAL
    )''')
    
    # Create attacks table
    c.execute('''CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        attack_type TEXT,
        severity TEXT,
        confidence REAL,
        duration_seconds INTEGER,
        connections_peak INTEGER,
        cpu_peak REAL,
        memory_peak REAL
    )''')
    
    # Create indexes
    c.execute('CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics(timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_attacks_time ON attacks(timestamp)')
    
    conn.commit()
    conn.close()

# Initialize database
init_database()

# Store last network stats for rate calculation
last_network = {'rx': 0, 'tx': 0, 'time': time.time()}
last_disk = {'read': 0, 'write': 0, 'time': time.time()}

def get_all_metrics():
    """Get comprehensive system metrics"""
    timestamp = datetime.now()
    
    # CPU
    cpu_percent = psutil.cpu_percent(interval=0.1)
    cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
    cpu_freq = psutil.cpu_freq()
    
    # Memory
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    # Disk
    disk = psutil.disk_usage('/')
    disk_io = psutil.disk_io_counters()
    
    # Network
    net_io = psutil.net_io_counters()
    net_connections = psutil.net_connections()
    
    # Processes
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
        try:
            processes.append(proc.info)
        except:
            continue
    
    # Sort processes
    top_cpu = sorted(processes, key=lambda x: x.get('cpu_percent', 0) or 0, reverse=True)[:10]
    top_memory = sorted(processes, key=lambda x: x.get('memory_percent', 0) or 0, reverse=True)[:10]
    
    # System info
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot_time
    
    # Load average
    try:
        load_avg = os.getloadavg()
    except:
        load_avg = (0.0, 0.0, 0.0)
    
    # Calculate rates
    now = time.time()
    time_diff = now - last_network['time']
    
    rx_rate = (net_io.bytes_recv - last_network['rx']) / time_diff if time_diff > 0 else 0
    tx_rate = (net_io.bytes_sent - last_network['tx']) / time_diff if time_diff > 0 else 0
    
    disk_read_rate = (disk_io.read_bytes - last_disk['read']) / time_diff if time_diff > 0 else 0
    disk_write_rate = (disk_io.write_bytes - last_disk['write']) / time_diff if time_diff > 0 else 0
    
    # Update last values
    last_network.update({'rx': net_io.bytes_recv, 'tx': net_io.bytes_sent, 'time': now})
    last_disk.update({'read': disk_io.read_bytes, 'write': disk_io.write_bytes, 'time': now})
    
    # Analyze connections for DDoS
    ddos_info = analyze_connections_for_ddos(net_connections)
    
    # Generate alerts
    alerts = generate_alerts(cpu_percent, memory.percent, len(net_connections), ddos_info)
    
    # Store metrics in database
    store_metrics(cpu_percent, memory.percent, len(net_connections), 
                  net_io.bytes_recv, net_io.bytes_sent, disk.percent, 
                  load_avg[0], ddos_info)
    
    # Return all metrics
    return {
        'timestamp': timestamp.isoformat(),
        'system': {
            'hostname': socket.gethostname(),
            'uptime': str(uptime).split('.')[0],
            'boot_time': boot_time.isoformat(),
            'load_avg': {
                '1m': load_avg[0],
                '5m': load_avg[1],
                '15m': load_avg[2]
            }
        },
        'cpu': {
            'percent': cpu_percent,
            'cores': len(cpu_per_core),
            'per_core': cpu_per_core,
            'frequency': cpu_freq.current if cpu_freq else 0,
            'max_frequency': cpu_freq.max if cpu_freq else 0
        },
        'memory': {
            'percent': memory.percent,
            'used_gb': memory.used / (1024**3),
            'total_gb': memory.total / (1024**3),
            'available_gb': memory.available / (1024**3),
            'swap_percent': swap.percent,
            'swap_used_gb': swap.used / (1024**3)
        },
        'disk': {
            'percent': disk.percent,
            'used_gb': disk.used / (1024**3),
            'total_gb': disk.total / (1024**3),
            'free_gb': disk.free / (1024**3),
            'read_rate_mb': disk_read_rate / (1024**2),
            'write_rate_mb': disk_write_rate / (1024**2)
        },
        'network': {
            'connections_total': len(net_connections),
            'connections_tcp': len([c for c in net_connections if c.type == 1]),
            'connections_udp': len([c for c in net_connections if c.type == 2]),
            'rx_rate_mb': rx_rate / (1024**2),
            'tx_rate_mb': tx_rate / (1024**2),
            'rx_total_gb': net_io.bytes_recv / (1024**3),
            'tx_total_gb': net_io.bytes_sent / (1024**3),
            'packets_rx': net_io.packets_recv,
            'packets_tx': net_io.packets_sent,
            'errors_in': net_io.errin,
            'errors_out': net_io.errout
        },
        'processes': {
            'total': len(processes),
            'running': len([p for p in processes if p.get('status') == 'running']),
            'sleeping': len([p for p in processes if p.get('status') == 'sleeping']),
            'top_cpu': top_cpu,
            'top_memory': top_memory
        },
        'ddos': ddos_info,
        'alerts': alerts
    }

def analyze_connections_for_ddos(connections):
    """Analyze connections for DDoS patterns"""
    total = len(connections)
    if total == 0:
        return {'detected': False, 'type': 'none', 'confidence': 0, 'indicators': []}
    
    # Analyze connection types
    tcp_conns = [c for c in connections if c.type == 1]
    udp_conns = [c for c in connections if c.type == 2]
    
    syn_count = 0
    estab_count = 0
    ip_counts = {}
    
    for conn in tcp_conns:
        if hasattr(conn, 'status'):
            if conn.status == 'SYN_RECV':
                syn_count += 1
            elif conn.status == 'ESTABLISHED':
                estab_count += 1
        
        if conn.raddr:
            ip = conn.raddr.ip
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    # Check for SYN flood
    syn_ratio = syn_count / total if total > 0 else 0
    if syn_ratio > 0.3 and syn_count > 50:
        return {
            'detected': True,
            'type': 'SYN_FLOOD',
            'confidence': min(100, int(syn_ratio * 100)),
            'severity': 'high' if syn_ratio > 0.5 else 'medium',
            'indicators': [f'SYN ratio: {syn_ratio:.1%}', f'SYN count: {syn_count}']
        }
    
    # Check for UDP flood
    udp_ratio = len(udp_conns) / total if total > 0 else 0
    if udp_ratio > 0.4 and len(udp_conns) > 100:
        return {
            'detected': True,
            'type': 'UDP_FLOOD',
            'confidence': min(100, int(udp_ratio * 100)),
            'severity': 'high' if udp_ratio > 0.6 else 'medium',
            'indicators': [f'UDP ratio: {udp_ratio:.1%}', f'UDP count: {len(udp_conns)}']
        }
    
    # Check for connection flood from single IP
    for ip, count in ip_counts.items():
        if count > 50:
            return {
                'detected': True,
                'type': 'CONNECTION_FLOOD',
                'confidence': min(100, count),
                'severity': 'high' if count > 100 else 'medium',
                'indicators': [f'IP {ip} has {count} connections']
            }
    
    return {'detected': False, 'type': 'none', 'confidence': 0, 'indicators': []}

def generate_alerts(cpu_percent, memory_percent, connections, ddos_info):
    """Generate system alerts"""
    alerts = []
    
    # CPU alert
    if cpu_percent > 90:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'CPU',
            'message': f'CPU usage critical: {cpu_percent:.1f}%',
            'timestamp': datetime.now().isoformat()
        })
    elif cpu_percent > 80:
        alerts.append({
            'level': 'WARNING',
            'type': 'CPU',
            'message': f'CPU usage high: {cpu_percent:.1f}%',
            'timestamp': datetime.now().isoformat()
        })
    
    # Memory alert
    if memory_percent > 90:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'MEMORY',
            'message': f'Memory usage critical: {memory_percent:.1f}%',
            'timestamp': datetime.now().isoformat()
        })
    elif memory_percent > 80:
        alerts.append({
            'level': 'WARNING',
            'type': 'MEMORY',
            'message': f'Memory usage high: {memory_percent:.1f}%',
            'timestamp': datetime.now().isoformat()
        })
    
    # Connection alert
    if connections > 5000:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'CONNECTIONS',
            'message': f'Extremely high connection count: {connections}',
            'timestamp': datetime.now().isoformat()
        })
    elif connections > 1000:
        alerts.append({
            'level': 'WARNING',
            'type': 'CONNECTIONS',
            'message': f'High connection count: {connections}',
            'timestamp': datetime.now().isoformat()
        })
    
    # DDoS alert
    if ddos_info['detected']:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'DDoS',
            'message': f'DDoS attack detected: {ddos_info["type"]} ({ddos_info["confidence"]}% confidence)',
            'timestamp': datetime.now().isoformat(),
            'details': ddos_info
        })
    
    # Disk alert
    try:
        disk = psutil.disk_usage('/')
        if disk.percent > 95:
            alerts.append({
                'level': 'CRITICAL',
                'type': 'DISK',
                'message': f'Disk usage critical: {disk.percent:.1f}%',
                'timestamp': datetime.now().isoformat()
            })
        elif disk.percent > 85:
            alerts.append({
                'level': 'WARNING',
                'type': 'DISK',
                'message': f'Disk usage high: {disk.percent:.1f}%',
                'timestamp': datetime.now().isoformat()
            })
    except:
        pass
    
    return alerts

def store_metrics(cpu, memory, connections, rx, tx, disk, load, ddos_info):
    """Store metrics in database"""
    try:
        conn = sqlite3.connect('enterprise_monitor.db', check_same_thread=False)
        c = conn.cursor()
        
        c.execute('''INSERT INTO metrics 
                    (cpu_percent, memory_percent, connections, network_rx, network_tx, 
                     disk_usage, load_avg, attack_detected, attack_type, attack_confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (cpu, memory, connections, rx, tx, disk, load,
                  ddos_info['detected'], ddos_info['type'], ddos_info['confidence']))
        
        # If attack detected, also record in attacks table
        if ddos_info['detected']:
            c.execute('''INSERT INTO attacks 
                        (attack_type, severity, confidence, connections_peak, cpu_peak, memory_peak)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (ddos_info['type'], ddos_info.get('severity', 'medium'), 
                      ddos_info['confidence'], connections, cpu, memory))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error storing metrics: {e}")

def get_historical_data(hours=24):
    """Get historical data from database"""
    try:
        conn = sqlite3.connect('enterprise_monitor.db', check_same_thread=False)
        c = conn.cursor()
        
        c.execute('''SELECT 
                    strftime('%Y-%m-%d %H:%M', timestamp) as time,
                    AVG(cpu_percent) as cpu,
                    AVG(memory_percent) as memory,
                    AVG(connections) as connections,
                    AVG(disk_usage) as disk,
                    MAX(attack_detected) as attack
                    FROM metrics 
                    WHERE timestamp >= datetime('now', ?)
                    GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
                    ORDER BY time''', (f'-{hours} hours',))
        
        rows = c.fetchall()
        conn.close()
        
        return [{
            'time': row[0],
            'cpu': row[1],
            'memory': row[2],
            'connections': row[3],
            'disk': row[4],
            'attack': bool(row[5])
        } for row in rows]
    except:
        return []

def get_attack_history(days=7):
    """Get attack history from database"""
    try:
        conn = sqlite3.connect('enterprise_monitor.db', check_same_thread=False)
        c = conn.cursor()
        
        c.execute('''SELECT 
                    timestamp, attack_type, severity, confidence,
                    connections_peak, cpu_peak, memory_peak,
                    duration_seconds
                    FROM attacks 
                    WHERE timestamp >= datetime('now', ?)
                    ORDER BY timestamp DESC''', (f'-{days} days',))
        
        rows = c.fetchall()
        conn.close()
        
        return [{
            'timestamp': row[0],
            'type': row[1],
            'severity': row[2],
            'confidence': row[3],
            'connections_peak': row[4],
            'cpu_peak': row[5],
            'memory_peak': row[6],
            'duration': row[7] or 0
        } for row in rows]
    except:
        return []

# HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>ENTERPRISE DDoS MONITOR</title>
    <meta charset="utf-8">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/socket.io-client@4.5.0/dist/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f172a; 
            color: #e2e8f0;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%);
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
            text-align: center;
            border: 1px solid #334155;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .header .subtitle {
            color: #94a3b8;
            font-size: 1.1rem;
        }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }
        
        .card {
            background: #1e293b;
            padding: 20px;
            border-radius: 12px;
            border: 1px solid #334155;
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #334155;
        }
        
        .card-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: #60a5fa;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .badge-success { background: #065f46; color: #6ee7b7; }
        .badge-warning { background: #92400e; color: #fbbf24; }
        .badge-danger { background: #7f1d1d; color: #fca5a5; }
        .badge-info { background: #1e40af; color: #93c5fd; }
        
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px;
            background: #0f172a;
            border-radius: 8px;
            margin-bottom: 10px;
            border: 1px solid #334155;
        }
        
        .metric-label {
            font-size: 0.9rem;
            color: #94a3b8;
        }
        
        .metric-value {
            font-size: 1.5rem;
            font-weight: 700;
        }
        
        .progress-bar {
            height: 8px;
            background: #334155;
            border-radius: 4px;
            margin-top: 10px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.5s;
        }
        
        .cpu-progress { background: linear-gradient(90deg, #3b82f6, #8b5cf6); }
        .mem-progress { background: linear-gradient(90deg, #10b981, #0d9488); }
        .disk-progress { background: linear-gradient(90deg, #f59e0b, #d97706); }
        .net-progress { background: linear-gradient(90deg, #ef4444, #dc2626); }
        
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid;
        }
        
        .alert-critical {
            background: rgba(239, 68, 68, 0.1);
            border-left-color: #ef4444;
        }
        
        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            border-left-color: #f59e0b;
        }
        
        .chart-container {
            height: 250px;
            margin-top: 20px;
        }
        
        .tabs {
            display: flex;
            gap: 5px;
            margin-bottom: 20px;
            background: #1e293b;
            padding: 5px;
            border-radius: 8px;
        }
        
        .tab {
            padding: 12px 24px;
            background: transparent;
            border: none;
            color: #94a3b8;
            cursor: pointer;
            border-radius: 6px;
            font-weight: 600;
        }
        
        .tab.active {
            background: #3b82f6;
            color: white;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
            animation: fadeIn 0.3s;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th {
            text-align: left;
            padding: 12px;
            background: #0f172a;
            color: #94a3b8;
            font-weight: 600;
            border-bottom: 1px solid #334155;
        }
        
        .table td {
            padding: 12px;
            border-bottom: 1px solid #334155;
        }
        
        .attack-visualization {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 300px;
            background: #0f172a;
            border-radius: 12px;
            border: 1px solid #334155;
            margin: 20px 0;
            position: relative;
        }
        
        .attack-node {
            position: absolute;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 1.5rem;
        }
        
        .attack-node.center {
            background: #ef4444;
            color: white;
            box-shadow: 0 0 30px rgba(239, 68, 68, 0.5);
        }
        
        .attack-node.attacker {
            background: #f59e0b;
            color: black;
        }
        
        .attack-line {
            position: absolute;
            height: 2px;
            background: rgba(239, 68, 68, 0.3);
            transform-origin: 0 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ENTERPRISE DDoS MONITOR</h1>
            <div class="subtitle">Real-time System Monitoring & Attack Detection</div>
            <div style="margin-top: 15px; display: flex; gap: 10px; justify-content: center;">
                <div class="badge badge-info" id="status">Live</div>
                <div class="badge" id="threat-level">Low Threat</div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('overview')">Overview</button>
            <button class="tab" onclick="switchTab('network')">Network</button>
            <button class="tab" onclick="switchTab('history')">History</button>
            <button class="tab" onclick="switchTab('attacks')">Attacks</button>
            <button class="tab" onclick="switchTab('processes')">Processes</button>
        </div>
        
        <!-- Overview Tab -->
        <div id="overview" class="tab-content active">
            <!-- Alerts -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🚨 System Alerts</div>
                    <div class="badge" id="alert-count">0 Alerts</div>
                </div>
                <div id="alerts-container">
                    <!-- Alerts will appear here -->
                </div>
            </div>
            
            <!-- System Metrics -->
            <div class="grid">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">💻 CPU</div>
                        <div class="badge" id="cpu-badge">Normal</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Usage</div>
                        <div class="metric-value" id="cpu-value">0%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill cpu-progress" id="cpu-bar" style="width: 0%"></div>
                    </div>
                    <div style="margin-top: 10px; font-size: 0.9rem; color: #94a3b8;">
                        Cores: <span id="cpu-cores">0</span> | Freq: <span id="cpu-freq">0 GHz</span>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🧠 Memory</div>
                        <div class="badge" id="memory-badge">Normal</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Usage</div>
                        <div class="metric-value" id="memory-value">0%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill mem-progress" id="memory-bar" style="width: 0%"></div>
                    </div>
                    <div style="margin-top: 10px; font-size: 0.9rem; color: #94a3b8;">
                        Used: <span id="memory-used">0 GB</span> / <span id="memory-total">0 GB</span>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">💾 Disk</div>
                        <div class="badge" id="disk-badge">Normal</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Usage</div>
                        <div class="metric-value" id="disk-value">0%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill disk-progress" id="disk-bar" style="width: 0%"></div>
                    </div>
                    <div style="margin-top: 10px; font-size: 0.9rem; color: #94a3b8;">
                        Free: <span id="disk-free">0 GB</span> | I/O: <span id="disk-io">0 MB/s</span>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🌐 Network</div>
                        <div class="badge" id="network-badge">Normal</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Throughput</div>
                        <div class="metric-value" id="network-value">0 MB/s</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill net-progress" id="network-bar" style="width: 0%"></div>
                    </div>
                    <div style="margin-top: 10px; font-size: 0.9rem; color: #94a3b8;">
                        Connections: <span id="network-connections">0</span> | Errors: <span id="network-errors">0</span>
                    </div>
                </div>
            </div>
            
            <!-- Charts -->
            <div class="grid">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">📈 System Load (24h)</div>
                    </div>
                    <div class="chart-container">
                        <canvas id="load-chart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">📊 Connections Trend</div>
                    </div>
                    <div class="chart-container">
                        <canvas id="connections-chart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Network Tab -->
        <div id="network" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🌐 Network Analysis & DDoS Detection</div>
                    <div class="badge" id="ddos-status">No Attacks</div>
                </div>
                
                <div class="attack-visualization" id="attack-visualization">
                    <!-- Attack visualization will appear here -->
                </div>
                
                <div class="grid">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">📡 Connection Statistics</div>
                        </div>
                        <div id="connection-stats">
                            <!-- Connection stats will appear here -->
                        </div>
                    </div>
                    
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">🎯 DDoS Indicators</div>
                        </div>
                        <div id="ddos-indicators">
                            <!-- DDoS indicators will appear here -->
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- History Tab -->
        <div id="history" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">📅 Historical Data (Last 24 Hours)</div>
                    <button onclick="loadHistoricalData()" class="badge badge-info">Refresh</button>
                </div>
                <div class="chart-container">
                    <canvas id="historical-chart"></canvas>
                </div>
            </div>
        </div>
        
        <!-- Attacks Tab -->
        <div id="attacks" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">⚔️ Attack History</div>
                </div>
                <table class="table" id="attacks-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Confidence</th>
                            <th>Connections</th>
                            <th>CPU Peak</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Attacks will appear here -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Processes Tab -->
        <div id="processes" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">⚙️ Top Processes</div>
                    <div class="badge" id="process-count">0 Processes</div>
                </div>
                <table class="table" id="processes-table">
                    <thead>
                        <tr>
                            <th>PID</th>
                            <th>Name</th>
                            <th>CPU %</th>
                            <th>Memory %</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Processes will appear here -->
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script>
        let socket = null;
        let charts = {};
        let historicalData = [];
        
        // Initialize WebSocket
        function initWebSocket() {
            socket = io();
            
            socket.on('connect', () => {
                console.log('Connected to WebSocket');
                document.getElementById('status').textContent = 'Live';
                document.getElementById('status').className = 'badge badge-success';
            });
            
            socket.on('metrics', (data) => {
                updateDashboard(data);
            });
            
            socket.on('alert', (alert) => {
                showAlert(alert);
            });
            
            socket.on('attack', (attack) => {
                handleAttack(attack);
            });
            
            socket.on('disconnect', () => {
                document.getElementById('status').textContent = 'Offline';
                document.getElementById('status').className = 'badge badge-danger';
            });
        }
        
        // Initialize charts
        function initCharts() {
            // Load chart
            const loadCtx = document.getElementById('load-chart').getContext('2d');
            charts.load = new Chart(loadCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'CPU %',
                            data: [],
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            tension: 0.4,
                            fill: true
                        },
                        {
                            label: 'Memory %',
                            data: [],
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            tension: 0.4,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: '#94a3b8' } } },
                    scales: {
                        x: { display: false },
                        y: {
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#94a3b8' }
                        }
                    }
                }
            });
            
            // Connections chart
            const connCtx = document.getElementById('connections-chart').getContext('2d');
            charts.connections = new Chart(connCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Total Connections',
                            data: [],
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.4,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: '#94a3b8' } } },
                    scales: {
                        x: { display: false },
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#94a3b8' }
                        }
                    }
                }
            });
            
            // Historical chart
            const histCtx = document.getElementById('historical-chart').getContext('2d');
            charts.historical = new Chart(histCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'CPU %',
                            data: [],
                            borderColor: '#3b82f6',
                            tension: 0.4
                        },
                        {
                            label: 'Memory %',
                            data: [],
                            borderColor: '#10b981',
                            tension: 0.4
                        },
                        {
                            label: 'Connections',
                            data: [],
                            borderColor: '#ef4444',
                            tension: 0.4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { labels: { color: '#94a3b8' } } },
                    scales: {
                        x: { 
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#94a3b8' }
                        },
                        y: {
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#94a3b8' }
                        }
                    }
                }
            });
        }
        
        // Update dashboard with new data
        function updateDashboard(data) {
            // Update quick stats
            document.getElementById('cpu-value').textContent = data.cpu.percent.toFixed(1) + '%';
            document.getElementById('cpu-bar').style.width = data.cpu.percent + '%';
            document.getElementById('cpu-cores').textContent = data.cpu.cores;
            document.getElementById('cpu-freq').textContent = (data.cpu.frequency / 1000).toFixed(1) + ' GHz';
            
            document.getElementById('memory-value').textContent = data.memory.percent.toFixed(1) + '%';
            document.getElementById('memory-bar').style.width = data.memory.percent + '%';
            document.getElementById('memory-used').textContent = data.memory.used_gb.toFixed(1) + ' GB';
            document.getElementById('memory-total').textContent = data.memory.total_gb.toFixed(1) + ' GB';
            
            document.getElementById('disk-value').textContent = data.disk.percent.toFixed(1) + '%';
            document.getElementById('disk-bar').style.width = data.disk.percent + '%';
            document.getElementById('disk-free').textContent = data.disk.free_gb.toFixed(1) + ' GB';
            document.getElementById('disk-io').textContent = (data.disk.read_rate_mb + data.disk.write_rate_mb).toFixed(1) + ' MB/s';
            
            const networkThroughput = (data.network.rx_rate_mb + data.network.tx_rate_mb).toFixed(1);
            document.getElementById('network-value').textContent = networkThroughput + ' MB/s';
            document.getElementById('network-bar').style.width = Math.min(100, networkThroughput * 10) + '%';
            document.getElementById('network-connections').textContent = data.network.connections_total;
            document.getElementById('network-errors').textContent = data.network.errors_in + data.network.errors_out;
            
            // Update status badges
            updateBadge('cpu', data.cpu.percent);
            updateBadge('memory', data.memory.percent);
            updateBadge('disk', data.disk.percent);
            updateBadge('network', networkThroughput * 10);
            
            // Update charts
            const time = new Date(data.timestamp).toLocaleTimeString();
            
            if (charts.load) {
                charts.load.data.labels.push(time);
                charts.load.data.datasets[0].data.push(data.cpu.percent);
                charts.load.data.datasets[1].data.push(data.memory.percent);
                
                if (charts.load.data.labels.length > 20) {
                    charts.load.data.labels.shift();
                    charts.load.data.datasets.forEach(dataset => dataset.data.shift());
                }
                
                charts.load.update('none');
            }
            
            if (charts.connections) {
                charts.connections.data.labels.push(time);
                charts.connections.data.datasets[0].data.push(data.network.connections_total);
                
                if (charts.connections.data.labels.length > 20) {
                    charts.connections.data.labels.shift();
                    charts.connections.data.datasets[0].data.shift();
                }
                
                charts.connections.update('none');
            }
            
            // Update processes table
            updateProcessesTable(data.processes.top_cpu);
            
            // Update alerts
            updateAlerts(data.alerts);
            
            // Update DDoS status
            updateDDoSStatus(data.ddos);
            
            // Update threat level
            const threatLevel = data.ddos.detected ? 'HIGH THREAT' : 'LOW THREAT';
            const threatClass = data.ddos.detected ? 'badge-danger' : 'badge-success';
            document.getElementById('threat-level').textContent = threatLevel;
            document.getElementById('threat-level').className = 'badge ' + threatClass;
            
            // Update attack visualization if on network tab
            if (document.getElementById('network').classList.contains('active')) {
                updateAttackVisualization(data.ddos);
                updateConnectionStats(data.network);
                updateDDoSIndicators(data.ddos);
            }
        }
        
        function updateBadge(type, value) {
            const badge = document.getElementById(`${type}-badge`);
            let level = 'Normal';
            let badgeClass = 'badge-success';
            
            if (type === 'cpu' || type === 'memory' || type === 'disk') {
                if (value > 90) {
                    level = 'Critical';
                    badgeClass = 'badge-danger';
                } else if (value > 80) {
                    level = 'High';
                    badgeClass = 'badge-warning';
                }
            } else if (type === 'network') {
                if (value > 80) {
                    level = 'High';
                    badgeClass = 'badge-warning';
                } else if (value > 60) {
                    level = 'Medium';
                    badgeClass = 'badge-info';
                }
            }
            
            badge.textContent = level;
            badge.className = 'badge ' + badgeClass;
        }
        
        function updateProcessesTable(processes) {
            const tbody = document.querySelector('#processes-table tbody');
            tbody.innerHTML = '';
            
            processes.forEach(proc => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${proc.pid}</td>
                    <td>${proc.name}</td>
                    <td>${proc.cpu_percent?.toFixed(1) || '0.0'}</td>
                    <td>${proc.memory_percent?.toFixed(1) || '0.0'}</td>
                    <td>${proc.status}</td>
                `;
                tbody.appendChild(row);
            });
            
            document.getElementById('process-count').textContent = processes.length + ' Processes';
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            const countBadge = document.getElementById('alert-count');
            
            if (alerts.length === 0) {
                container.innerHTML = '<div style="text-align: center; padding: 20px; color: #94a3b8;">No alerts</div>';
                countBadge.textContent = '0 Alerts';
                countBadge.className = 'badge badge-success';
                return;
            }
            
            container.innerHTML = '';
            let criticalCount = 0;
            let warningCount = 0;
            
            alerts.forEach(alert => {
                const alertDiv = document.createElement('div');
                const alertClass = alert.level === 'CRITICAL' ? 'alert-critical' : 'alert-warning';
                const icon = alert.level === 'CRITICAL' ? '🔴' : '🟡';
                
                if (alert.level === 'CRITICAL') criticalCount++;
                if (alert.level === 'WARNING') warningCount++;
                
                alertDiv.className = `alert ${alertClass}`;
                alertDiv.innerHTML = `
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <div style="font-size: 1.5rem;">${icon}</div>
                        <div>
                            <strong>${alert.type}:</strong> ${alert.message}
                            <div style="font-size: 0.85rem; color: #94a3b8; margin-top: 4px;">
                                ${new Date(alert.timestamp).toLocaleTimeString()}
                            </div>
                        </div>
                    </div>
                `;
                container.appendChild(alertDiv);
            });
            
            const totalAlerts = alerts.length;
            countBadge.textContent = `${totalAlerts} Alert${totalAlerts !== 1 ? 's' : ''}`;
            countBadge.className = criticalCount > 0 ? 'badge badge-danger' : 'badge badge-warning';
        }
        
        function updateDDoSStatus(ddos) {
            const statusBadge = document.getElementById('ddos-status');
            
            if (ddos.detected) {
                statusBadge.textContent = 'ATTACK DETECTED!';
                statusBadge.className = 'badge badge-danger';
                statusBadge.style.animation = 'none';
                setTimeout(() => {
                    statusBadge.style.animation = 'pulse 1s infinite';
                }, 10);
            } else {
                statusBadge.textContent = 'No Attacks';
                statusBadge.className = 'badge badge-success';
                statusBadge.style.animation = 'none';
            }
        }
        
        function updateAttackVisualization(ddos) {
            const container = document.getElementById('attack-visualization');
            
            if (!ddos.detected) {
                container.innerHTML = `
                    <div style="text-align: center; color: #94a3b8;">
                        <div style="font-size: 3rem;">✅</div>
                        <div style="margin-top: 10px;">No active attacks detected</div>
                        <div style="font-size: 0.9rem;">System is secure</div>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = '';
            
            // Create center node (our server)
            const center = document.createElement('div');
            center.className = 'attack-node center';
            center.textContent = '🛡️';
            center.style.left = '50%';
            center.style.top = '50%';
            center.style.transform = 'translate(-50%, -50%)';
            container.appendChild(center);
            
            // Create attacker nodes
            const attackerCount = Math.min(8, Math.max(3, Math.floor(ddos.confidence / 10)));
            for (let i = 0; i < attackerCount; i++) {
                const angle = (i / attackerCount) * 2 * Math.PI;
                const radius = 120;
                const x = radius * Math.cos(angle);
                const y = radius * Math.sin(angle);
                
                // Create connection line
                const line = document.createElement('div');
                line.className = 'attack-line';
                line.style.left = '50%';
                line.style.top = '50%';
                line.style.width = `${radius}px`;
                line.style.transform = `rotate(${angle}rad)`;
                container.appendChild(line);
                
                // Create attacker node
                const attacker = document.createElement('div');
                attacker.className = 'attack-node attacker';
                attacker.textContent = '⚔️';
                attacker.style.left = `calc(50% + ${x}px)`;
                attacker.style.top = `calc(50% + ${y}px)`;
                attacker.style.transform = 'translate(-50%, -50%)';
                container.appendChild(attacker);
            }
        }
        
        function updateConnectionStats(network) {
            const container = document.getElementById('connection-stats');
            container.innerHTML = `
                <div class="metric">
                    <div class="metric-label">Total Connections</div>
                    <div class="metric-value">${network.connections_total}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">TCP Connections</div>
                    <div class="metric-value">${network.connections_tcp}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">UDP Connections</div>
                    <div class="metric-value">${network.connections_udp}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Download Rate</div>
                    <div class="metric-value">${network.rx_rate_mb.toFixed(1)} MB/s</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Upload Rate</div>
                    <div class="metric-value">${network.tx_rate_mb.toFixed(1)} MB/s</div>
                </div>
            `;
        }
        
        function updateDDoSIndicators(ddos) {
            const container = document.getElementById('ddos-indicators');
            
            if (!ddos.detected) {
                container.innerHTML = '<div style="color: #94a3b8; text-align: center; padding: 20px;">No DDoS indicators detected</div>';
                return;
            }
            
            let indicatorsHTML = `
                <div class="metric">
                    <div class="metric-label">Attack Type</div>
                    <div class="metric-value">${ddos.type}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Confidence</div>
                    <div class="metric-value">${ddos.confidence}%</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Severity</div>
                    <div class="metric-value">${ddos.severity.toUpperCase()}</div>
                </div>
            `;
            
            if (ddos.indicators && ddos.indicators.length > 0) {
                indicatorsHTML += `
                    <div style="margin-top: 15px;">
                        <strong>Detection Indicators:</strong>
                        <ul style="margin-top: 10px; padding-left: 20px; color: #fca5a5;">
                            ${ddos.indicators.map(ind => `<li>${ind}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }
            
            container.innerHTML = indicatorsHTML;
        }
        
        function showAlert(alert) {
            // Implementation for showing real-time alerts
            console.log('Alert:', alert);
        }
        
        function handleAttack(attack) {
            // Implementation for handling attack events
            console.log('Attack:', attack);
        }
        
        function switchTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Load data for the tab if needed
            if (tabName === 'history') {
                loadHistoricalData();
            } else if (tabName === 'attacks') {
                loadAttackHistory();
            }
        }
        
        async function loadHistoricalData() {
            try {
                const response = await fetch('/api/historical/24');
                const data = await response.json();
                
                if (charts.historical && data.length > 0) {
                    charts.historical.data.labels = data.map(d => d.time);
                    charts.historical.data.datasets[0].data = data.map(d => d.cpu || 0);
                    charts.historical.data.datasets[1].data = data.map(d => d.memory || 0);
                    charts.historical.data.datasets[2].data = data.map(d => d.connections || 0);
                    charts.historical.update();
                }
            } catch (error) {
                console.error('Error loading historical data:', error);
            }
        }
        
        async function loadAttackHistory() {
            try {
                const response = await fetch('/api/attacks/7');
                const attacks = await response.json();
                
                const tbody = document.querySelector('#attacks-table tbody');
                tbody.innerHTML = '';
                
                attacks.forEach(attack => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${new Date(attack.timestamp).toLocaleString()}</td>
                        <td>${attack.type}</td>
                        <td>
                            <span class="badge ${attack.severity === 'high' ? 'badge-danger' : 'badge-warning'}">
                                ${attack.severity}
                            </span>
                        </td>
                        <td>${attack.confidence}%</td>
                        <td>${attack.connections_peak}</td>
                        <td>${attack.cpu_peak.toFixed(1)}%</td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (error) {
                console.error('Error loading attack history:', error);
            }
        }
        
        // Initialize everything
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            initWebSocket();
            loadHistoricalData();
            loadAttackHistory();
            
            // Request initial data
            socket.emit('request_metrics');
            
            // Set up periodic updates
            setInterval(() => {
                socket.emit('request_metrics');
            }, 3000);
        });
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    """Serve the dashboard"""
    return HTML_TEMPLATE

@app.route('/api/metrics')
def api_metrics():
    """Get current metrics"""
    metrics = get_all_metrics()
    return jsonify(metrics)

@app.route('/api/historical/<int:hours>')
def api_historical(hours):
    """Get historical data"""
    data = get_historical_data(min(hours, 168))  # Max 7 days
    return jsonify(data)

@app.route('/api/attacks/<int:days>')
def api_attacks(days):
    """Get attack history"""
    data = get_attack_history(min(days, 30))  # Max 30 days
    return jsonify(data)

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Enterprise DDoS Monitor'})

@socketio.on('request_metrics')
def handle_request_metrics():
    metrics = get_all_metrics()
    if metrics:
        emit('metrics', metrics)
        
        # Send alerts if any
        if metrics['alerts']:
            for alert in metrics['alerts']:
                if alert['level'] in ['CRITICAL', 'WARNING']:
                    emit('alert', alert)
        
        # Send attack info if detected
        if metrics['ddos']['detected']:
            emit('attack', metrics['ddos'])

def background_monitoring():
    """Background thread for monitoring"""
    while True:
        try:
            socketio.sleep(3)
            metrics = get_all_metrics()
            if metrics:
                socketio.emit('metrics', metrics)
        except Exception as e:
            print(f"Background monitoring error: {e}")

# Start background thread
threading.Thread(target=background_monitoring, daemon=True).start()

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🚀 ENTERPRISE DDoS MONITORING SYSTEM")
    print("="*80)
    print("📊 Dashboard URL: http://0.0.0.0:5001")
    print("⚡ Real-time updates every 3 seconds")
    print("💾 Historical data stored in SQLite")
    print("🛡️ Advanced DDoS attack detection")
    print("📈 Real-time charts and visualization")
    print("="*80 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)
