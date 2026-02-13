#!/usr/bin/python3
"""
COMPLETE REAL-TIME SYSTEM MONITOR
Shows ALL system information in real-time
"""
from flask import Flask, jsonify, Response
import psutil
import time
import os
import json
from datetime import datetime, timedelta
import threading
import socket
import netifaces
import subprocess

app = Flask(__name__)

# Store historical data
history = {
    'cpu': [],
    'memory': [],
    'network_rx': [],
    'network_tx': [],
    'connections': []
}

def get_all_metrics():
    """Collect ALL system metrics"""
    timestamp = datetime.now()
    
    # ========== CPU ==========
    cpu_percent = psutil.cpu_percent(interval=0.1, percpu=True)
    cpu_freq = psutil.cpu_freq()
    cpu_stats = psutil.cpu_stats()
    cpu_times = psutil.cpu_times_percent(interval=0.1)
    
    # ========== MEMORY ==========
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    
    # ========== DISK ==========
    disk_usage = psutil.disk_usage('/')
    disk_io = psutil.disk_io_counters()
    
    # ========== NETWORK ==========
    net_io = psutil.net_io_counters()
    net_connections = psutil.net_connections()
    net_if_addrs = psutil.net_if_addrs()
    net_if_stats = psutil.net_if_stats()
    
    # Network interfaces
    interfaces = {}
    for interface, addrs in net_if_addrs.items():
        interfaces[interface] = {
            'addresses': [str(addr.address) for addr in addrs],
            'stats': net_if_stats.get(interface, {})
        }
    
    # ========== PROCESSES ==========
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Sort by CPU usage
    processes.sort(key=lambda x: x.get('cpu_percent', 0) or 0, reverse=True)
    top_processes = processes[:10]
    
    # ========== SYSTEM INFO ==========
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot_time
    
    # ========== DDoS DETECTION (Real heuristics) ==========
    # Analyze connections for DDoS patterns
    ddos_indicators = analyze_ddos_patterns(net_connections)
    
    # ========== SERVICES STATUS ==========
    services = check_services()
    
    # ========== SYSTEM LOAD ==========
    try:
        load_avg = os.getloadavg()
    except:
        load_avg = (0.0, 0.0, 0.0)
    
    # ========== NETWORK CONNECTIONS ANALYSIS ==========
    connection_analysis = analyze_connections(net_connections)
    
    # ========== SECURITY STATUS ==========
    security_status = check_security()
    
    # Build complete response
    return {
        'timestamp': timestamp.isoformat(),
        'system': {
            'hostname': socket.gethostname(),
            'uptime': str(uptime).split('.')[0],
            'boot_time': boot_time.isoformat(),
            'users': [u.name for u in psutil.users()],
            'load_average': load_avg
        },
        
        'cpu': {
            'cores': psutil.cpu_count(),
            'cores_logical': psutil.cpu_count(logical=True),
            'percent_per_core': cpu_percent,
            'percent_total': sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0,
            'frequency': {
                'current': cpu_freq.current if cpu_freq else 0,
                'max': cpu_freq.max if cpu_freq else 0,
                'min': cpu_freq.min if cpu_freq else 0
            },
            'stats': {
                'ctx_switches': cpu_stats.ctx_switches,
                'interrupts': cpu_stats.interrupts,
                'soft_interrupts': cpu_stats.soft_interrupts,
                'syscalls': cpu_stats.syscalls
            },
            'times': {
                'user': cpu_times.user,
                'system': cpu_times.system,
                'idle': cpu_times.idle,
                'iowait': getattr(cpu_times, 'iowait', 0)
            }
        },
        
        'memory': {
            'total': memory.total,
            'available': memory.available,
            'used': memory.used,
            'free': memory.free,
            'percent': memory.percent,
            'swap_total': swap.total,
            'swap_used': swap.used,
            'swap_free': swap.free,
            'swap_percent': swap.percent
        },
        
        'disk': {
            'total': disk_usage.total,
            'used': disk_usage.used,
            'free': disk_usage.free,
            'percent': disk_usage.percent,
            'io': {
                'read_bytes': disk_io.read_bytes,
                'write_bytes': disk_io.write_bytes,
                'read_count': disk_io.read_count,
                'write_count': disk_io.write_count
            }
        },
        
        'network': {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errors_in': net_io.errin,
            'errors_out': net_io.errout,
            'dropped_in': net_io.dropin,
            'dropped_out': net_io.dropout,
            'interfaces': interfaces
        },
        
        'connections': connection_analysis,
        
        'processes': {
            'total': len(processes),
            'running': len([p for p in processes if p.get('status') == 'running']),
            'sleeping': len([p for p in processes if p.get('status') == 'sleeping']),
            'top_by_cpu': top_processes,
            'top_by_memory': sorted(processes, key=lambda x: x.get('memory_percent', 0) or 0, reverse=True)[:10]
        },
        
        'ddos_detection': ddos_indicators,
        
        'services': services,
        
        'security': security_status,
        
        'alerts': generate_alerts(memory, cpu_percent, connection_analysis, ddos_indicators)
    }

def analyze_connections(connections):
    """Analyze network connections for patterns"""
    stats = {
        'total': len(connections),
        'tcp': {'total': 0, 'estab': 0, 'syn_sent': 0, 'syn_recv': 0, 'fin_wait': 0, 'time_wait': 0, 'close': 0},
        'udp': 0,
        'by_port': {},
        'by_ip': {},
        'suspicious': []
    }
    
    for conn in connections:
        # TCP connections
        if conn.type == socket.SOCK_STREAM:
            stats['tcp']['total'] += 1
            if conn.status == 'ESTABLISHED':
                stats['tcp']['estab'] += 1
            elif conn.status == 'SYN_SENT':
                stats['tcp']['syn_sent'] += 1
            elif conn.status == 'SYN_RECV':
                stats['tcp']['syn_recv'] += 1
            elif conn.status == 'FIN_WAIT1' or conn.status == 'FIN_WAIT2':
                stats['tcp']['fin_wait'] += 1
            elif conn.status == 'TIME_WAIT':
                stats['tcp']['time_wait'] += 1
            elif conn.status == 'CLOSE_WAIT' or conn.status == 'CLOSED':
                stats['tcp']['close'] += 1
        
        # UDP connections
        elif conn.type == socket.SOCK_DGRAM:
            stats['udp'] += 1
        
        # Analyze by port
        if conn.laddr and conn.laddr.port:
            port = conn.laddr.port
            stats['by_port'][port] = stats['by_port'].get(port, 0) + 1
        
        # Analyze by remote IP
        if conn.raddr:
            ip = conn.raddr.ip
            stats['by_ip'][ip] = stats['by_ip'].get(ip, 0) + 1
            
            # Check for suspicious patterns
            if stats['by_ip'][ip] > 10:  # More than 10 connections from same IP
                stats['suspicious'].append({
                    'ip': ip,
                    'connections': stats['by_ip'][ip],
                    'ports': [conn.laddr.port if conn.laddr else 0]
                })
    
    # Sort ports by connection count
    stats['top_ports'] = sorted(stats['by_port'].items(), key=lambda x: x[1], reverse=True)[:10]
    stats['top_ips'] = sorted(stats['by_ip'].items(), key=lambda x: x[1], reverse=True)[:10]
    
    return stats

def analyze_ddos_patterns(connections):
    """Analyze connections for DDoS patterns"""
    indicators = {
        'detected': False,
        'confidence': 0,
        'type': 'none',
        'indicators': []
    }
    
    total_conns = len(connections)
    syn_count = 0
    udp_count = 0
    ip_counts = {}
    
    for conn in connections:
        # Count SYN connections
        if hasattr(conn, 'status') and conn.status == 'SYN_RECV':
            syn_count += 1
        
        # Count UDP connections
        if conn.type == socket.SOCK_DGRAM:
            udp_count += 1
        
        # Count connections per IP
        if conn.raddr:
            ip = conn.raddr.ip
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    # Check for SYN flood
    syn_ratio = syn_count / total_conns if total_conns > 0 else 0
    if syn_ratio > 0.3 and syn_count > 50:  # More than 30% SYN connections
        indicators['detected'] = True
        indicators['confidence'] = min(100, int(syn_ratio * 100))
        indicators['type'] = 'SYN Flood'
        indicators['indicators'].append(f"High SYN ratio: {syn_ratio:.1%}")
    
    # Check for UDP flood
    udp_ratio = udp_count / total_conns if total_conns > 0 else 0
    if udp_ratio > 0.4 and udp_count > 100:  # More than 40% UDP connections
        indicators['detected'] = True
        indicators['confidence'] = max(indicators['confidence'], min(100, int(udp_ratio * 100)))
        indicators['type'] = 'UDP Flood'
        indicators['indicators'].append(f"High UDP ratio: {udp_ratio:.1%}")
    
    # Check for connection flood from single IP
    for ip, count in ip_counts.items():
        if count > 50:  # More than 50 connections from single IP
            indicators['detected'] = True
            indicators['confidence'] = max(indicators['confidence'], min(100, count))
            indicators['type'] = 'Connection Flood'
            indicators['indicators'].append(f"High connections from {ip}: {count}")
    
    return indicators

def check_services():
    """Check status of common services"""
    services = {
        'ssh': check_service(22),
        'http': check_service(80),
        'https': check_service(443),
        'dns': check_service(53),
        'mysql': check_service(3306),
        'postgresql': check_service(5432),
        'redis': check_service(6379),
        'nginx': check_process('nginx'),
        'apache': check_process('apache2'),
        'docker': check_process('dockerd'),
        'fail2ban': check_process('fail2ban'),
        'ufw': check_ufw()
    }
    return services

def check_service(port):
    """Check if a port is listening"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0
    except:
        return False

def check_process(name):
    """Check if a process is running"""
    try:
        for proc in psutil.process_iter(['name']):
            if name.lower() in proc.info['name'].lower():
                return True
        return False
    except:
        return False

def check_ufw():
    """Check UFW firewall status"""
    try:
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
        return 'Status: active' in result.stdout
    except:
        return False

def check_security():
    """Check system security status"""
    return {
        'firewall': check_ufw(),
        'ssh_root_login': check_ssh_root_login(),
        'fail2ban': check_process('fail2ban'),
        'auto_updates': check_auto_updates(),
        'password_expiry': check_password_expiry()
    }

def check_ssh_root_login():
    """Check if SSH root login is disabled"""
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            content = f.read()
            return 'PermitRootLogin no' in content or 'PermitRootLogin prohibit-password' in content
    except:
        return False

def check_auto_updates():
    """Check if auto-updates are enabled"""
    try:
        return os.path.exists('/etc/apt/apt.conf.d/20auto-upgrades')
    except:
        return False

def check_password_expiry():
    """Check password expiry settings"""
    try:
        result = subprocess.run(['chage', '-l', 'root'], capture_output=True, text=True)
        return 'Password expires' in result.stdout
    except:
        return False

def generate_alerts(memory, cpu_percent, connections, ddos_indicators):
    """Generate system alerts"""
    alerts = []
    
    # Memory alert
    if memory.percent > 90:
        alerts.append({
            'level': 'CRITICAL',
            'message': f'Memory usage critical: {memory.percent:.1f}%',
            'type': 'memory'
        })
    elif memory.percent > 80:
        alerts.append({
            'level': 'WARNING',
            'message': f'Memory usage high: {memory.percent:.1f}%',
            'type': 'memory'
        })
    
    # CPU alert
    cpu_total = sum(cpu_percent) / len(cpu_percent) if cpu_percent else 0
    if cpu_total > 90:
        alerts.append({
            'level': 'CRITICAL',
            'message': f'CPU usage critical: {cpu_total:.1f}%',
            'type': 'cpu'
        })
    elif cpu_total > 80:
        alerts.append({
            'level': 'WARNING',
            'message': f'CPU usage high: {cpu_total:.1f}%',
            'type': 'cpu'
        })
    
    # Connection alert
    if connections['total'] > 1000:
        alerts.append({
            'level': 'WARNING',
            'message': f'High connection count: {connections["total"]}',
            'type': 'network'
        })
    
    # DDoS alert
    if ddos_indicators['detected']:
        alerts.append({
            'level': 'CRITICAL',
            'message': f'DDoS detected: {ddos_indicators["type"]} ({ddos_indicators["confidence"]}% confidence)',
            'type': 'ddos'
        })
    
    return alerts

# ========== FLASK ROUTES ==========

@app.route('/')
def monitor():
    """Main monitoring page"""
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>COMPLETE SYSTEM MONITOR</title>
    <meta charset="utf-8">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', 'Roboto', sans-serif; 
            background: #0f172a; 
            color: #e2e8f0; 
            padding: 20px;
            font-size: 14px;
            line-height: 1.6;
        }
        .container { max-width: 1800px; margin: 0 auto; }
        
        .header {
            background: linear-gradient(135deg, #1e40af 0%, #1e3a8a 100%);
            padding: 25px;
            margin-bottom: 25px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
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
        .header .timestamp { 
            font-size: 1.1rem; 
            color: #94a3b8;
            margin-top: 10px;
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
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid #334155;
        }
        .card-header h2 {
            font-size: 1.3rem;
            color: #60a5fa;
        }
        .card-header .badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        .badge-success { background: #065f46; color: #6ee7b7; }
        .badge-warning { background: #92400e; color: #fbbf24; }
        .badge-danger { background: #7f1d1d; color: #fca5a5; }
        .badge-info { background: #1e40af; color: #93c5fd; }
        
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }
        
        .metric {
            background: #0f172a;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #334155;
        }
        .metric-label {
            font-size: 0.85rem;
            color: #94a3b8;
            margin-bottom: 5px;
        }
        .metric-value {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        .metric-unit {
            font-size: 0.85rem;
            color: #64748b;
        }
        .metric-change {
            font-size: 0.85rem;
            margin-top: 5px;
        }
        .positive { color: #10b981; }
        .negative { color: #ef4444; }
        
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
            transition: width 0.5s ease;
        }
        .cpu-progress { background: linear-gradient(90deg, #3b82f6, #8b5cf6); }
        .mem-progress { background: linear-gradient(90deg, #10b981, #0d9488); }
        .disk-progress { background: linear-gradient(90deg, #f59e0b, #d97706); }
        .net-progress { background: linear-gradient(90deg, #ef4444, #dc2626); }
        
        .alert {
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            display: flex;
            align-items: center;
            gap: 12px;
            border-left: 4px solid;
        }
        .alert-critical {
            background: rgba(127, 29, 29, 0.2);
            border-left-color: #ef4444;
        }
        .alert-warning {
            background: rgba(146, 64, 14, 0.2);
            border-left-color: #f59e0b;
        }
        .alert-info {
            background: rgba(30, 64, 175, 0.2);
            border-left-color: #3b82f6;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
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
        .table tr:hover {
            background: rgba(255, 255, 255, 0.05);
        }
        
        .chart-container {
            height: 200px;
            margin-top: 20px;
            position: relative;
        }
        
        .connections-badge {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            padding: 4px 10px;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 6px;
            font-size: 0.85rem;
            margin: 2px;
        }
        
        .service-status {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 12px;
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
        }
        .service-up { color: #10b981; }
        .service-down { color: #ef4444; }
        
        .refresh-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #3b82f6;
            color: white;
            border: none;
            padding: 15px 25px;
            border-radius: 50px;
            font-weight: 600;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
            z-index: 1000;
            transition: all 0.3s;
        }
        .refresh-btn:hover {
            background: #2563eb;
            transform: scale(1.05);
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
            transition: all 0.3s;
        }
        .tab.active {
            background: #3b82f6;
            color: white;
        }
        .tab:hover:not(.active) {
            background: #334155;
        }
        
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .blink {
            animation: blink 1s infinite;
        }
        @keyframes blink {
            50% { opacity: 0.5; }
        }
        
        .ip-badge {
            font-family: monospace;
            background: #0f172a;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.9rem;
            border: 1px solid #334155;
        }
        
        .scrollable {
            max-height: 300px;
            overflow-y: auto;
            margin-top: 15px;
        }
        
        .legend {
            display: flex;
            gap: 15px;
            margin-top: 10px;
            flex-wrap: wrap;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 5px;
            font-size: 0.85rem;
            color: #94a3b8;
        }
        .legend-color {
            width: 12px;
            height: 12px;
            border-radius: 2px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ COMPLETE SYSTEM MONITOR</h1>
            <div class="timestamp" id="timestamp">Loading...</div>
            <div style="margin-top: 15px; display: flex; gap: 10px; justify-content: center;">
                <div class="badge badge-info" id="update-status">Live Updating</div>
                <div class="badge" id="system-status">System Normal</div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('overview')">📊 Overview</button>
            <button class="tab" onclick="switchTab('network')">🌐 Network</button>
            <button class="tab" onclick="switchTab('processes')">⚙️ Processes</button>
            <button class="tab" onclick="switchTab('security')">🛡️ Security</button>
            <button class="tab" onclick="switchTab('details')">🔍 Details</button>
        </div>
        
        <!-- OVERVIEW TAB -->
        <div id="overview" class="tab-content active">
            <!-- ALERTS -->
            <div class="card">
                <div class="card-header">
                    <h2>🚨 System Alerts</h2>
                    <div class="badge" id="alert-count">0 Alerts</div>
                </div>
                <div id="alerts-container">
                    <!-- Alerts will be populated here -->
                </div>
            </div>
            
            <!-- SYSTEM RESOURCES -->
            <div class="grid">
                <div class="card">
                    <div class="card-header">
                        <h2>💻 CPU</h2>
                        <div class="badge" id="cpu-status">Normal</div>
                    </div>
                    <div class="metric-grid">
                        <div class="metric">
                            <div class="metric-label">Total Usage</div>
                            <div class="metric-value" id="cpu-total">0%</div>
                            <div class="progress-bar">
                                <div class="progress-fill cpu-progress" id="cpu-bar" style="width: 0%"></div>
                            </div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">Cores</div>
                            <div class="metric-value" id="cpu-cores">0</div>
                            <div class="metric-unit">Logical: <span id="cpu-logical">0</span></div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">Frequency</div>
                            <div class="metric-value" id="cpu-freq">0 GHz</div>
                            <div class="metric-unit">Max: <span id="cpu-freq-max">0 GHz</span></div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2>🧠 Memory</h2>
                        <div class="badge" id="mem-status">Normal</div>
                    </div>
                    <div class="metric-grid">
                        <div class="metric">
                            <div class="metric-label">Used</div>
                            <div class="metric-value" id="mem-used">0 GB</div>
                            <div class="progress-bar">
                                <div class="progress-fill mem-progress" id="mem-bar" style="width: 0%"></div>
                            </div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">Total</div>
                            <div class="metric-value" id="mem-total">0 GB</div>
                            <div class="metric-unit">Available: <span id="mem-avail">0 GB</span></div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">Swap</div>
                            <div class="metric-value" id="swap-used">0 GB</div>
                            <div class="metric-unit">Total: <span id="swap-total">0 GB</span></div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2>💾 Disk</h2>
                        <div class="badge" id="disk-status">Normal</div>
                    </div>
                    <div class="metric-grid">
                        <div class="metric">
                            <div class="metric-label">Used</div>
                            <div class="metric-value" id="disk-used">0 GB</div>
                            <div class="progress-bar">
                                <div class="progress-fill disk-progress" id="disk-bar" style="width: 0%"></div>
                            </div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">Total</div>
                            <div class="metric-value" id="disk-total">0 GB</div>
                            <div class="metric-unit">Free: <span id="disk-free">0 GB</span></div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">IO Read</div>
                            <div class="metric-value" id="disk-read">0 MB/s</div>
                            <div class="metric-unit">Write: <span id="disk-write">0 MB/s</span></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- NETWORK & CONNECTIONS -->
            <div class="grid">
                <div class="card">
                    <div class="card-header">
                        <h2>🌐 Network</h2>
                        <div class="badge" id="net-status">Normal</div>
                    </div>
                    <div class="metric-grid">
                        <div class="metric">
                            <div class="metric-label">Download</div>
                            <div class="metric-value" id="net-rx">0 MB/s</div>
                            <div class="progress-bar">
                                <div class="progress-fill net-progress" id="net-rx-bar" style="width: 0%"></div>
                            </div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">Upload</div>
                            <div class="metric-value" id="net-tx">0 MB/s</div>
                            <div class="progress-bar">
                                <div class="progress-fill net-progress" id="net-tx-bar" style="width: 0%"></div>
                            </div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">Packets/s</div>
                            <div class="metric-value" id="net-packets">0</div>
                            <div class="metric-unit">Errors: <span id="net-errors">0</span></div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2>🔗 Connections</h2>
                        <div class="badge" id="conn-status">Normal</div>
                    </div>
                    <div class="metric-grid">
                        <div class="metric">
                            <div class="metric-label">Total</div>
                            <div class="metric-value" id="conn-total">0</div>
                            <div class="metric-unit">TCP: <span id="conn-tcp">0</span></div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">Established</div>
                            <div class="metric-value" id="conn-estab">0</div>
                            <div class="metric-unit">SYN: <span id="conn-syn">0</span></div>
                        </div>
                        <div class="metric">
                            <div class="metric-label">UDP</div>
                            <div class="metric-value" id="conn-udp">0</div>
                            <div class="metric-unit">Time Wait: <span id="conn-timewait">0</span></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- NETWORK TAB -->
        <div id="network" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-header">
                        <h2>🌐 Network Interfaces</h2>
                    </div>
                    <div id="interfaces-container">
                        <!-- Interfaces will be populated here -->
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2>🎯 Top Connection Ports</h2>
                    </div>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Connections</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody id="top-ports">
                            <!-- Ports will be populated here -->
                        </tbody>
                    </table>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2>📍 Top Remote IPs</h2>
                    </div>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Connections</th>
                                <th>Country</th>
                                <th>Risk</th>
                            </tr>
                        </thead>
                        <tbody id="top-ips">
                            <!-- IPs will be populated here -->
                        </tbody>
                    </table>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2>🛡️ DDoS Detection</h2>
                        <div class="badge" id="ddos-status">No Attacks</div>
                    </div>
                    <div id="ddos-info">
                        <!-- DDoS info will be populated here -->
                    </div>
                </div>
            </div>
        </div>
        
        <!-- PROCESSES TAB -->
        <div id="processes" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>⚙️ Top Processes by CPU</h2>
                    <div class="badge" id="process-count">0 Processes</div>
                </div>
                <table class="table">
                    <thead>
                        <tr>
                            <th>PID</th>
                            <th>Name</th>
                            <th>CPU %</th>
                            <th>Memory %</th>
                            <th>Status</th>
                            <th>User</th>
                        </tr>
                    </thead>
                    <tbody id="top-processes">
                        <!-- Processes will be populated here -->
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- SECURITY TAB -->
        <div id="security" class="tab-content">
            <div class="grid">
                <div class="card">
                    <div class="card-header">
                        <h2>🛡️ Security Status</h2>
                    </div>
                    <div id="security-status">
                        <!-- Security status will be populated here -->
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2>🔒 Services Status</h2>
                    </div>
                    <div id="services-status">
                        <!-- Services status will be populated here -->
                    </div>
                </div>
            </div>
        </div>
        
        <!-- DETAILS TAB -->
        <div id="details" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h2>🔍 System Details</h2>
                </div>
                <div id="system-details">
                    <!-- System details will be populated here -->
                </div>
            </div>
        </div>
    </div>
    
    <button class="refresh-btn" onclick="refreshData()">
        🔄 Refresh Data
    </button>
    
    <script>
        let lastData = null;
        let lastNetworkStats = { bytes_recv: 0, bytes_sent: 0, packets_recv: 0, packets_sent: 0, timestamp: Date.now() };
        let lastDiskStats = { read_bytes: 0, write_bytes: 0, timestamp: Date.now() };
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }
        
        function formatBps(bytesPerSecond) {
            return formatBytes(bytesPerSecond) + '/s';
        }
        
        function formatPercent(value) {
            return value.toFixed(1) + '%';
        }
        
        function getPortService(port) {
            const commonPorts = {
                22: 'SSH', 80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 3306: 'MySQL',
                5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB', 21: 'FTP',
                25: 'SMTP', 110: 'POP3', 143: 'IMAP', 3389: 'RDP', 5900: 'VNC'
            };
            return commonPorts[port] || 'Unknown';
        }
        
        function getRiskLevel(count) {
            if (count > 50) return '🔴 High';
            if (count > 20) return '🟡 Medium';
            return '🟢 Low';
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
        }
        
        async function fetchMetrics() {
            try {
                const response = await fetch('/api/all');
                if (!response.ok) throw new Error('Network response was not ok');
                return await response.json();
            } catch (error) {
                console.error('Error fetching metrics:', error);
                return null;
            }
        }
        
        function updateMetrics(data) {
            if (!data) return;
            
            lastData = data;
            
            // Update timestamp
            document.getElementById('timestamp').textContent = 
                new Date(data.timestamp).toLocaleString();
            
            // SYSTEM RESOURCES
            // CPU
            document.getElementById('cpu-total').textContent = formatPercent(data.cpu.percent_total);
            document.getElementById('cpu-bar').style.width = data.cpu.percent_total + '%';
            document.getElementById('cpu-cores').textContent = data.cpu.cores;
            document.getElementById('cpu-logical').textContent = data.cpu.cores_logical;
            document.getElementById('cpu-freq').textContent = (data.cpu.frequency.current / 1000).toFixed(2) + ' GHz';
            document.getElementById('cpu-freq-max').textContent = (data.cpu.frequency.max / 1000).toFixed(2) + ' GHz';
            
            // Memory
            document.getElementById('mem-used').textContent = formatBytes(data.memory.used);
            document.getElementById('mem-bar').style.width = data.memory.percent + '%';
            document.getElementById('mem-total').textContent = formatBytes(data.memory.total);
            document.getElementById('mem-avail').textContent = formatBytes(data.memory.available);
            document.getElementById('swap-used').textContent = formatBytes(data.memory.swap_used);
            document.getElementById('swap-total').textContent = formatBytes(data.memory.swap_total);
            
            // Disk
            document.getElementById('disk-used').textContent = formatBytes(data.disk.used);
            document.getElementById('disk-bar').style.width = data.disk.percent + '%';
            document.getElementById('disk-total').textContent = formatBytes(data.disk.total);
            document.getElementById('disk-free').textContent = formatBytes(data.disk.free);
            
            // Calculate disk IO rates
            const now = Date.now();
            const timeDiff = (now - lastDiskStats.timestamp) / 1000;
            const readRate = (data.disk.io.read_bytes - lastDiskStats.read_bytes) / timeDiff;
            const writeRate = (data.disk.io.write_bytes - lastDiskStats.write_bytes) / timeDiff;
            
            document.getElementById('disk-read').textContent = formatBps(readRate);
            document.getElementById('disk-write').textContent = formatBps(writeRate);
            
            lastDiskStats = {
                read_bytes: data.disk.io.read_bytes,
                write_bytes: data.disk.io.write_bytes,
                timestamp: now
            };
            
            // NETWORK
            // Calculate network rates
            const netTimeDiff = (now - lastNetworkStats.timestamp) / 1000;
            const rxRate = (data.network.bytes_recv - lastNetworkStats.bytes_recv) / netTimeDiff;
            const txRate = (data.network.bytes_sent - lastNetworkStats.bytes_sent) / netTimeDiff;
            const packetRate = ((data.network.packets_recv + data.network.packets_sent) - 
                               (lastNetworkStats.packets_recv + lastNetworkStats.packets_sent)) / netTimeDiff;
            
            document.getElementById('net-rx').textContent = formatBps(rxRate);
            document.getElementById('net-tx').textContent = formatBps(txRate);
            document.getElementById('net-packets').textContent = Math.round(packetRate).toLocaleString();
            document.getElementById('net-errors').textContent = 
                (data.network.errors_in + data.network.errors_out).toLocaleString();
            
            // Update network bars (scaled to max of 1 Gbps)
            const maxRate = 1000 * 1024 * 1024; // 1 Gbps in bytes/s
            document.getElementById('net-rx-bar').style.width = Math.min(100, (rxRate / maxRate) * 100) + '%';
            document.getElementById('net-tx-bar').style.width = Math.min(100, (txRate / maxRate) * 100) + '%';
            
            lastNetworkStats = {
                bytes_recv: data.network.bytes_recv,
                bytes_sent: data.network.bytes_sent,
                packets_recv: data.network.packets_recv,
                packets_sent: data.network.packets_sent,
                timestamp: now
            };
            
            // CONNECTIONS
            document.getElementById('conn-total').textContent = data.connections.total.toLocaleString();
            document.getElementById('conn-tcp').textContent = data.connections.tcp.total.toLocaleString();
            document.getElementById('conn-estab').textContent = data.connections.tcp.estab.toLocaleString();
            document.getElementById('conn-syn').textContent = data.connections.tcp.syn_recv.toLocaleString();
            document.getElementById('conn-udp').textContent = data.connections.udp.toLocaleString();
            document.getElementById('conn-timewait').textContent = data.connections.tcp.time_wait.toLocaleString();
            
            // ALERTS
            updateAlerts(data.alerts);
            
            // DDoS DETECTION
            updateDDoS(data.ddos_detection);
            
            // PROCESSES
            updateProcesses(data.processes);
            
            // NETWORK INTERFACES
            updateInterfaces(data.network.interfaces);
            
            // TOP PORTS
            updateTopPorts(data.connections.top_ports || []);
            
            // TOP IPs
            updateTopIPs(data.connections.top_ips || []);
            
            // SECURITY
            updateSecurity(data.security);
            
            // SERVICES
            updateServices(data.services);
            
            // SYSTEM DETAILS
            updateSystemDetails(data.system);
            
            // Update status badges
            updateStatusBadges(data);
        }
        
        function updateStatusBadges(data) {
            // CPU status
            const cpuStatus = document.getElementById('cpu-status');
            if (data.cpu.percent_total > 90) {
                cpuStatus.className = 'badge badge-danger';
                cpuStatus.textContent = 'Critical';
            } else if (data.cpu.percent_total > 70) {
                cpuStatus.className = 'badge badge-warning';
                cpuStatus.textContent = 'High';
            } else {
                cpuStatus.className = 'badge badge-success';
                cpuStatus.textContent = 'Normal';
            }
            
            // Memory status
            const memStatus = document.getElementById('mem-status');
            if (data.memory.percent > 90) {
                memStatus.className = 'badge badge-danger';
                memStatus.textContent = 'Critical';
            } else if (data.memory.percent > 80) {
                memStatus.className = 'badge badge-warning';
                memStatus.textContent = 'High';
            } else {
                memStatus.className = 'badge badge-success';
                memStatus.textContent = 'Normal';
            }
            
            // Disk status
            const diskStatus = document.getElementById('disk-status');
            if (data.disk.percent > 90) {
                diskStatus.className = 'badge badge-danger';
                diskStatus.textContent = 'Critical';
            } else if (data.disk.percent > 80) {
                diskStatus.className = 'badge badge-warning';
                diskStatus.textContent = 'High';
            } else {
                diskStatus.className = 'badge badge-success';
                diskStatus.textContent = 'Normal';
            }
            
            // Network status
            const netStatus = document.getElementById('net-status');
            const totalErrors = data.network.errors_in + data.network.errors_out;
            if (totalErrors > 100) {
                netStatus.className = 'badge badge-danger';
                netStatus.textContent = 'High Errors';
            } else if (totalErrors > 10) {
                netStatus.className = 'badge badge-warning';
                netStatus.textContent = 'Errors';
            } else {
                netStatus.className = 'badge badge-success';
                netStatus.textContent = 'Normal';
            }
            
            // Connection status
            const connStatus = document.getElementById('conn-status');
            if (data.connections.total > 5000) {
                connStatus.className = 'badge badge-danger';
                connStatus.textContent = 'Very High';
            } else if (data.connections.total > 1000) {
                connStatus.className = 'badge badge-warning';
                connStatus.textContent = 'High';
            } else {
                connStatus.className = 'badge badge-success';
                connStatus.textContent = 'Normal';
            }
            
            // System status
            const systemStatus = document.getElementById('system-status');
            if (data.alerts.some(a => a.level === 'CRITICAL')) {
                systemStatus.className = 'badge badge-danger';
                systemStatus.textContent = 'Critical Issues';
            } else if (data.alerts.some(a => a.level === 'WARNING')) {
                systemStatus.className = 'badge badge-warning';
                systemStatus.textContent = 'Warnings';
            } else {
                systemStatus.className = 'badge badge-success';
                systemStatus.textContent = 'System Normal';
            }
            
            // Alert count
            const alertCount = document.getElementById('alert-count');
            const criticalCount = data.alerts.filter(a => a.level === 'CRITICAL').length;
            const warningCount = data.alerts.filter(a => a.level === 'WARNING').length;
            
            if (criticalCount > 0) {
                alertCount.className = 'badge badge-danger';
                alertCount.textContent = `${criticalCount} Critical, ${warningCount} Warnings`;
            } else if (warningCount > 0) {
                alertCount.className = 'badge badge-warning';
                alertCount.textContent = `${warningCount} Warnings`;
            } else {
                alertCount.className = 'badge badge-success';
                alertCount.textContent = 'No Alerts';
            }
            
            // Process count
            document.getElementById('process-count').textContent = 
                `${data.processes.total.toLocaleString()} Processes`;
            
            // DDoS status
            const ddosStatus = document.getElementById('ddos-status');
            if (data.ddos_detection.detected) {
                ddosStatus.className = 'badge badge-danger blink';
                ddosStatus.textContent = 'ATTACK DETECTED!';
            } else {
                ddosStatus.className = 'badge badge-success';
                ddosStatus.textContent = 'No Attacks';
            }
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            if (alerts.length === 0) {
                container.innerHTML = `
                    <div class="alert alert-info">
                        <span style="font-size: 1.5rem;">✅</span>
                        <div>
                            <strong>No alerts</strong>
                            <div>System is operating normally</div>
                        </div>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = '';
            alerts.forEach(alert => {
                const alertClass = alert.level === 'CRITICAL' ? 'alert-critical' : 
                                 alert.level === 'WARNING' ? 'alert-warning' : 'alert-info';
                
                const icon = alert.level === 'CRITICAL' ? '🔴' :
                            alert.level === 'WARNING' ? '🟡' : '🔵';
                
                const element = document.createElement('div');
                element.className = `alert ${alertClass}`;
                element.innerHTML = `
                    <span style="font-size: 1.5rem;">${icon}</span>
                    <div>
                        <strong>${alert.level}: ${alert.type.toUpperCase()}</strong>
                        <div>${alert.message}</div>
                    </div>
                `;
                container.appendChild(element);
            });
        }
        
        function updateDDoS(ddos) {
            const container = document.getElementById('ddos-info');
            if (!ddos.detected) {
                container.innerHTML = `
                    <div style="text-align: center; padding: 20px;">
                        <div style="font-size: 3rem; color: #10b981;">✅</div>
                        <div style="margin-top: 10px; font-size: 1.1rem;">No DDoS attacks detected</div>
                        <div style="margin-top: 5px; color: #94a3b8;">System is secure</div>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = `
                <div style="background: rgba(239, 68, 68, 0.1); padding: 15px; border-radius: 8px; border: 1px solid #ef4444;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 15px;">
                        <div style="font-size: 2rem;">⚠️</div>
                        <div>
                            <strong style="color: #fca5a5; font-size: 1.2rem;">${ddos.type} DETECTED</strong>
                            <div style="color: #fca5a5;">Confidence: ${ddos.confidence}%</div>
                        </div>
                    </div>
                    <div style="margin-top: 10px;">
                        <strong>Indicators:</strong>
                        <ul style="margin-top: 5px; padding-left: 20px;">
                            ${ddos.indicators.map(ind => `<li style="color: #fca5a5;">${ind}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            `;
        }
        
        function updateProcesses(processes) {
            const container = document.getElementById('top-processes');
            container.innerHTML = '';
            
            processes.top_by_cpu.forEach(proc => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${proc.pid}</td>
                    <td>${proc.name}</td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 60px; height: 6px; background: #334155; border-radius: 3px;">
                                <div style="width: ${Math.min(100, proc.cpu_percent)}%; height: 100%; background: #3b82f6; border-radius: 3px;"></div>
                            </div>
                            <span>${proc.cpu_percent?.toFixed(1) || '0.0'}%</span>
                        </div>
                    </td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 60px; height: 6px; background: #334155; border-radius: 3px;">
                                <div style="width: ${Math.min(100, proc.memory_percent)}%; height: 100%; background: #10b981; border-radius: 3px;"></div>
                            </div>
                            <span>${proc.memory_percent?.toFixed(1) || '0.0'}%</span>
                        </div>
                    </td>
                    <td>
                        <span class="badge ${proc.status === 'running' ? 'badge-success' : 'badge-info'}">
                            ${proc.status}
                        </span>
                    </td>
                    <td>${proc.username || 'N/A'}</td>
                `;
                container.appendChild(row);
            });
        }
        
        function updateInterfaces(interfaces) {
            const container = document.getElementById('interfaces-container');
            container.innerHTML = '';
            
            Object.entries(interfaces).forEach(([name, info]) => {
                const card = document.createElement('div');
                card.className = 'metric';
                card.style.marginBottom = '15px';
                
                const addresses = info.addresses.join(', ') || 'No IP';
                const isUp = info.stats && info.stats.isup;
                
                card.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong>${name}</strong>
                            <div style="color: #94a3b8; font-size: 0.9rem;">${addresses}</div>
                        </div>
                        <span class="badge ${isUp ? 'badge-success' : 'badge-danger'}">
                            ${isUp ? 'UP' : 'DOWN'}
                        </span>
                    </div>
                `;
                container.appendChild(card);
            });
        }
        
        function updateTopPorts(ports) {
            const container = document.getElementById('top-ports');
            container.innerHTML = '';
            
            ports.forEach(([port, count]) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>
                        <span class="ip-badge">${port}</span>
                    </td>
                    <td>${getPortService(port)}</td>
                    <td>${count.toLocaleString()}</td>
                    <td>
                        <span class="badge ${count > 50 ? 'badge-warning' : 'badge-info'}">
                            ${count > 50 ? 'High' : 'Normal'}
                        </span>
                    </td>
                `;
                container.appendChild(row);
            });
        }
        
        function updateTopIPs(ips) {
            const container = document.getElementById('top-ips');
            container.innerHTML = '';
            
            ips.forEach(([ip, count]) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>
                        <span class="ip-badge">${ip}</span>
                    </td>
                    <td>${count.toLocaleString()}</td>
                    <td>Unknown</td>
                    <td>${getRiskLevel(count)}</td>
                `;
                container.appendChild(row);
            });
        }
        
        function updateSecurity(security) {
            const container = document.getElementById('security-status');
            container.innerHTML = '';
            
            const checks = [
                { name: 'Firewall Active', value: security.firewall, good: true },
                { name: 'SSH Root Login Disabled', value: security.ssh_root_login, good: true },
                { name: 'Fail2Ban Running', value: security.fail2ban, good: true },
                { name: 'Auto Updates Enabled', value: security.auto_updates, good: true },
                { name: 'Password Expiry Enabled', value: security.password_expiry, good: true }
            ];
            
            checks.forEach(check => {
                const element = document.createElement('div');
                element.className = 'service-status';
                element.style.marginBottom = '10px';
                
                const icon = check.value === check.good ? '✅' : '❌';
                const color = check.value === check.good ? 'service-up' : 'service-down';
                
                element.innerHTML = `
                    <span style="font-size: 1.2rem;">${icon}</span>
                    <span>${check.name}</span>
                    <span class="${color}" style="margin-left: auto;">
                        ${check.value === check.good ? 'Secure' : 'Not Secure'}
                    </span>
                `;
                container.appendChild(element);
            });
        }
        
        function updateServices(services) {
            const container = document.getElementById('services-status');
            container.innerHTML = '';
            
            Object.entries(services).forEach(([name, status]) => {
                const element = document.createElement('div');
                element.className = 'service-status';
                element.style.marginBottom = '10px';
                
                const icon = status ? '✅' : '❌';
                const color = status ? 'service-up' : 'service-down';
                const displayName = name.charAt(0).toUpperCase() + name.slice(1);
                
                element.innerHTML = `
                    <span style="font-size: 1.2rem;">${icon}</span>
                    <span>${displayName}</span>
                    <span class="${color}" style="margin-left: auto;">
                        ${status ? 'Running' : 'Stopped'}
                    </span>
                `;
                container.appendChild(element);
            });
        }
        
        function updateSystemDetails(system) {
            const container = document.getElementById('system-details');
            container.innerHTML = `
                <div class="metric-grid">
                    <div class="metric">
                        <div class="metric-label">Hostname</div>
                        <div class="metric-value">${system.hostname}</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Uptime</div>
                        <div class="metric-value">${system.uptime}</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Boot Time</div>
                        <div class="metric-value">${new Date(system.boot_time).toLocaleString()}</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Users</div>
                        <div class="metric-value">${system.users.length}</div>
                        <div class="metric-unit">${system.users.join(', ') || 'None'}</div>
                    </div>
                    <div class="metric">
                        <div class="metric-label">Load Average (1m)</div>
                        <div class="metric-value">${system.load_average[0]?.toFixed(2) || '0.00'}</div>
                        <div class="metric-unit">5m: ${system.load_average[1]?.toFixed(2) || '0.00'} | 15m: ${system.load_average[2]?.toFixed(2) || '0.00'}</div>
                    </div>
                </div>
            `;
        }
        
        async function refreshData() {
            const btn = document.querySelector('.refresh-btn');
            const originalText = btn.innerHTML;
            btn.innerHTML = '🔄 Loading...';
            btn.disabled = true;
            
            try {
                const data = await fetchMetrics();
                if (data) {
                    updateMetrics(data);
                }
            } catch (error) {
                console.error('Refresh failed:', error);
            } finally {
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        }
        
        // Auto-refresh every 3 seconds
        setInterval(refreshData, 3000);
        
        // Initial load
        refreshData();
    </script>
</body>
</html>
'''

# API endpoint that returns all metrics
@app.route('/api/all')
def api_all():
    return jsonify(get_all_metrics())

if __name__ == '__main__':
    print("\n" + "="*80)
    print("🌐 COMPLETE REAL-TIME SYSTEM MONITOR")
    print("="*80)
    print("📊 URL: http://0.0.0.0:5001")
    print("⚡ Real-time updates every 3 seconds")
    print("📈 Shows ALL system information")
    print("🛡️ Includes DDoS detection")
    print("🔒 Security monitoring")
    print("="*80 + "\n")
    
    app.run(host='0.0.0.0', port=5001, debug=True, threaded=True)
