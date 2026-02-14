#!/usr/bin/python3
"""
ULTIMATE ENTERPRISE DDoS MONITOR
Complete working version with all real data, historical tracking, and attack visualization
"""
from flask import Flask, jsonify, request, render_template_string
from flask_socketio import SocketIO, emit
import psutil
import time
import os
import sqlite3
from datetime import datetime, timedelta
import threading
import socket
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'enterprise_ddos_monitor_secret_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# ========== DATABASE SETUP ==========
def init_database():
    """Initialize SQLite database for historical data"""
    conn = sqlite3.connect('enterprise_monitor.db', check_same_thread=False)
    c = conn.cursor()
    
    # Metrics table (stores data every 10 seconds)
    c.execute('''CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        cpu_percent REAL,
        memory_percent REAL,
        connections_total INTEGER,
        connections_tcp INTEGER,
        connections_syn INTEGER,
        network_rx_bytes INTEGER,
        network_tx_bytes INTEGER,
        disk_usage_percent REAL,
        load_avg_1m REAL,
        attack_detected BOOLEAN DEFAULT 0,
        attack_type TEXT,
        attack_confidence REAL
    )''')
    
    # Attacks table (stores attack events)
    c.execute('''CREATE TABLE IF NOT EXISTS attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
        end_time DATETIME,
        attack_type TEXT,
        severity TEXT,
        peak_connections INTEGER,
        peak_cpu REAL,
        peak_memory REAL,
        duration_seconds INTEGER,
        resolved BOOLEAN DEFAULT 0,
        mitigation_action TEXT
    )''')
    
    # Create indexes for faster queries
    c.execute('CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics(timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_attacks_time ON attacks(start_time)')
    
    conn.commit()
    conn.close()
    
    print("✅ Database initialized: enterprise_monitor.db")

# Initialize database
init_database()

# ========== GLOBAL VARIABLES ==========
last_network_stats = {
    'bytes_recv': 0,
    'bytes_sent': 0,
    'packets_recv': 0,
    'packets_sent': 0,
    'timestamp': time.time()
}

last_disk_stats = {
    'read_bytes': 0,
    'write_bytes': 0,
    'timestamp': time.time()
}

active_attack = None
metrics_history = []
attack_history = []

# ========== METRICS COLLECTION ==========
def collect_all_metrics():
    """Collect comprehensive system metrics"""
    timestamp = datetime.now()
    
    try:
        # ========== CPU METRICS ==========
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
        cpu_freq = psutil.cpu_freq()
        cpu_stats = psutil.cpu_stats()
        
        # ========== MEMORY METRICS ==========
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # ========== DISK METRICS ==========
        disk_usage = psutil.disk_usage('/')
        disk_io = psutil.disk_io_counters()
        
        # Calculate disk I/O rates
        now = time.time()
        disk_time_diff = now - last_disk_stats['timestamp']
        disk_read_rate = (disk_io.read_bytes - last_disk_stats['read_bytes']) / disk_time_diff if disk_time_diff > 0 else 0
        disk_write_rate = (disk_io.write_bytes - last_disk_stats['write_bytes']) / disk_time_diff if disk_time_diff > 0 else 0
        
        last_disk_stats.update({
            'read_bytes': disk_io.read_bytes,
            'write_bytes': disk_io.write_bytes,
            'timestamp': now
        })
        
        # ========== NETWORK METRICS ==========
        net_io = psutil.net_io_counters()
        net_connections = psutil.net_connections()
        
        # Calculate network rates
        net_time_diff = now - last_network_stats['timestamp']
        rx_rate = (net_io.bytes_recv - last_network_stats['bytes_recv']) / net_time_diff if net_time_diff > 0 else 0
        tx_rate = (net_io.bytes_sent - last_network_stats['bytes_sent']) / net_time_diff if net_time_diff > 0 else 0
        
        last_network_stats.update({
            'bytes_recv': net_io.bytes_recv,
            'bytes_sent': net_io.bytes_sent,
            'packets_recv': net_io.packets_recv,
            'packets_sent': net_io.packets_sent,
            'timestamp': now
        })
        
        # ========== CONNECTION ANALYSIS ==========
        connection_stats = analyze_connections(net_connections)
        
        # ========== PROCESS METRICS ==========
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'username']):
            try:
                processes.append(proc.info)
            except:
                continue
        
        top_cpu = sorted(processes, key=lambda x: x.get('cpu_percent', 0) or 0, reverse=True)[:10]
        top_memory = sorted(processes, key=lambda x: x.get('memory_percent', 0) or 0, reverse=True)[:10]
        
        # ========== SYSTEM INFO ==========
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        
        try:
            load_avg = os.getloadavg()
        except:
            load_avg = (0.0, 0.0, 0.0)
        
        # ========== DDoS DETECTION ==========
        ddos_info = detect_ddos_attack(net_connections, connection_stats)
        
        # ========== ALERTS GENERATION ==========
        alerts = generate_alerts(cpu_percent, memory.percent, connection_stats['total'], ddos_info, disk_usage.percent)
        
        # ========== STORE METRICS IN DATABASE ==========
        store_metrics_in_db(
            cpu_percent, memory.percent, connection_stats['total'],
            connection_stats.get('tcp', 0), connection_stats.get('syn', 0),
            net_io.bytes_recv, net_io.bytes_sent, disk_usage.percent,
            load_avg[0], ddos_info
        )
        
        # ========== BUILD RESPONSE ==========
        metrics_data = {
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
                'max_frequency': cpu_freq.max if cpu_freq else 0,
                'ctx_switches': cpu_stats.ctx_switches,
                'interrupts': cpu_stats.interrupts
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
                'percent': disk_usage.percent,
                'used_gb': disk_usage.used / (1024**3),
                'total_gb': disk_usage.total / (1024**3),
                'free_gb': disk_usage.free / (1024**3),
                'read_rate_mbps': disk_read_rate / (1024**2),
                'write_rate_mbps': disk_write_rate / (1024**2)
            },
            'network': {
                'connections': connection_stats,
                'rx_rate_mbps': rx_rate / (1024**2),
                'tx_rate_mbps': tx_rate / (1024**2),
                'rx_total_gb': net_io.bytes_recv / (1024**3),
                'tx_total_gb': net_io.bytes_sent / (1024**3),
                'packets_rx': net_io.packets_recv,
                'packets_tx': net_io.packets_sent,
                'errors_in': net_io.errin,
                'errors_out': net_io.errout,
                'dropped_in': net_io.dropin,
                'dropped_out': net_io.dropout
            },
            'processes': {
                'total': len(processes),
                'running': len([p for p in processes if p.get('status') == 'running']),
                'sleeping': len([p for p in processes if p.get('status') == 'sleeping']),
                'top_cpu': top_cpu[:5],
                'top_memory': top_memory[:5]
            },
            'ddos': ddos_info,
            'alerts': alerts,
            'status': {
                'overall': 'normal' if not alerts else 'warning',
                'cpu': 'critical' if cpu_percent > 90 else 'warning' if cpu_percent > 80 else 'normal',
                'memory': 'critical' if memory.percent > 90 else 'warning' if memory.percent > 80 else 'normal',
                'disk': 'critical' if disk_usage.percent > 90 else 'warning' if disk_usage.percent > 80 else 'normal',
                'network': 'critical' if connection_stats['total'] > 5000 else 'warning' if connection_stats['total'] > 1000 else 'normal'
            }
        }
        
        # Store in memory cache (keep last 100 entries)
        metrics_history.append(metrics_data)
        if len(metrics_history) > 100:
            metrics_history.pop(0)
        
        return metrics_data
        
    except Exception as e:
        print(f"❌ Error collecting metrics: {e}")
        return None

def analyze_connections(connections):
    """Analyze network connections"""
    stats = {
        'total': len(connections),
        'tcp': 0,
        'udp': 0,
        'syn': 0,
        'established': 0,
        'time_wait': 0,
        'close_wait': 0,
        'listen': 0,
        'by_port': {},
        'by_ip': {}
    }
    
    for conn in connections:
        # Count by type
        if conn.type == 1:  # SOCK_STREAM (TCP)
            stats['tcp'] += 1
        elif conn.type == 2:  # SOCK_DGRAM (UDP)
            stats['udp'] += 1
        
        # Count by status
        if hasattr(conn, 'status'):
            status = conn.status
            if status == 'SYN_RECV':
                stats['syn'] += 1
            elif status == 'ESTABLISHED':
                stats['established'] += 1
            elif status == 'TIME_WAIT':
                stats['time_wait'] += 1
            elif status == 'CLOSE_WAIT':
                stats['close_wait'] += 1
            elif status == 'LISTEN':
                stats['listen'] += 1
        
        # Count by port
        if conn.laddr:
            port = conn.laddr.port
            stats['by_port'][port] = stats['by_port'].get(port, 0) + 1
        
        # Count by remote IP
        if conn.raddr:
            ip = conn.raddr.ip
            stats['by_ip'][ip] = stats['by_ip'].get(ip, 0) + 1
    
    # Get top ports and IPs
    stats['top_ports'] = sorted(stats['by_port'].items(), key=lambda x: x[1], reverse=True)[:10]
    stats['top_ips'] = sorted(stats['by_ip'].items(), key=lambda x: x[1], reverse=True)[:10]
    
    return stats

def detect_ddos_attack(connections, connection_stats):
    """Detect DDoS attacks based on connection patterns"""
    total_conns = connection_stats['total']
    if total_conns < 10:
        return {'detected': False, 'type': 'none', 'confidence': 0, 'severity': 'low', 'indicators': []}
    
    syn_ratio = connection_stats['syn'] / total_conns if total_conns > 0 else 0
    indicators = []
    
    # SYN Flood detection
    if syn_ratio > 0.3 and connection_stats['syn'] > 50:
        confidence = min(100, int(syn_ratio * 100))
        severity = 'high' if syn_ratio > 0.5 else 'medium'
        indicators.append(f'SYN Flood: {connection_stats["syn"]} SYN packets ({syn_ratio:.1%} ratio)')
        
        return {
            'detected': True,
            'type': 'SYN_FLOOD',
            'confidence': confidence,
            'severity': severity,
            'indicators': indicators
        }
    
    # UDP Flood detection
    udp_ratio = connection_stats['udp'] / total_conns if total_conns > 0 else 0
    if udp_ratio > 0.4 and connection_stats['udp'] > 100:
        confidence = min(100, int(udp_ratio * 100))
        severity = 'high' if udp_ratio > 0.6 else 'medium'
        indicators.append(f'UDP Flood: {connection_stats["udp"]} UDP packets ({udp_ratio:.1%} ratio)')
        
        return {
            'detected': True,
            'type': 'UDP_FLOOD',
            'confidence': confidence,
            'severity': severity,
            'indicators': indicators
        }
    
    # Connection flood from single IP
    for ip, count in connection_stats['by_ip'].items():
        if count > 50:  # More than 50 connections from single IP
            confidence = min(100, count)
            severity = 'high' if count > 100 else 'medium'
            indicators.append(f'Connection Flood from {ip}: {count} connections')
            
            return {
                'detected': True,
                'type': 'CONNECTION_FLOOD',
                'confidence': confidence,
                'severity': severity,
                'indicators': indicators
            }
    
    # Port scan detection
    if len(connection_stats['by_port']) > 50 and total_conns > 100:
        return {
            'detected': True,
            'type': 'PORT_SCAN',
            'confidence': 75,
            'severity': 'medium',
            'indicators': [f'Port Scan: {len(connection_stats["by_port"])} ports targeted']
        }
    
    return {'detected': False, 'type': 'none', 'confidence': 0, 'severity': 'low', 'indicators': []}

def generate_alerts(cpu_percent, memory_percent, connections, ddos_info, disk_percent):
    """Generate system alerts based on thresholds"""
    alerts = []
    
    # CPU alerts
    if cpu_percent > 95:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'CPU',
            'message': f'CPU usage critical: {cpu_percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Investigate high CPU processes'
        })
    elif cpu_percent > 85:
        alerts.append({
            'level': 'WARNING',
            'type': 'CPU',
            'message': f'CPU usage high: {cpu_percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Monitor CPU usage'
        })
    
    # Memory alerts
    if memory_percent > 95:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'MEMORY',
            'message': f'Memory usage critical: {memory_percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Consider adding more RAM'
        })
    elif memory_percent > 85:
        alerts.append({
            'level': 'WARNING',
            'type': 'MEMORY',
            'message': f'Memory usage high: {memory_percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Monitor memory usage'
        })
    
    # Connection alerts
    if connections > 10000:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'CONNECTIONS',
            'message': f'Extremely high connection count: {connections}',
            'timestamp': datetime.now().isoformat(),
            'action': 'Possible DDoS attack'
        })
    elif connections > 5000:
        alerts.append({
            'level': 'WARNING',
            'type': 'CONNECTIONS',
            'message': f'High connection count: {connections}',
            'timestamp': datetime.now().isoformat(),
            'action': 'Monitor network traffic'
        })
    
    # DDoS alerts
    if ddos_info['detected']:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'DDoS',
            'message': f'DDoS attack detected: {ddos_info["type"]} ({ddos_info["confidence"]}% confidence)',
            'timestamp': datetime.now().isoformat(),
            'action': 'Activate mitigation strategies',
            'details': ddos_info
        })
    
    # Disk alerts
    if disk_percent > 95:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'DISK',
            'message': f'Disk usage critical: {disk_percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Free up disk space immediately'
        })
    elif disk_percent > 85:
        alerts.append({
            'level': 'WARNING',
            'type': 'DISK',
            'message': f'Disk usage high: {disk_percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Consider cleaning up files'
        })
    
    return alerts

def store_metrics_in_db(cpu, memory, connections, tcp, syn, rx, tx, disk, load, ddos_info):
    """Store metrics in SQLite database"""
    try:
        conn = sqlite3.connect('enterprise_monitor.db', check_same_thread=False)
        c = conn.cursor()
        
        c.execute('''INSERT INTO metrics 
                    (cpu_percent, memory_percent, connections_total, connections_tcp, connections_syn,
                     network_rx_bytes, network_tx_bytes, disk_usage_percent, load_avg_1m,
                     attack_detected, attack_type, attack_confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (cpu, memory, connections, tcp, syn, rx, tx, disk, load,
                  int(ddos_info['detected']), ddos_info['type'], ddos_info['confidence']))
        
        # If attack detected, record in attacks table
        if ddos_info['detected']:
            # Check if we have an ongoing attack
            c.execute('SELECT id FROM attacks WHERE resolved = 0 AND attack_type = ? ORDER BY start_time DESC LIMIT 1',
                     (ddos_info['type'],))
            existing_attack = c.fetchone()
            
            if existing_attack:
                # Update existing attack
                c.execute('''UPDATE attacks SET 
                           peak_connections = MAX(peak_connections, ?),
                           peak_cpu = MAX(peak_cpu, ?),
                           peak_memory = MAX(peak_memory, ?)
                           WHERE id = ?''',
                         (connections, cpu, memory, existing_attack[0]))
            else:
                # Start new attack record
                c.execute('''INSERT INTO attacks 
                           (attack_type, severity, peak_connections, peak_cpu, peak_memory)
                           VALUES (?, ?, ?, ?, ?)''',
                         (ddos_info['type'], ddos_info['severity'], connections, cpu, memory))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Error storing metrics: {e}")

def get_historical_metrics(hours=24):
    """Get historical metrics from database"""
    try:
        conn = sqlite3.connect('enterprise_monitor.db', check_same_thread=False)
        c = conn.cursor()
        
        c.execute('''SELECT 
                    strftime('%Y-%m-%d %H:%M', timestamp) as time,
                    AVG(cpu_percent) as cpu,
                    AVG(memory_percent) as memory,
                    AVG(connections_total) as connections,
                    AVG(disk_usage_percent) as disk,
                    MAX(attack_detected) as attack
                    FROM metrics 
                    WHERE timestamp >= datetime('now', ?)
                    GROUP BY strftime('%Y-%m-%d %H:%M', timestamp)
                    ORDER BY timestamp''', (f'-{hours} hours',))
        
        rows = c.fetchall()
        conn.close()
        
        return [{
            'time': row[0],
            'cpu': row[1] or 0,
            'memory': row[2] or 0,
            'connections': row[3] or 0,
            'disk': row[4] or 0,
            'attack': bool(row[5]) if row[5] is not None else False
        } for row in rows]
    except Exception as e:
        print(f"⚠️ Error getting historical data: {e}")
        return []

def get_attack_history(days=7):
    """Get attack history from database"""
    try:
        conn = sqlite3.connect('enterprise_monitor.db', check_same_thread=False)
        c = conn.cursor()
        
        c.execute('''SELECT 
                    start_time, attack_type, severity, 
                    peak_connections, peak_cpu, peak_memory,
                    duration_seconds, resolved, mitigation_action
                    FROM attacks 
                    WHERE start_time >= datetime('now', ?)
                    ORDER BY start_time DESC''', (f'-{days} days',))
        
        rows = c.fetchall()
        conn.close()
        
        attacks = []
        for row in rows:
            attacks.append({
                'timestamp': row[0],
                'type': row[1],
                'severity': row[2],
                'peak_connections': row[3] or 0,
                'peak_cpu': row[4] or 0,
                'peak_memory': row[5] or 0,
                'duration': row[6] or 0,
                'resolved': bool(row[7]),
                'mitigation': row[8] or 'None'
            })
        
        return attacks
    except Exception as e:
        print(f"⚠️ Error getting attack history: {e}")
        return []

# ========== FLASK ROUTES ==========
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>ULTIMATE ENTERPRISE DDoS MONITOR</title>
    <meta charset="utf-8">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/socket.io-client@4.5.0/dist/socket.io.min.js"></script>
    <style>
        :root {
            --primary: #3b82f6;
            --primary-dark: #1d4ed8;
            --secondary: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --dark: #0f172a;
            --darker: #020617;
            --light: #f8fafc;
            --gray: #64748b;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--darker);
            color: var(--light);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, var(--primary-dark) 0%, #1e3a8a 100%);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }
        
        .header h1 {
            font-size: 3rem;
            margin-bottom: 10px;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .header p {
            color: #94a3b8;
            font-size: 1.2rem;
            margin-bottom: 20px;
        }
        
        .status-bar {
            display: flex;
            gap: 15px;
            justify-content: center;
            margin-top: 20px;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 20px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        
        .status-dot.green { background: var(--secondary); animation: pulse 2s infinite; }
        .status-dot.red { background: var(--danger); animation: blink 1s infinite; }
        .status-dot.yellow { background: var(--warning); animation: pulse 2s infinite; }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            padding: 25px;
            backdrop-filter: blur(10px);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.4);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .card-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: #60a5fa;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-title i {
            font-size: 1.5rem;
        }
        
        .badge {
            padding: 6px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
        }
        
        .badge-success { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-warning { background: rgba(245, 158, 11, 0.2); color: #fde68a; border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-danger { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge-info { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.3); }
        
        .metric {
            margin: 15px 0;
        }
        
        .metric-label {
            font-size: 0.9rem;
            color: #94a3b8;
            margin-bottom: 5px;
        }
        
        .metric-value {
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 5px;
        }
        
        .metric-details {
            font-size: 0.9rem;
            color: #64748b;
        }
        
        .progress {
            height: 10px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 5px;
            margin: 15px 0;
            overflow: hidden;
        }
        
        .progress-bar {
            height: 100%;
            border-radius: 5px;
            transition: width 0.5s ease;
        }
        
        .progress-cpu { background: linear-gradient(90deg, #3b82f6, #8b5cf6); }
        .progress-memory { background: linear-gradient(90deg, #10b981, #0d9488); }
        .progress-disk { background: linear-gradient(90deg, #f59e0b, #d97706); }
        .progress-network { background: linear-gradient(90deg, #ef4444, #dc2626); }
        
        .chart-container {
            height: 250px;
            margin-top: 20px;
            position: relative;
        }
        
        .alert {
            padding: 20px;
            border-radius: 12px;
            margin: 15px 0;
            border-left: 6px solid;
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { transform: translateX(-20px); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        .alert-critical {
            background: rgba(239, 68, 68, 0.1);
            border-left-color: var(--danger);
        }
        
        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            border-left-color: var(--warning);
        }
        
        .alert-info {
            background: rgba(59, 130, 246, 0.1);
            border-left-color: var(--primary);
        }
        
        .alert-header {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 10px;
        }
        
        .alert-icon {
            font-size: 2rem;
        }
        
        .alert-title {
            font-weight: 600;
            font-size: 1.1rem;
        }
        
        .alert-message {
            color: #cbd5e1;
            margin-bottom: 10px;
        }
        
        .alert-action {
            font-size: 0.9rem;
            color: #94a3b8;
            font-style: italic;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            background: rgba(30, 41, 59, 0.5);
            padding: 10px;
            border-radius: 12px;
        }
        
        .tab {
            padding: 15px 30px;
            background: transparent;
            border: none;
            color: #94a3b8;
            cursor: pointer;
            border-radius: 8px;
            font-weight: 600;
            font-size: 1rem;
            transition: all 0.3s;
        }
        
        .tab:hover {
            background: rgba(255, 255, 255, 0.1);
        }
        
        .tab.active {
            background: var(--primary);
            color: white;
            box-shadow: 0 5px 15px rgba(59, 130, 246, 0.3);
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .tab-content.active {
            display: block;
        }
        
        .attack-visualization {
            height: 300px;
            background: rgba(15, 23, 42, 0.5);
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin: 20px 0;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            overflow: hidden;
        }
        
        .attack-node {
            position: absolute;
            width: 60px;
            height: 60px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            font-weight: bold;
            z-index: 10;
        }
        
        .attack-node.center {
            background: var(--danger);
            color: white;
            box-shadow: 0 0 40px rgba(239, 68, 68, 0.5);
        }
        
        .attack-node.attacker {
            background: var(--warning);
            color: black;
            font-size: 1.2rem;
        }
        
        .attack-line {
            position: absolute;
            height: 2px;
            background: rgba(239, 68, 68, 0.3);
            transform-origin: 0 0;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .table th {
            text-align: left;
            padding: 15px;
            background: rgba(15, 23, 42, 0.5);
            color: #94a3b8;
            font-weight: 600;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .table td {
            padding: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .table tr:hover {
            background: rgba(255, 255, 255, 0.05);
        }
        
        .connection-badge {
            display: inline-block;
            padding: 4px 12px;
            background: rgba(59, 130, 246, 0.2);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 6px;
            font-size: 0.85rem;
            margin: 2px;
        }
        
        .refresh-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: var(--primary);
            color: white;
            border: none;
            padding: 15px 25px;
            border-radius: 50px;
            font-weight: 600;
            cursor: pointer;
            box-shadow: 0 10px 25px rgba(59, 130, 246, 0.4);
            z-index: 1000;
            transition: all 0.3s;
        }
        
        .refresh-btn:hover {
            background: var(--primary-dark);
            transform: scale(1.05);
        }
        
        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 2rem;
            }
            
            .tabs {
                flex-wrap: wrap;
            }
            
            .tab {
                flex: 1;
                min-width: 120px;
                padding: 12px 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ULTIMATE ENTERPRISE DDoS MONITOR</h1>
            <p>Real-time System Monitoring & Advanced Threat Detection</p>
            <div class="status-bar">
                <div class="status-item">
                    <div class="status-dot green" id="status-dot"></div>
                    <span id="system-status">System Normal</span>
                </div>
                <div class="status-item">
                    <div class="status-dot" id="threat-dot"></div>
                    <span id="threat-level">Low Threat</span>
                </div>
                <div class="status-item">
                    <span id="update-time">--:--:--</span>
                </div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('overview')">📊 Overview</button>
            <button class="tab" onclick="switchTab('network')">🌐 Network Analysis</button>
            <button class="tab" onclick="switchTab('history')">📅 History</button>
            <button class="tab" onclick="switchTab('attacks')">⚔️ Attacks</button>
            <button class="tab" onclick="switchTab('processes')">⚙️ Processes</button>
        </div>
        
        <!-- Overview Tab -->
        <div id="overview" class="tab-content active">
            <!-- Alerts Section -->
            <div id="alerts-section"></div>
            
            <!-- System Metrics -->
            <div class="dashboard-grid">
                <!-- CPU Card -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">💻 CPU Usage</div>
                        <div class="badge" id="cpu-badge">Normal</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="cpu-value">0%</div>
                        <div class="metric-details" id="cpu-details">Cores: 0 | Freq: 0 GHz</div>
                    </div>
                    <div class="progress">
                        <div class="progress-bar progress-cpu" id="cpu-bar" style="width: 0%"></div>
                    </div>
                </div>
                
                <!-- Memory Card -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🧠 Memory</div>
                        <div class="badge" id="memory-badge">Normal</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="memory-value">0%</div>
                        <div class="metric-details" id="memory-details">0 GB / 0 GB</div>
                    </div>
                    <div class="progress">
                        <div class="progress-bar progress-memory" id="memory-bar" style="width: 0%"></div>
                    </div>
                </div>
                
                <!-- Network Card -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🌐 Network</div>
                        <div class="badge" id="network-badge">Normal</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="network-value">0 MB/s</div>
                        <div class="metric-details" id="network-details">Connections: 0</div>
                    </div>
                    <div class="progress">
                        <div class="progress-bar progress-network" id="network-bar" style="width: 0%"></div>
                    </div>
                </div>
                
                <!-- Disk Card -->
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">💾 Disk</div>
                        <div class="badge" id="disk-badge">Normal</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value" id="disk-value">0%</div>
                        <div class="metric-details" id="disk-details">0 GB free | I/O: 0 MB/s</div>
                    </div>
                    <div class="progress">
                        <div class="progress-bar progress-disk" id="disk-bar" style="width: 0%"></div>
                    </div>
                </div>
            </div>
            
            <!-- Charts Section -->
            <div class="dashboard-grid">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">📈 System Load (Live)</div>
                    </div>
                    <div class="chart-container">
                        <canvas id="load-chart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">📊 Network Connections</div>
                    </div>
                    <div class="chart-container">
                        <canvas id="connections-chart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Network Analysis Tab -->
        <div id="network" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🌐 DDoS Detection & Analysis</div>
                    <div class="badge" id="ddos-badge">No Attacks</div>
                </div>
                
                <div class="attack-visualization" id="attack-visualization">
                    <!-- Attack visualization will be rendered here -->
                </div>
                
                <div class="dashboard-grid">
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
                <div style="overflow-x: auto;">
                    <table class="table" id="attacks-table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>Confidence</th>
                                <th>Peak Connections</th>
                                <th>CPU Peak</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            <!-- Attacks will be populated here -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- Processes Tab -->
        <div id="processes" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">⚙️ Top Processes</div>
                    <div class="badge" id="process-count">0 Processes</div>
                </div>
                <div style="overflow-x: auto;">
                    <table class="table" id="processes-table">
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
                        <tbody>
                            <!-- Processes will be populated here -->
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <button class="refresh-btn" onclick="refreshAllData()">
        🔄 Refresh Data
    </button>
    
    <script>
        // Global variables
        let socket = null;
        let charts = {};
        let currentData = null;
        let attackAnimationInterval = null;
        
        // Initialize WebSocket connection
        function initWebSocket() {
            socket = io();
            
            socket.on('connect', () => {
                console.log('✅ Connected to WebSocket server');
                updateStatus('connected');
                
                // Request initial data
                socket.emit('get_metrics');
                
                // Set up periodic requests
                setInterval(() => {
                    socket.emit('get_metrics');
                }, 3000); // Request every 3 seconds
            });
            
            socket.on('metrics', (data) => {
                updateDashboard(data);
            });
            
            socket.on('alert', (alert) => {
                showAlert(alert);
            });
            
            socket.on('attack_detected', (attack) => {
                handleAttackDetection(attack);
            });
            
            socket.on('disconnect', () => {
                updateStatus('disconnected');
            });
        }
        
        // Initialize charts
        function initCharts() {
            // System Load Chart
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
                            fill: true,
                            borderWidth: 2
                        },
                        {
                            label: 'Memory %',
                            data: [],
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            tension: 0.4,
                            fill: true,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#94a3b8',
                                font: { size: 12 }
                            }
                        }
                    },
                    scales: {
                        x: {
                            display: false
                        },
                        y: {
                            min: 0,
                            max: 100,
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            },
                            ticks: {
                                color: '#94a3b8',
                                callback: function(value) {
                                    return value + '%';
                                }
                            }
                        }
                    }
                }
            });
            
            // Connections Chart
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
                            fill: true,
                            borderWidth: 2
                        },
                        {
                            label: 'SYN Connections',
                            data: [],
                            borderColor: '#f59e0b',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            tension: 0.4,
                            fill: true,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#94a3b8',
                                font: { size: 12 }
                            }
                        }
                    },
                    scales: {
                        x: {
                            display: false
                        },
                        y: {
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            },
                            ticks: {
                                color: '#94a3b8'
                            }
                        }
                    }
                }
            });
            
            // Historical Chart
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
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            tension: 0.3,
                            fill: true,
                            borderWidth: 2
                        },
                        {
                            label: 'Memory %',
                            data: [],
                            borderColor: '#10b981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            tension: 0.3,
                            fill: true,
                            borderWidth: 2
                        },
                        {
                            label: 'Connections',
                            data: [],
                            borderColor: '#ef4444',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            tension: 0.3,
                            fill: true,
                            borderWidth: 2
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: {
                                color: '#94a3b8',
                                font: { size: 12 }
                            }
                        }
                    },
                    scales: {
                        x: {
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            },
                            ticks: {
                                color: '#94a3b8',
                                maxRotation: 45
                            }
                        },
                        y: {
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            },
                            ticks: {
                                color: '#94a3b8'
                            }
                        }
                    }
                }
            });
        }
        
        // Update dashboard with new data
        function updateDashboard(data) {
            currentData = data;
            
            // Update timestamp
            const now = new Date(data.timestamp);
            document.getElementById('update-time').textContent = now.toLocaleTimeString();
            
            // Update CPU
            document.getElementById('cpu-value').textContent = data.cpu.percent.toFixed(1) + '%';
            document.getElementById('cpu-bar').style.width = data.cpu.percent + '%';
            document.getElementById('cpu-details').textContent = 
                `Cores: ${data.cpu.cores} | Freq: ${(data.cpu.frequency / 1000).toFixed(1)} GHz`;
            updateBadge('cpu', data.cpu.percent);
            
            // Update Memory
            document.getElementById('memory-value').textContent = data.memory.percent.toFixed(1) + '%';
            document.getElementById('memory-bar').style.width = data.memory.percent + '%';
            document.getElementById('memory-details').textContent = 
                `${data.memory.used_gb.toFixed(1)} GB / ${data.memory.total_gb.toFixed(1)} GB`;
            updateBadge('memory', data.memory.percent);
            
            // Update Network
            const throughput = (data.network.rx_rate_mbps + data.network.tx_rate_mbps).toFixed(1);
            document.getElementById('network-value').textContent = throughput + ' MB/s';
            document.getElementById('network-bar').style.width = Math.min(100, throughput * 2) + '%';
            document.getElementById('network-details').textContent = 
                `Connections: ${data.network.connections.total}`;
            updateBadge('network', throughput * 2);
            
            // Update Disk
            document.getElementById('disk-value').textContent = data.disk.percent.toFixed(1) + '%';
            document.getElementById('disk-bar').style.width = data.disk.percent + '%';
            document.getElementById('disk-details').textContent = 
                `${data.disk.free_gb.toFixed(1)} GB free | I/O: ${(data.disk.read_rate_mbps + data.disk.write_rate_mbps).toFixed(1)} MB/s`;
            updateBadge('disk', data.disk.percent);
            
            // Update DDoS status
            updateDDoSStatus(data.ddos);
            
            // Update system status
            updateSystemStatus(data.status);
            
            // Update alerts
            updateAlerts(data.alerts);
            
            // Update charts
            updateCharts(data);
            
            // Update processes table
            updateProcessesTable(data.processes.top_cpu);
            
            // Update connection stats if on network tab
            if (document.getElementById('network').classList.contains('active')) {
                updateConnectionStats(data.network);
                updateDDoSIndicators(data.ddos);
                updateAttackVisualization(data.ddos);
            }
            
            // Update attack history if on attacks tab
            if (document.getElementById('attacks').classList.contains('active')) {
                loadAttackHistory();
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
        
        function updateDDoSStatus(ddos) {
            const badge = document.getElementById('ddos-badge');
            const threatDot = document.getElementById('threat-dot');
            const threatLevel = document.getElementById('threat-level');
            
            if (ddos.detected) {
                badge.textContent = 'ATTACK!';
                badge.className = 'badge badge-danger';
                threatDot.className = 'status-dot red';
                threatLevel.textContent = 'HIGH THREAT';
                threatLevel.style.color = '#fca5a5';
                
                // Start attack visualization
                startAttackVisualization(ddos);
            } else {
                badge.textContent = 'No Attacks';
                badge.className = 'badge badge-success';
                threatDot.className = 'status-dot green';
                threatLevel.textContent = 'Low Threat';
                threatLevel.style.color = '#6ee7b7';
                
                // Stop attack visualization
                stopAttackVisualization();
            }
        }
        
        function updateSystemStatus(status) {
            const statusDot = document.getElementById('status-dot');
            const systemStatus = document.getElementById('system-status');
            
            if (status.overall === 'critical') {
                statusDot.className = 'status-dot red';
                systemStatus.textContent = 'CRITICAL';
                systemStatus.style.color = '#fca5a5';
            } else if (status.overall === 'warning') {
                statusDot.className = 'status-dot yellow';
                systemStatus.textContent = 'WARNING';
                systemStatus.style.color = '#fde68a';
            } else {
                statusDot.className = 'status-dot green';
                systemStatus.textContent = 'System Normal';
                systemStatus.style.color = '#6ee7b7';
            }
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-section');
            
            if (alerts.length === 0) {
                container.innerHTML = `
                    <div class="alert alert-info">
                        <div class="alert-header">
                            <div class="alert-icon">✅</div>
                            <div class="alert-title">System Status: Normal</div>
                        </div>
                        <div class="alert-message">All systems operating within normal parameters</div>
                    </div>
                `;
                return;
            }
            
            container.innerHTML = '';
            alerts.forEach(alert => {
                const alertClass = alert.level === 'CRITICAL' ? 'alert-critical' : 'alert-warning';
                const icon = alert.level === 'CRITICAL' ? '🔴' : '🟡';
                
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert ${alertClass}`;
                alertDiv.innerHTML = `
                    <div class="alert-header">
                        <div class="alert-icon">${icon}</div>
                        <div class="alert-title">${alert.level}: ${alert.type}</div>
                    </div>
                    <div class="alert-message">${alert.message}</div>
                    <div class="alert-action">Action: ${alert.action}</div>
                `;
                container.appendChild(alertDiv);
            });
        }
        
        function updateCharts(data) {
            const time = new Date(data.timestamp).toLocaleTimeString();
            
            // Update load chart
            if (charts.load) {
                charts.load.data.labels.push(time);
                charts.load.data.datasets[0].data.push(data.cpu.percent);
                charts.load.data.datasets[1].data.push(data.memory.percent);
                
                // Keep only last 20 data points
                if (charts.load.data.labels.length > 20) {
                    charts.load.data.labels.shift();
                    charts.load.data.datasets.forEach(dataset => dataset.data.shift());
                }
                
                charts.load.update('none');
            }
            
            // Update connections chart
            if (charts.connections) {
                charts.connections.data.labels.push(time);
                charts.connections.data.datasets[0].data.push(data.network.connections.total);
                charts.connections.data.datasets[1].data.push(data.network.connections.syn || 0);
                
                if (charts.connections.data.labels.length > 20) {
                    charts.connections.data.labels.shift();
                    charts.connections.data.datasets.forEach(dataset => dataset.data.shift());
                }
                
                charts.connections.update('none');
            }
        }
        
        function updateProcessesTable(processes) {
            const tbody = document.querySelector('#processes-table tbody');
            tbody.innerHTML = '';
            
            document.getElementById('process-count').textContent = `${processes.length} Processes`;
            
            processes.forEach(proc => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${proc.pid}</td>
                    <td>${proc.name}</td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 60px; height: 8px; background: rgba(255, 255, 255, 0.1); border-radius: 4px;">
                                <div style="width: ${Math.min(100, proc.cpu_percent || 0)}%; height: 100%; background: #3b82f6; border-radius: 4px;"></div>
                            </div>
                            <span>${(proc.cpu_percent || 0).toFixed(1)}%</span>
                        </div>
                    </td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 60px; height: 8px; background: rgba(255, 255, 255, 0.1); border-radius: 4px;">
                                <div style="width: ${Math.min(100, proc.memory_percent || 0)}%; height: 100%; background: #10b981; border-radius: 4px;"></div>
                            </div>
                            <span>${(proc.memory_percent || 0).toFixed(1)}%</span>
                        </div>
                    </td>
                    <td>
                        <span class="badge ${proc.status === 'running' ? 'badge-success' : 'badge-info'}">
                            ${proc.status}
                        </span>
                    </td>
                    <td>${proc.username || 'N/A'}</td>
                `;
                tbody.appendChild(row);
            });
        }
        
        function updateConnectionStats(network) {
            const container = document.getElementById('connection-stats');
            
            const statsHTML = `
                <div class="metric">
                    <div class="metric-label">Total Connections</div>
                    <div class="metric-value">${network.connections.total}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">TCP Connections</div>
                    <div class="metric-value">${network.connections.tcp}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">UDP Connections</div>
                    <div class="metric-value">${network.connections.udp || 0}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">SYN Connections</div>
                    <div class="metric-value">${network.connections.syn || 0}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Established</div>
                    <div class="metric-value">${network.connections.established || 0}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Download Rate</div>
                    <div class="metric-value">${network.rx_rate_mbps.toFixed(1)} MB/s</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Upload Rate</div>
                    <div class="metric-value">${network.tx_rate_mbps.toFixed(1)} MB/s</div>
                </div>
            `;
            
            container.innerHTML = statsHTML;
        }
        
        function updateDDoSIndicators(ddos) {
            const container = document.getElementById('ddos-indicators');
            
            if (!ddos.detected) {
                container.innerHTML = `
                    <div style="text-align: center; padding: 20px; color: #94a3b8;">
                        <div style="font-size: 3rem;">✅</div>
                        <div style="margin-top: 10px; font-size: 1.1rem;">No DDoS indicators detected</div>
                        <div style="margin-top: 5px;">System is secure</div>
                    </div>
                `;
                return;
            }
            
            let indicatorsHTML = `
                <div class="metric">
                    <div class="metric-label">Attack Type</div>
                    <div class="metric-value" style="color: #fca5a5;">${ddos.type}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Confidence</div>
                    <div class="metric-value" style="color: #fca5a5;">${ddos.confidence}%</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Severity</div>
                    <div class="metric-value" style="color: #fca5a5;">${ddos.severity.toUpperCase()}</div>
                </div>
            `;
            
            if (ddos.indicators && ddos.indicators.length > 0) {
                indicatorsHTML += `
                    <div style="margin-top: 20px;">
                        <div style="font-weight: 600; margin-bottom: 10px; color: #fca5a5;">Detection Indicators:</div>
                        <ul style="padding-left: 20px; color: #fca5a5;">
                            ${ddos.indicators.map(ind => `<li>${ind}</li>`).join('')}
                        </ul>
                    </div>
                `;
            }
            
            container.innerHTML = indicatorsHTML;
        }
        
        function startAttackVisualization(ddos) {
            const container = document.getElementById('attack-visualization');
            
            // Clear any existing animation
            if (attackAnimationInterval) {
                clearInterval(attackAnimationInterval);
            }
            
            // Create visualization
            container.innerHTML = '';
            
            // Create center node (our server)
            const center = document.createElement('div');
            center.className = 'attack-node center';
            center.textContent = '🛡️';
            center.style.left = '50%';
            center.style.top = '50%';
            center.style.transform = 'translate(-50%, -50%)';
            container.appendChild(center);
            
            // Create attacker nodes based on attack type and confidence
            const attackerCount = Math.min(12, Math.max(5, Math.floor(ddos.confidence / 10)));
            
            for (let i = 0; i < attackerCount; i++) {
                const angle = (i / attackerCount) * 2 * Math.PI;
                const radius = 130 + Math.random() * 40; // Random radius between 130-170
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
            
            // Animate the lines
            let pulseState = 0;
            attackAnimationInterval = setInterval(() => {
                const lines = container.querySelectorAll('.attack-line');
                lines.forEach(line => {
                    pulseState = (pulseState + 0.1) % (2 * Math.PI);
                    const opacity = 0.2 + 0.3 * Math.sin(pulseState);
                    line.style.opacity = opacity;
                    line.style.backgroundColor = `rgba(239, 68, 68, ${opacity})`;
                });
            }, 50);
        }
        
        function stopAttackVisualization() {
            if (attackAnimationInterval) {
                clearInterval(attackAnimationInterval);
                attackAnimationInterval = null;
            }
            
            const container = document.getElementById('attack-visualization');
            container.innerHTML = `
                <div style="text-align: center; color: #94a3b8;">
                    <div style="font-size: 4rem;">🛡️</div>
                    <div style="margin-top: 10px; font-size: 1.2rem;">System Protected</div>
                    <div style="margin-top: 5px;">No active attacks detected</div>
                </div>
            `;
        }
        
        function handleAttackDetection(attack) {
            // Show notification
            showAlert({
                level: 'CRITICAL',
                type: 'DDoS ATTACK',
                message: `${attack.type} detected with ${attack.confidence}% confidence`,
                action: 'Activating defense protocols...'
            });
            
            // Update attack history
            loadAttackHistory();
        }
        
        function showAlert(alert) {
            // Implementation for showing real-time alerts
            console.log('Alert:', alert);
        }
        
        function updateStatus(status) {
            const statusDot = document.getElementById('status-dot');
            
            if (status === 'connected') {
                statusDot.className = 'status-dot green';
            } else if (status === 'disconnected') {
                statusDot.className = 'status-dot red';
            }
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
            
            // Load data for specific tabs
            if (tabName === 'history') {
                loadHistoricalData();
            } else if (tabName === 'attacks') {
                loadAttackHistory();
            } else if (tabName === 'network' && currentData) {
                updateAttackVisualization(currentData.ddos);
                updateConnectionStats(currentData.network);
                updateDDoSIndicators(currentData.ddos);
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
                    
                    // Format severity badge
                    let severityBadge = '';
                    if (attack.severity === 'high') {
                        severityBadge = '<span class="badge badge-danger">HIGH</span>';
                    } else if (attack.severity === 'medium') {
                        severityBadge = '<span class="badge badge-warning">MEDIUM</span>';
                    } else {
                        severityBadge = '<span class="badge badge-info">LOW</span>';
                    }
                    
                    // Format status
                    const status = attack.resolved ? 
                        '<span class="badge badge-success">RESOLVED</span>' :
                        '<span class="badge badge-danger">ACTIVE</span>';
                    
                    row.innerHTML = `
                        <td>${new Date(attack.timestamp).toLocaleString()}</td>
                        <td>${attack.type}</td>
                        <td>${severityBadge}</td>
                        <td>${attack.confidence || 0}%</td>
                        <td>${attack.peak_connections.toLocaleString()}</td>
                        <td>${attack.peak_cpu.toFixed(1)}%</td>
                        <td>${status}</td>
                    `;
                    tbody.appendChild(row);
                });
            } catch (error) {
                console.error('Error loading attack history:', error);
            }
        }
        
        function refreshAllData() {
            // Refresh all data
            if (socket && socket.connected) {
                socket.emit('get_metrics');
            }
            
            // Refresh historical data if on history tab
            if (document.getElementById('history').classList.contains('active')) {
                loadHistoricalData();
            }
            
            // Refresh attack history if on attacks tab
            if (document.getElementById('attacks').classList.contains('active')) {
                loadAttackHistory();
            }
        }
        
        // Initialize everything when page loads
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            initWebSocket();
            loadHistoricalData();
            loadAttackHistory();
        });
    </script>
</body>
</html>
''')

@app.route('/api/metrics')
def api_metrics():
    """Get current metrics"""
    metrics = collect_all_metrics()
    if metrics:
        return jsonify(metrics)
    return jsonify({'error': 'Failed to collect metrics'}), 500

@app.route('/api/historical/<int:hours>')
def api_historical(hours):
    """Get historical metrics"""
    data = get_historical_metrics(min(hours, 168))  # Max 7 days
    return jsonify(data)

@app.route('/api/attacks/<int:days>')
def api_attacks(days):
    """Get attack history"""
    data = get_attack_history(min(days, 30))  # Max 30 days
    return jsonify(data)

@app.route('/api/all')
def api_all():
    """Legacy endpoint - redirect to /api/metrics"""
    return api_metrics()

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    print(f"✅ Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Enterprise DDoS Monitor'})

@socketio.on('get_metrics')
def handle_get_metrics():
    """Handle metrics request"""
    metrics = collect_all_metrics()
    if metrics:
        emit('metrics', metrics)
        
        # Send alerts if any
        if metrics['alerts']:
            for alert in metrics['alerts']:
                if alert['level'] in ['CRITICAL', 'WARNING']:
                    emit('alert', alert)
        
        # Send attack detection if any
        if metrics['ddos']['detected']:
            emit('attack_detected', metrics['ddos'])

def background_monitoring():
    """Background monitoring thread"""
    while True:
        try:
            socketio.sleep(3)  # Update every 3 seconds
            
            metrics = collect_all_metrics()
            if metrics:
                socketio.emit('metrics', metrics)
                
                # Send alerts
                if metrics['alerts']:
                    for alert in metrics['alerts']:
                        if alert['level'] in ['CRITICAL', 'WARNING']:
                            socketio.emit('alert', alert)
                
                # Send attack detection
                if metrics['ddos']['detected']:
                    socketio.emit('attack_detected', metrics['ddos'])
                    
        except Exception as e:
            print(f"⚠️ Background monitoring error: {e}")

# Start background thread
threading.Thread(target=background_monitoring, daemon=True).start()

if __name__ == '__main__':
    print("\n" + "="*100)
    print("🚀 ULTIMATE ENTERPRISE DDoS MONITORING SYSTEM")
    print("="*100)
    print("📊 Dashboard URL: http://0.0.0.0:5001")
    print("⚡ Real-time updates every 3 seconds")
    print("💾 Historical data storage (SQLite database)")
    print("🛡️ Advanced DDoS attack detection with visualization")
    print("📈 Real-time charts and metrics")
    print("🔔 Alert system with notifications")
    print("="*100)
    print("\n📋 Available API Endpoints:")
    print("  • GET /              - Main dashboard")
    print("  • GET /api/metrics   - Current system metrics")
    print("  • GET /api/historical/<hours> - Historical data")
    print("  • GET /api/attacks/<days>     - Attack history")
    print("  • WebSocket: get_metrics     - Real-time updates")
    print("="*100 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=5005, debug=True, allow_unsafe_werkzeug=True)
