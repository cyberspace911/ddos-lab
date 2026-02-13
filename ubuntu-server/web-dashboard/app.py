#!/usr/bin/python3
"""
Enterprise DDoS Web Management Dashboard v4.0
Complete web-based management interface
"""

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit
import psutil
import os
import json
import subprocess
import threading
import time
import re
from datetime import datetime
from collections import deque
import sqlite3
import hashlib
import jwt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ddos-lab-secret-key-2024-enterprise'
app.config['DATABASE'] = os.path.expanduser('~/ddos-enterprise-lab/ubuntu-server/web-dashboard/ddos_lab.db')
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
CONFIG_DIR = os.path.expanduser("~/ddos-enterprise-lab/ubuntu-server")
LOG_DIR = f"{CONFIG_DIR}/logs"
MONITOR_DIR = f"{CONFIG_DIR}/monitoring"
FORENSIC_DIR = f"{CONFIG_DIR}/forensic"
DASHBOARD_DIR = os.path.expanduser("~/ddos-enterprise-lab/ubuntu-server/web-dashboard")

# Store real-time data
system_metrics = {
    'connections': deque(maxlen=100),
    'cpu_load': deque(maxlen=100),
    'memory_usage': deque(maxlen=100),
    'network_rx': deque(maxlen=100),
    'network_tx': deque(maxlen=100),
    'attack_status': deque(maxlen=100),
    'firewall_stats': deque(maxlen=100)
}

# Store incidents
incidents = []

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token.split()[1], app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Database initialization
def init_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create incidents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            description TEXT,
            evidence_path TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP,
            resolved_by TEXT
        )
    ''')
    
    # Create metrics history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            connections INTEGER,
            syn_connections INTEGER,
            cpu_load REAL,
            memory_usage REAL,
            network_rx INTEGER,
            network_tx INTEGER,
            attack_detected BOOLEAN
        )
    ''')
    
    # Create firewall rules table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            port TEXT,
            protocol TEXT,
            action TEXT NOT NULL,
            enabled BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create default admin user if not exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
    if cursor.fetchone()[0] == 0:
        hashed_password = hashlib.sha256('admin123'.encode()).hexdigest()
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('admin', hashed_password, 'admin')
        )
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

# System monitoring functions
def get_system_metrics():
    """Get comprehensive system metrics"""
    metrics = {}
    
    # Connection statistics
    try:
        result = subprocess.run(['netstat', '-ant'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        total_conn = len(lines) - 2 if len(lines) > 2 else 0
        
        syn_conn = 0
        established_conn = 0
        for line in lines:
            if 'SYN_RECV' in line:
                syn_conn += 1
            elif 'ESTABLISHED' in line:
                established_conn += 1
        
        metrics['connections'] = {
            'total': total_conn,
            'syn': syn_conn,
            'established': established_conn,
            'syn_percentage': (syn_conn / total_conn * 100) if total_conn > 0 else 0
        }
    except:
        metrics['connections'] = {'total': 0, 'syn': 0, 'established': 0, 'syn_percentage': 0}
    
    # System load and memory
    metrics['cpu'] = {
        'load': psutil.getloadavg()[0],
        'cores': psutil.cpu_count(),
        'percent': psutil.cpu_percent(interval=0.1)
    }
    
    memory = psutil.virtual_memory()
    metrics['memory'] = {
        'total': memory.total,
        'used': memory.used,
        'free': memory.free,
        'percent': memory.percent,
        'available': memory.available
    }
    
    # Disk usage
    disk = psutil.disk_usage('/')
    metrics['disk'] = {
        'total': disk.total,
        'used': disk.used,
        'free': disk.free,
        'percent': disk.percent
    }
    
    # Network statistics
    net_io = psutil.net_io_counters()
    metrics['network'] = {
        'bytes_sent': net_io.bytes_sent,
        'bytes_recv': net_io.bytes_recv,
        'packets_sent': net_io.packets_sent,
        'packets_recv': net_io.packets_recv,
        'errin': net_io.errin,
        'errout': net_io.errout
    }
    
    # Process information
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            processes.append(proc.info)
        except:
            pass
    
    # Top 10 processes by CPU
    top_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:10]
    # Top 10 processes by memory
    top_memory = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:10]
    
    metrics['processes'] = {
        'total': len(processes),
        'top_cpu': top_cpu,
        'top_memory': top_memory
    }
    
    # Get firewall status
    metrics['firewall'] = get_firewall_status()
    
    # Get attack detection status
    metrics['attack_detection'] = detect_attacks(metrics)
    
    # Get service status
    metrics['services'] = get_service_status()
    
    # Get recent logs
    metrics['recent_logs'] = get_recent_logs()
    
    # Add timestamp
    metrics['timestamp'] = datetime.now().isoformat()
    
    # Store in history
    store_metrics_history(metrics)
    
    # Update real-time data
    system_metrics['connections'].append(metrics['connections']['total'])
    system_metrics['cpu_load'].append(metrics['cpu']['load'])
    system_metrics['memory_usage'].append(metrics['memory']['percent'])
    system_metrics['network_rx'].append(metrics['network']['bytes_recv'])
    system_metrics['network_tx'].append(metrics['network']['bytes_sent'])
    system_metrics['attack_status'].append(1 if metrics['attack_detection']['detected'] else 0)
    
    return metrics

def get_firewall_status():
    """Get current firewall rules and statistics"""
    firewall = {'rules': [], 'stats': {}, 'policy': {}}
    
    try:
        # Get iptables rules
        result = subprocess.run(['sudo', 'iptables', '-L', '-n', '-v', '--line-numbers'], 
                              capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')
        
        chain = None
        for line in lines:
            if line.startswith('Chain'):
                chain = line.split()[1]
                firewall['policy'][chain] = line.split()[3].strip(')')
            elif 'pkts' in line and 'bytes' in line and not line.startswith('Chain'):
                parts = line.split()
                if len(parts) >= 10:
                    rule = {
                        'chain': chain,
                        'pkts': parts[0],
                        'bytes': parts[1],
                        'target': parts[2],
                        'protocol': parts[3],
                        'source': parts[7],
                        'destination': parts[8],
                        'options': ' '.join(parts[9:])
                    }
                    firewall['rules'].append(rule)
        
        # Get packet statistics
        firewall['stats'] = {
            'input_packets': 0,
            'output_packets': 0,
            'forward_packets': 0,
            'dropped_packets': 0
        }
        
    except Exception as e:
        firewall['error'] = str(e)
    
    return firewall

def detect_attacks(metrics):
    """Detect potential DDoS attacks based on metrics"""
    detection = {
        'detected': False,
        'type': None,
        'confidence': 0,
        'indicators': []
    }
    
    # SYN flood detection
    syn_percentage = metrics['connections']['syn_percentage']
    if syn_percentage > 70:
        detection['detected'] = True
        detection['type'] = 'SYN Flood'
        detection['confidence'] = min(100, syn_percentage)
        detection['indicators'].append(f'High SYN connections: {syn_percentage:.1f}%')
    
    # High network traffic detection
    net_rx = metrics['network']['bytes_recv']
    net_tx = metrics['network']['bytes_sent']
    
    # Check for unusually high traffic (simplified threshold)
    if net_rx > 100000000:  # 100 MB threshold
        detection['detected'] = True
        detection['type'] = 'Traffic Flood'
        detection['confidence'] = min(100, net_rx / 100000000 * 100)
        detection['indicators'].append(f'High incoming traffic: {net_rx:,} bytes')
    
    # High CPU usage detection
    if metrics['cpu']['percent'] > 90:
        detection['detected'] = True
        if not detection['type']:
            detection['type'] = 'Resource Exhaustion'
        detection['confidence'] = max(detection['confidence'], metrics['cpu']['percent'])
        detection['indicators'].append(f'High CPU usage: {metrics["cpu"]["percent"]:.1f}%')
    
    # High memory usage detection
    if metrics['memory']['percent'] > 90:
        detection['detected'] = True
        if not detection['type']:
            detection['type'] = 'Resource Exhaustion'
        detection['confidence'] = max(detection['confidence'], metrics['memory']['percent'])
        detection['indicators'].append(f'High memory usage: {metrics["memory"]["percent"]:.1f}%')
    
    return detection

def get_service_status():
    """Get status of critical services"""
    services = {}
    
    service_list = [
        'apache2',
        'ssh',
        'iptables',
        'systemd-logind',
        'cron'
    ]
    
    for service in service_list:
        try:
            result = subprocess.run(['systemctl', 'is-active', service], 
                                  capture_output=True, text=True)
            status = result.stdout.strip()
            services[service] = {
                'status': status,
                'active': status == 'active'
            }
        except:
            services[service] = {'status': 'unknown', 'active': False}
    
    return services

def get_recent_logs():
    """Get recent system logs"""
    logs = []
    
    log_files = [
        '/var/log/syslog',
        '/var/log/kern.log',
        f'{LOG_DIR}/defense_controller.log'
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()[-10:]  # Last 10 lines
                    logs.extend([{'file': log_file, 'line': line.strip()} for line in lines])
            except:
                pass
    
    return logs[-20:]  # Return last 20 log entries total

def store_metrics_history(metrics):
    """Store metrics in database for historical analysis"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO metrics_history 
        (connections, syn_connections, cpu_load, memory_usage, network_rx, network_tx, attack_detected)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        metrics['connections']['total'],
        metrics['connections']['syn'],
        metrics['cpu']['load'],
        metrics['memory']['percent'],
        metrics['network']['bytes_recv'],
        metrics['network']['bytes_sent'],
        metrics['attack_detection']['detected']
    ))
    
    conn.commit()
    conn.close()

def execute_defense_command(level):
    """Execute defense level command"""
    try:
        script_path = f"{CONFIG_DIR}/ddos_defense_controller.sh"
        if os.path.exists(script_path):
            result = subprocess.run(['sudo', script_path, 'level', str(level)], 
                                  capture_output=True, text=True)
            return {'success': True, 'output': result.stdout, 'error': result.stderr}
        else:
            return {'success': False, 'error': 'Defense controller not found'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def collect_forensic_evidence(incident_id, description):
    """Collect forensic evidence for an incident"""
    try:
        evidence_dir = f"{FORENSIC_DIR}/incident_{incident_id}"
        os.makedirs(evidence_dir, exist_ok=True)
        
        # Collect system state
        commands = [
            (['uname', '-a'], 'system_info.txt'),
            (['ip', 'addr', 'show'], 'network_info.txt'),
            (['netstat', '-ant'], 'connections.txt'),
            (['ps', 'aux'], 'processes.txt'),
            (['sudo', 'iptables', '-L', '-n', '-v'], 'firewall_rules.txt'),
            (['dmesg', '|', 'tail', '-100'], 'dmesg.log')
        ]
        
        for cmd, filename in commands:
            try:
                result = subprocess.run(cmd[0] if len(cmd) > 1 else cmd, 
                                      capture_output=True, text=True)
                with open(f"{evidence_dir}/{filename}", 'w') as f:
                    f.write(result.stdout)
            except:
                pass
        
        # Create incident record
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO incidents (incident_id, title, severity, status, description, evidence_path)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (incident_id, f'Incident {incident_id}', 'high', 'open', description, evidence_dir))
        
        conn.commit()
        conn.close()
        
        return {'success': True, 'evidence_dir': evidence_dir}
        
    except Exception as e:
        return {'success': False, 'error': str(e)}

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('connected', {'data': 'Connected to DDoS Dashboard'})

@socketio.on('request_metrics')
def handle_metrics_request():
    metrics = get_system_metrics()
    emit('metrics_update', metrics)

# Background thread for real-time updates
def background_metrics_thread():
    """Background thread to send periodic metric updates"""
    while True:
        metrics = get_system_metrics()
        socketio.emit('real_time_metrics', metrics)
        time.sleep(2)  # Update every 2 seconds

# Start background thread
threading.Thread(target=background_metrics_thread, daemon=True).start()

# API Routes
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        hashed_input = hashlib.sha256(password.encode()).hexdigest()
        if hashed_input == user[0]:
            token = jwt.encode({
                'username': username,
                'role': user[1],
                'exp': datetime.utcnow().timestamp() + 3600
            }, app.config['SECRET_KEY'])
            return jsonify({'token': token, 'role': user[1]})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/metrics')
@token_required
def api_metrics(current_user):
    metrics = get_system_metrics()
    return jsonify(metrics)

@app.route('/api/metrics/history')
@token_required
def api_metrics_history(current_user):
    conn = get_db()
    cursor = conn.cursor()
    
    limit = request.args.get('limit', 100)
    cursor.execute('''
        SELECT * FROM metrics_history 
        ORDER BY timestamp DESC 
        LIMIT ?
    ''', (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append(dict(row))
    
    return jsonify(history)

@app.route('/api/defense/set_level/<int:level>', methods=['POST'])
@token_required
def api_set_defense_level(current_user, level):
    result = execute_defense_command(level)
    return jsonify(result)

@app.route('/api/incidents', methods=['GET', 'POST'])
@token_required
def api_incidents(current_user):
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        data = request.json
        incident_id = f"INC_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        cursor.execute('''
            INSERT INTO incidents (incident_id, title, severity, status, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            incident_id,
            data.get('title', 'New Incident'),
            data.get('severity', 'medium'),
            'open',
            data.get('description', '')
        ))
        
        conn.commit()
        conn.close()
        
        # Trigger evidence collection
        collect_forensic_evidence(incident_id, data.get('description', ''))
        
        return jsonify({'success': True, 'incident_id': incident_id})
    
    else:
        cursor.execute('SELECT * FROM incidents ORDER BY created_at DESC')
        rows = cursor.fetchall()
        conn.close()
        
        incidents = []
        for row in rows:
            incidents.append(dict(row))
        
        return jsonify(incidents)

@app.route('/api/incidents/<incident_id>/resolve', methods=['POST'])
@token_required
def api_resolve_incident(current_user, incident_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE incidents 
        SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
        WHERE incident_id = ?
    ''', (current_user, incident_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

@app.route('/api/firewall/rules', methods=['GET', 'POST', 'DELETE'])
@token_required
def api_firewall_rules(current_user):
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'GET':
        cursor.execute('SELECT * FROM firewall_rules ORDER BY created_at DESC')
        rows = cursor.fetchall()
        rules = [dict(row) for row in rows]
        conn.close()
        return jsonify(rules)
    
    elif request.method == 'POST':
        data = request.json
        
        cursor.execute('''
            INSERT INTO firewall_rules (rule_name, rule_type, source_ip, destination_ip, port, protocol, action)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data.get('rule_name'),
            data.get('rule_type'),
            data.get('source_ip'),
            data.get('destination_ip'),
            data.get('port'),
            data.get('protocol'),
            data.get('action')
        ))
        
        conn.commit()
        rule_id = cursor.lastrowid
        conn.close()
        
        # Apply rule to iptables (simplified - in production would have proper iptables command generation)
        return jsonify({'success': True, 'rule_id': rule_id})
    
    elif request.method == 'DELETE':
        rule_id = request.args.get('rule_id')
        if rule_id:
            cursor.execute('DELETE FROM firewall_rules WHERE id = ?', (rule_id,))
            conn.commit()
        
        conn.close()
        return jsonify({'success': True})

@app.route('/api/system/command', methods=['POST'])
@token_required
def api_system_command(current_user):
    if current_user != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.json
    command = data.get('command')
    
    try:
        result = subprocess.run(command.split(), capture_output=True, text=True, timeout=30)
        return jsonify({
            'success': True,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/logs')
@token_required
def api_logs(current_user):
    log_type = request.args.get('type', 'system')
    lines = int(request.args.get('lines', 50))
    
    log_files = {
        'system': '/var/log/syslog',
        'kernel': '/var/log/kern.log',
        'auth': '/var/log/auth.log',
        'defense': f'{LOG_DIR}/defense_controller.log',
        'dashboard': f'{DASHBOARD_DIR}/logs/dashboard.log'
    }
    
    log_file = log_files.get(log_type, '/var/log/syslog')
    
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                log_lines = f.readlines()[-lines:]
                return jsonify({'lines': log_lines})
        except:
            return jsonify({'error': 'Could not read log file'}), 500
    
    return jsonify({'error': 'Log file not found'}), 404

@app.route('/api/backup', methods=['POST'])
@token_required
def api_backup(current_user):
    backup_type = request.json.get('type', 'full')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    backup_files = [
        f'{CONFIG_DIR}/ddos_defense_controller.sh',
        '/etc/iptables/rules.v4',
        '/etc/sysctl.d/99-ddos-protection.conf'
    ]
    
    backup_dir = f"{CONFIG_DIR}/backup/{timestamp}"
    os.makedirs(backup_dir, exist_ok=True)
    
    for file in backup_files:
        if os.path.exists(file):
            try:
                subprocess.run(['cp', file, backup_dir])
            except:
                pass
    
    return jsonify({'success': True, 'backup_dir': backup_dir})

# Web Interface Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/firewall')
def firewall():
    return render_template('firewall.html')

@app.route('/incidents')
def incidents():
    return render_template('incidents.html')

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

if __name__ == '__main__':
    # Create required directories
    os.makedirs(f"{DASHBOARD_DIR}/logs", exist_ok=True)
    
    print("Starting Enterprise DDoS Web Dashboard v4.0...")
    print(f"Dashboard URL: http://0.0.0.0:5000")
    print(f"API Base URL: http://0.0.0.0:5000/api")
    print("Press Ctrl+C to stop")
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)
