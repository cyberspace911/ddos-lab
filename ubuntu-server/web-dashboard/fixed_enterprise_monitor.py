#!/usr/bin/python3
"""
ENTERPRISE DDoS MONITOR - FIXED VERSION
"""
from flask import Flask, jsonify, request
from flask_socketio import SocketIO
import psutil
import time
import os
import sqlite3
from datetime import datetime
import threading
import socket

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database
def init_db():
    conn = sqlite3.connect('monitor.db', check_same_thread=False)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        cpu REAL,
        memory REAL,
        connections INTEGER,
        network_rx INTEGER,
        network_tx INTEGER,
        disk REAL,
        load REAL,
        attack INTEGER,
        attack_type TEXT
    )''')
    conn.commit()
    conn.close()

init_db()

# Store last values for rate calculation
last_network = {'rx': 0, 'tx': 0, 'time': time.time()}

def get_all_metrics():
    """Get all system metrics"""
    timestamp = datetime.now()
    
    # CPU
    cpu_percent = psutil.cpu_percent(interval=0.1)
    cpu_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
    
    # Memory
    memory = psutil.virtual_memory()
    
    # Disk
    disk = psutil.disk_usage('/')
    
    # Network
    net_io = psutil.net_io_counters()
    net_connections = psutil.net_connections()
    
    # Load average
    try:
        load_avg = os.getloadavg()
    except:
        load_avg = (0.0, 0.0, 0.0)
    
    # Calculate network rates
    now = time.time()
    time_diff = now - last_network['time']
    
    rx_rate = (net_io.bytes_recv - last_network['rx']) / time_diff if time_diff > 0 else 0
    tx_rate = (net_io.bytes_sent - last_network['tx']) / time_diff if time_diff > 0 else 0
    
    # Update last values
    last_network.update({'rx': net_io.bytes_recv, 'tx': net_io.bytes_sent, 'time': now})
    
    # Analyze connections for DDoS
    ddos_info = analyze_ddos(net_connections)
    
    # Store in database
    store_metrics(cpu_percent, memory.percent, len(net_connections),
                  net_io.bytes_recv, net_io.bytes_sent, disk.percent,
                  load_avg[0], ddos_info)
    
    return {
        'timestamp': timestamp.isoformat(),
        'cpu': {
            'percent': cpu_percent,
            'cores': len(cpu_per_core),
            'per_core': cpu_per_core
        },
        'memory': {
            'percent': memory.percent,
            'used_gb': memory.used / (1024**3),
            'total_gb': memory.total / (1024**3)
        },
        'disk': {
            'percent': disk.percent,
            'used_gb': disk.used / (1024**3),
            'total_gb': disk.total / (1024**3)
        },
        'network': {
            'connections': len(net_connections),
            'rx_rate_mb': rx_rate / (1024**2),
            'tx_rate_mb': tx_rate / (1024**2),
            'rx_total_gb': net_io.bytes_recv / (1024**3),
            'tx_total_gb': net_io.bytes_sent / (1024**3)
        },
        'system': {
            'load_1m': load_avg[0],
            'load_5m': load_avg[1],
            'load_15m': load_avg[2]
        },
        'ddos': ddos_info,
        'alerts': generate_alerts(cpu_percent, memory.percent, len(net_connections), ddos_info)
    }

def analyze_ddos(connections):
    """Analyze connections for DDoS"""
    total = len(connections)
    if total == 0:
        return {'detected': False, 'type': 'none', 'confidence': 0}
    
    tcp_conns = [c for c in connections if c.type == 1]
    syn_count = 0
    ip_counts = {}
    
    for conn in tcp_conns:
        if hasattr(conn, 'status') and conn.status == 'SYN_RECV':
            syn_count += 1
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
            'severity': 'high' if syn_ratio > 0.5 else 'medium'
        }
    
    # Check for connection flood
    for ip, count in ip_counts.items():
        if count > 50:
            return {
                'detected': True,
                'type': 'CONNECTION_FLOOD',
                'confidence': min(100, count),
                'severity': 'high' if count > 100 else 'medium'
            }
    
    return {'detected': False, 'type': 'none', 'confidence': 0}

def generate_alerts(cpu, memory, connections, ddos):
    """Generate alerts"""
    alerts = []
    
    if cpu > 90:
        alerts.append({'level': 'CRITICAL', 'type': 'CPU', 'message': f'CPU critical: {cpu:.1f}%'})
    elif cpu > 80:
        alerts.append({'level': 'WARNING', 'type': 'CPU', 'message': f'CPU high: {cpu:.1f}%'})
    
    if memory > 90:
        alerts.append({'level': 'CRITICAL', 'type': 'MEMORY', 'message': f'Memory critical: {memory:.1f}%'})
    elif memory > 80:
        alerts.append({'level': 'WARNING', 'type': 'MEMORY', 'message': f'Memory high: {memory:.1f}%'})
    
    if connections > 5000:
        alerts.append({'level': 'CRITICAL', 'type': 'CONNECTIONS', 'message': f'Connections very high: {connections}'})
    elif connections > 1000:
        alerts.append({'level': 'WARNING', 'type': 'CONNECTIONS', 'message': f'Connections high: {connections}'})
    
    if ddos['detected']:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'DDoS',
            'message': f'DDoS detected: {ddos["type"]} ({ddos["confidence"]}%)'
        })
    
    return alerts

def store_metrics(cpu, memory, connections, rx, tx, disk, load, ddos):
    """Store metrics in database"""
    try:
        conn = sqlite3.connect('monitor.db', check_same_thread=False)
        c = conn.cursor()
        c.execute('''INSERT INTO metrics 
                    (cpu, memory, connections, network_rx, network_tx, disk, load, attack, attack_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (cpu, memory, connections, rx, tx, disk, load,
                  int(ddos['detected']), ddos['type']))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error storing metrics: {e}")

def get_historical_data(hours=24):
    """Get historical data"""
    try:
        conn = sqlite3.connect('monitor.db', check_same_thread=False)
        c = conn.cursor()
        c.execute('''SELECT 
                    strftime('%H:%M', timestamp) as time,
                    AVG(cpu) as cpu,
                    AVG(memory) as memory,
                    AVG(connections) as connections
                    FROM metrics 
                    WHERE timestamp >= datetime('now', ?)
                    GROUP BY strftime('%H:%M', timestamp)
                    ORDER BY timestamp''', (f'-{hours} hours',))
        
        rows = c.fetchall()
        conn.close()
        
        return [{'time': row[0], 'cpu': row[1], 'memory': row[2], 'connections': row[3]} for row in rows]
    except:
        return []

# HTML Template
HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>ENTERPRISE DDoS MONITOR</title>
    <meta charset="utf-8">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/socket.io-client@4.5.0/dist/socket.io.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; background: #0f172a; color: white; margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #60a5fa; font-size: 2.5rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: #1e293b; padding: 20px; border-radius: 10px; border: 1px solid #334155; }
        .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .card-title { font-size: 1.2rem; font-weight: bold; color: #94a3b8; }
        .badge { padding: 5px 10px; border-radius: 5px; font-size: 0.9rem; }
        .badge-success { background: #065f46; color: #6ee7b7; }
        .badge-warning { background: #92400e; color: #fbbf24; }
        .badge-danger { background: #7f1d1d; color: #fca5a5; }
        .metric { margin: 10px 0; }
        .metric-label { color: #94a3b8; font-size: 0.9rem; }
        .metric-value { font-size: 2rem; font-weight: bold; margin: 5px 0; }
        .progress { height: 10px; background: #334155; border-radius: 5px; margin: 10px 0; overflow: hidden; }
        .progress-bar { height: 100%; }
        .progress-cpu { background: #3b82f6; }
        .progress-memory { background: #10b981; }
        .progress-disk { background: #f59e0b; }
        .chart-container { height: 200px; margin-top: 20px; }
        .alert { padding: 15px; border-radius: 8px; margin: 10px 0; border-left: 4px solid; }
        .alert-critical { background: rgba(239, 68, 68, 0.1); border-left-color: #ef4444; }
        .alert-warning { background: rgba(245, 158, 11, 0.1); border-left-color: #f59e0b; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #1e293b; border: 1px solid #334155; color: #94a3b8; cursor: pointer; border-radius: 5px; }
        .tab.active { background: #3b82f6; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ENTERPRISE DDoS MONITOR</h1>
            <p>Real-time system monitoring with DDoS detection</p>
            <div style="display: flex; gap: 10px; justify-content: center; margin-top: 10px;">
                <div class="badge badge-success" id="status">Live</div>
                <div class="badge" id="threat-level">Low Threat</div>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('overview')">Overview</button>
            <button class="tab" onclick="switchTab('network')">Network</button>
            <button class="tab" onclick="switchTab('history')">History</button>
        </div>
        
        <div id="overview" class="tab-content active">
            <div id="alerts-container"></div>
            
            <div class="grid">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">💻 CPU</div>
                        <div class="badge" id="cpu-badge">Normal</div>
                    </div>
                    <div class="metric-value" id="cpu-value">0%</div>
                    <div class="progress">
                        <div class="progress-bar progress-cpu" id="cpu-bar" style="width: 0%"></div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🧠 Memory</div>
                        <div class="badge" id="memory-badge">Normal</div>
                    </div>
                    <div class="metric-value" id="memory-value">0%</div>
                    <div class="progress">
                        <div class="progress-bar progress-memory" id="memory-bar" style="width: 0%"></div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🌐 Network</div>
                        <div class="badge" id="network-badge">Normal</div>
                    </div>
                    <div class="metric-value" id="network-value">0 MB/s</div>
                    <div class="metric-label">Connections: <span id="connections-value">0</span></div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">🛡️ DDoS Status</div>
                        <div class="badge" id="ddos-badge">Safe</div>
                    </div>
                    <div id="ddos-info">No attacks detected</div>
                </div>
            </div>
            
            <div class="grid">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">📈 System Load</div>
                    </div>
                    <div class="chart-container">
                        <canvas id="load-chart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">📊 Connections</div>
                    </div>
                    <div class="chart-container">
                        <canvas id="connections-chart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="network" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">🌐 Network Analysis</div>
                </div>
                <div id="network-analysis">Loading...</div>
            </div>
        </div>
        
        <div id="history" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <div class="card-title">📅 Historical Data (24h)</div>
                </div>
                <div class="chart-container">
                    <canvas id="historical-chart"></canvas>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        let socket = null;
        let charts = {};
        
        function initWebSocket() {
            socket = io();
            
            socket.on('connect', () => {
                console.log('Connected');
                document.getElementById('status').textContent = 'Live';
                document.getElementById('status').className = 'badge badge-success';
            });
            
            socket.on('metrics', (data) => {
                updateDashboard(data);
            });
            
            socket.on('disconnect', () => {
                document.getElementById('status').textContent = 'Offline';
                document.getElementById('status').className = 'badge badge-danger';
            });
        }
        
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
                            label: 'Connections',
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
                            min: 0,
                            max: 100,
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#94a3b8' }
                        }
                    }
                }
            });
        }
        
        function updateDashboard(data) {
            // Update CPU
            document.getElementById('cpu-value').textContent = data.cpu.percent.toFixed(1) + '%';
            document.getElementById('cpu-bar').style.width = data.cpu.percent + '%';
            updateBadge('cpu', data.cpu.percent);
            
            // Update Memory
            document.getElementById('memory-value').textContent = data.memory.percent.toFixed(1) + '%';
            document.getElementById('memory-bar').style.width = data.memory.percent + '%';
            updateBadge('memory', data.memory.percent);
            
            // Update Network
            const throughput = (data.network.rx_rate_mb + data.network.tx_rate_mb).toFixed(1);
            document.getElementById('network-value').textContent = throughput + ' MB/s';
            document.getElementById('connections-value').textContent = data.network.connections;
            updateBadge('network', throughput * 10);
            
            // Update DDoS status
            updateDDoSStatus(data.ddos);
            
            // Update alerts
            updateAlerts(data.alerts);
            
            // Update charts
            const time = new Date(data.timestamp).toLocaleTimeString();
            
            if (charts.load) {
                charts.load.data.labels.push(time);
                charts.load.data.datasets[0].data.push(data.cpu.percent);
                
                if (charts.load.data.labels.length > 20) {
                    charts.load.data.labels.shift();
                    charts.load.data.datasets[0].data.shift();
                }
                
                charts.load.update('none');
            }
            
            if (charts.connections) {
                charts.connections.data.labels.push(time);
                charts.connections.data.datasets[0].data.push(data.network.connections);
                
                if (charts.connections.data.labels.length > 20) {
                    charts.connections.data.labels.shift();
                    charts.connections.data.datasets[0].data.shift();
                }
                
                charts.connections.update('none');
            }
        }
        
        function updateBadge(type, value) {
            const badge = document.getElementById(`${type}-badge`);
            let level = 'Normal';
            let badgeClass = 'badge-success';
            
            if (type === 'cpu' || type === 'memory') {
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
                }
            }
            
            badge.textContent = level;
            badge.className = 'badge ' + badgeClass;
        }
        
        function updateDDoSStatus(ddos) {
            const badge = document.getElementById('ddos-badge');
            const info = document.getElementById('ddos-info');
            
            if (ddos.detected) {
                badge.textContent = 'ATTACK!';
                badge.className = 'badge badge-danger';
                info.innerHTML = `
                    <div style="color: #fca5a5;">
                        <strong>${ddos.type} detected!</strong><br>
                        Confidence: ${ddos.confidence}%<br>
                        Severity: ${ddos.severity}
                    </div>
                `;
                document.getElementById('threat-level').textContent = 'HIGH THREAT';
                document.getElementById('threat-level').className = 'badge badge-danger';
            } else {
                badge.textContent = 'Safe';
                badge.className = 'badge badge-success';
                info.textContent = 'No attacks detected';
                document.getElementById('threat-level').textContent = 'Low Threat';
                document.getElementById('threat-level').className = 'badge badge-success';
            }
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            
            if (alerts.length === 0) {
                container.innerHTML = '<div style="text-align: center; color: #94a3b8; padding: 20px;">No alerts</div>';
                return;
            }
            
            container.innerHTML = '';
            alerts.forEach(alert => {
                const alertDiv = document.createElement('div');
                const alertClass = alert.level === 'CRITICAL' ? 'alert-critical' : 'alert-warning';
                alertDiv.className = `alert ${alertClass}`;
                alertDiv.innerHTML = `<strong>${alert.type}:</strong> ${alert.message}`;
                container.appendChild(alertDiv);
            });
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
            
            // Load historical data if needed
            if (tabName === 'history') {
                loadHistoricalData();
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
                    charts.historical.update();
                }
            } catch (error) {
                console.error('Error loading historical data:', error);
            }
        }
        
        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            initWebSocket();
            
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
    return HTML

@app.route('/api/metrics')
def api_metrics():
    metrics = get_all_metrics()
    return jsonify(metrics)

@app.route('/api/historical/<int:hours>')
def api_historical(hours):
    data = get_historical_data(min(hours, 24))
    return jsonify(data)

@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    socketio.emit('connected', {'message': 'Connected'})

@socketio.on('request_metrics')
def handle_request_metrics():
    metrics = get_all_metrics()
    socketio.emit('metrics', metrics)

def background_monitoring():
    while True:
        socketio.sleep(3)
        metrics = get_all_metrics()
        socketio.emit('metrics', metrics)

# Start background thread
threading.Thread(target=background_monitoring, daemon=True).start()

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 ENTERPRISE DDoS MONITOR - FIXED")
    print("="*60)
    print("📊 URL: http://0.0.0.0:5001")
    print("⚡ Real-time updates every 3 seconds")
    print("💾 Historical data storage")
    print("🛡️ DDoS attack detection")
    print("="*60 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)
