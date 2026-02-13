#!/usr/bin/python3
"""
Fixed DDoS Dashboard - Working API Endpoints
"""
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import sqlite3
import json
import os
import psutil
import time
from datetime import datetime
import threading

app = Flask(__name__)
app.secret_key = 'ddos_lab_secret_key_2024'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database setup
def init_db():
    conn = sqlite3.connect('ddos_lab.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'admin'
        )
    ''')
    
    # Incidents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            severity TEXT,
            description TEXT,
            status TEXT DEFAULT 'open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Check if admin user exists
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Simple authentication check (non-blocking for public endpoints)
def check_auth():
    # Public endpoints that don't require auth
    public_endpoints = ['/api/login', '/api/public/metrics', '/', '/login']
    if request.path in public_endpoints:
        return True
    
    # Check session or token
    if session.get('authenticated'):
        return True
    
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        # Simple token check (in real app, validate properly)
        if token == 'demo_token' or token.startswith('admin'):
            return True
    
    return False

@app.before_request
def before_request():
    # Skip auth check for static files and certain endpoints
    if request.endpoint in ['static', 'index', 'login_page']:
        return
    
    if not check_auth() and request.path.startswith('/api/'):
        return jsonify({'error': 'Unauthorized'}), 401

# ========== PUBLIC ROUTES ==========
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

# ========== API ROUTES ==========
@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        conn = sqlite3.connect('ddos_lab.db', check_same_thread=False)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['authenticated'] = True
            session['username'] = username
            session['role'] = user[3]
            
            return jsonify({
                'success': True,
                'token': f'{username}_token_{int(time.time())}',
                'user': {
                    'username': username,
                    'role': user[3]
                }
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/metrics')
def api_metrics():
    """Public metrics endpoint - no auth required"""
    try:
        # CPU
        cpu_percent = psutil.cpu_percent(interval=0.1)
        cpu_load = os.getloadavg()[0] if hasattr(os, 'getloadavg') else cpu_percent/100
        
        # Memory
        memory = psutil.virtual_memory()
        
        # Network
        net_io = psutil.net_io_counters()
        
        # Connections (simulated)
        import random
        connections = {
            'total': random.randint(10, 1000),
            'syn': random.randint(0, 100),
            'established': random.randint(5, 800),
            'time_wait': random.randint(1, 50)
        }
        
        # Services status (simulated)
        services = {
            'firewall': {'active': True, 'status': 'Running'},
            'ids': {'active': True, 'status': 'Monitoring'},
            'web_server': {'active': True, 'status': 'Online'},
            'database': {'active': True, 'status': 'Connected'}
        }
        
        # Attack detection (simulated)
        attack_detection = {
            'detected': random.random() > 0.7,  # 30% chance of "attack"
            'type': random.choice(['SYN Flood', 'HTTP Flood', 'UDP Amplification', 'Slowloris']),
            'confidence': random.uniform(70, 99),
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'timestamp': datetime.now().isoformat(),
            'cpu': {
                'percent': cpu_percent,
                'load': cpu_load,
                'cores': psutil.cpu_count()
            },
            'memory': {
                'percent': memory.percent,
                'used': memory.used,
                'total': memory.total,
                'available': memory.available
            },
            'network': {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            },
            'connections': connections,
            'attack_detection': attack_detection,
            'services': services
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs')
def api_logs():
    """Get system logs"""
    try:
        log_type = request.args.get('type', 'system')
        lines = int(request.args.get('lines', 10))
        
        # Generate simulated logs
        logs = []
        log_messages = [
            'INFO: System started successfully',
            'INFO: Firewall rules loaded',
            'INFO: Monitoring service active',
            'WARNING: High connection count detected',
            'INFO: Network traffic normal',
            'ERROR: Failed to connect to database',
            'INFO: Backup completed successfully',
            'WARNING: CPU usage above 80%',
            'INFO: Security scan completed',
            'ALERT: Possible DDoS attack detected'
        ]
        
        for i in range(lines):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            message = f"{timestamp} - {log_messages[i % len(log_messages)]}"
            logs.append(message)
        
        return jsonify({
            'success': True,
            'type': log_type,
            'lines': logs
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/defense/set_level/<int:level>', methods=['POST'])
def set_defense_level(level):
    """Set defense level"""
    try:
        levels = ['No Defense', 'Medium Defense', 'Enterprise Defense']
        if level < 0 or level >= len(levels):
            return jsonify({'error': 'Invalid level'}), 400
            
        return jsonify({
            'success': True,
            'message': f'Defense level set to: {levels[level]}',
            'level': level,
            'level_name': levels[level]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/incidents', methods=['GET', 'POST'])
def api_incidents():
    """Manage incidents"""
    conn = sqlite3.connect('ddos_lab.db', check_same_thread=False)
    cursor = conn.cursor()
    
    if request.method == 'POST':
        try:
            data = request.json
            cursor.execute('''
                INSERT INTO incidents (title, severity, description, status)
                VALUES (?, ?, ?, ?)
            ''', (data['title'], data.get('severity', 'medium'), 
                  data.get('description', ''), data.get('status', 'open')))
            conn.commit()
            incident_id = cursor.lastrowid
            
            return jsonify({
                'success': True,
                'incident_id': incident_id,
                'message': 'Incident created successfully'
            })
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500
            
    else:  # GET request
        cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT 20")
        incidents = cursor.fetchall()
        
        result = []
        for inc in incidents:
            result.append({
                'id': inc[0],
                'title': inc[1],
                'severity': inc[2],
                'description': inc[3],
                'status': inc[4],
                'created_at': inc[5]
            })
        
        return jsonify({
            'success': True,
            'incidents': result
        })
    
    conn.close()

# ========== PROTECTED ROUTES ==========
@app.route('/dashboard')
def dashboard():
    if not session.get('authenticated'):
        return redirect(url_for('login_page'))
    return render_template('dashboard.html')

@app.route('/firewall')
def firewall():
    if not session.get('authenticated'):
        return redirect(url_for('login_page'))
    return render_template('firewall.html')

@app.route('/incidents')
def incidents_page():
    if not session.get('authenticated'):
        return redirect(url_for('login_page'))
    return render_template('incidents.html')

@app.route('/reports')
def reports():
    if not session.get('authenticated'):
        return redirect(url_for('login_page'))
    return render_template('reports.html')

@app.route('/settings')
def settings():
    if not session.get('authenticated'):
        return redirect(url_for('login_page'))
    return render_template('settings.html')

# ========== SOCKET.IO EVENTS ==========
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to DDoS Dashboard'})

def background_metrics():
    """Send metrics updates to all connected clients"""
    while True:
        try:
            socketio.sleep(2)  # Update every 2 seconds
            
            # Get metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            
            # Simulate some variations
            import random
            connections = random.randint(50, 1500)
            
            metrics = {
                'cpu': {
                    'percent': cpu_percent,
                    'load': cpu_percent / 100 + random.uniform(0, 0.3)
                },
                'memory': {
                    'percent': memory.percent,
                    'used': memory.used,
                    'total': memory.total
                },
                'connections': {
                    'total': connections,
                    'syn': int(connections * 0.1)
                },
                'timestamp': datetime.now().isoformat()
            }
            
            socketio.emit('metrics_update', metrics)
            
        except Exception as e:
            print(f"Error in background metrics: {e}")

# Start background thread
threading.Thread(target=background_metrics, daemon=True).start()

# ========== MAIN ==========
if __name__ == '__main__':
    print("\n" + "="*50)
    print("🚀 DDoS Dashboard v4.0 - FIXED VERSION")
    print("="*50)
    print("📊 Dashboard URL: http://0.0.0.0:5001")
    print("🔐 Login: admin / admin123")
    print("="*50 + "\n")
    
    # Ensure templates exist
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)
