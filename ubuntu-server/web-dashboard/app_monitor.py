#!/usr/bin/python3
"""
Single Page DDoS Monitor - Everything on One Page
"""
from flask import Flask, jsonify
import psutil
import time
import random
from datetime import datetime

app = Flask(__name__)

# Serve a single HTML page
@app.route('/')
def monitor():
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>DDoS Monitor</title>
    <meta http-equiv="refresh" content="2">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: monospace; 
            background: #0a0a0a; 
            color: #0f0; 
            padding: 10px;
            font-size: 14px;
        }
        .header {
            background: #111;
            padding: 15px;
            margin-bottom: 15px;
            border: 1px solid #333;
            text-align: center;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
        }
        .box {
            background: #111;
            padding: 15px;
            border: 1px solid #333;
        }
        .metric {
            display: flex;
            justify-content: space-between;
            margin: 5px 0;
            padding: 5px;
            background: #1a1a1a;
        }
        .alert {
            background: #330000;
            border: 1px solid #ff0000;
            padding: 10px;
            margin: 5px 0;
        }
        .log {
            background: #111;
            border: 1px solid #333;
            padding: 10px;
            height: 200px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 12px;
        }
        .timestamp {
            color: #666;
            font-size: 12px;
        }
        .conn-badge {
            display: inline-block;
            padding: 2px 8px;
            background: #003300;
            margin: 0 2px;
            border-radius: 3px;
        }
        .attack {
            animation: blink 1s infinite;
            background: #330000 !important;
        }
        @keyframes blink {
            50% { background: #660000; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ DDoS MONITOR v4.0</h1>
        <div class="timestamp" id="timestamp">Loading...</div>
    </div>

    <div class="grid">
        <div class="box">
            <h2>SYSTEM</h2>
            <div class="metric">
                <span>CPU:</span>
                <span id="cpu">--%</span>
            </div>
            <div class="metric">
                <span>Memory:</span>
                <span id="mem">--%</span>
            </div>
            <div class="metric">
                <span>Load:</span>
                <span id="load">--</span>
            </div>
            <div class="metric">
                <span>Uptime:</span>
                <span id="uptime">--</span>
            </div>
        </div>

        <div class="box">
            <h2>NETWORK</h2>
            <div class="metric">
                <span>Connections:</span>
                <span id="conns">--</span>
            </div>
            <div class="metric">
                <span>RX:</span>
                <span id="rx">-- B/s</span>
            </div>
            <div class="metric">
                <span>TX:</span>
                <span id="tx">-- B/s</span>
            </div>
            <div class="metric">
                <span>Packets/s:</span>
                <span id="pkts">--</span>
            </div>
        </div>

        <div class="box">
            <h2>DDoS STATUS</h2>
            <div class="metric">
                <span>Defense:</span>
                <span id="defense">ENTERPRISE</span>
            </div>
            <div class="metric">
                <span>Threat Level:</span>
                <span id="threat">LOW</span>
            </div>
            <div class="metric">
                <span>Attack:</span>
                <span id="attack">NONE</span>
            </div>
            <div class="metric">
                <span>Firewall:</span>
                <span id="fw">ACTIVE</span>
            </div>
        </div>
    </div>

    <div id="alert" class="alert" style="display: none;">
        <strong>⚠️ ATTACK DETECTED!</strong>
        <span id="attack-info"></span>
    </div>

    <div class="box">
        <h2>CONNECTION TYPES</h2>
        <div>
            <span class="conn-badge">ESTAB: <span id="estab">0</span></span>
            <span class="conn-badge">SYN: <span id="syn">0</span></span>
            <span class="conn-badge">TIME_WAIT: <span id="timewait">0</span></span>
            <span class="conn-badge">UDP: <span id="udp">0</span></span>
        </div>
    </div>

    <div class="box">
        <h2>SERVICES</h2>
        <div class="grid" style="grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));">
            <div class="metric">
                <span>Firewall:</span>
                <span id="svc-fw" style="color: #0f0;">✓</span>
            </div>
            <div class="metric">
                <span>IDS:</span>
                <span id="svc-ids" style="color: #0f0;">✓</span>
            </div>
            <div class="metric">
                <span>Web:</span>
                <span id="svc-web" style="color: #0f0;">✓</span>
            </div>
            <div class="metric">
                <span>Monitor:</span>
                <span id="svc-mon" style="color: #0f0;">✓</span>
            </div>
        </div>
    </div>

    <div class="box">
        <h2>LIVE LOGS</h2>
        <div class="log" id="log">
            <!-- Logs will appear here -->
        </div>
    </div>

    <script>
        let lastNetwork = { rx: 0, tx: 0, time: Date.now() };
        let logs = [];
        
        function formatBytes(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / 1048576).toFixed(1) + ' MB';
        }
        
        function updateMetrics() {
            fetch('/api')
                .then(r => r.json())
                .then(data => {
                    // Update timestamp
                    document.getElementById('timestamp').textContent = 
                        new Date().toLocaleTimeString() + ' | Auto-refresh every 2s';
                    
                    // System metrics
                    document.getElementById('cpu').textContent = data.cpu + '%';
                    document.getElementById('mem').textContent = data.memory + '%';
                    document.getElementById('load').textContent = data.load;
                    document.getElementById('uptime').textContent = data.uptime;
                    
                    // Network metrics
                    document.getElementById('conns').textContent = data.connections.total;
                    document.getElementById('estab').textContent = data.connections.established;
                    document.getElementById('syn').textContent = data.connections.syn;
                    document.getElementById('timewait').textContent = data.connections.time_wait;
                    document.getElementById('udp').textContent = data.connections.udp;
                    
                    // Calculate network rates
                    const now = Date.now();
                    const timeDiff = (now - lastNetwork.time) / 1000;
                    const rxRate = (data.network.rx - lastNetwork.rx) / timeDiff;
                    const txRate = (data.network.tx - lastNetwork.tx) / timeDiff;
                    const pktRate = (data.network.packets - lastNetwork.packets) / timeDiff;
                    
                    document.getElementById('rx').textContent = formatBytes(rxRate) + '/s';
                    document.getElementById('tx').textContent = formatBytes(txRate) + '/s';
                    document.getElementById('pkts').textContent = Math.round(pktRate) + '/s';
                    
                    lastNetwork = {
                        rx: data.network.rx,
                        tx: data.network.tx,
                        packets: data.network.packets,
                        time: now
                    };
                    
                    // DDoS status
                    document.getElementById('defense').textContent = data.defense.toUpperCase();
                    document.getElementById('threat').textContent = data.threat.toUpperCase();
                    document.getElementById('fw').textContent = data.firewall ? 'ACTIVE' : 'INACTIVE';
                    
                    // Attack detection
                    if (data.attack.detected) {
                        document.getElementById('attack').textContent = data.attack.type;
                        document.getElementById('attack-info').textContent = 
                            data.attack.type + ' | Confidence: ' + data.attack.confidence + '%';
                        document.getElementById('alert').style.display = 'block';
                        document.getElementById('threat').style.color = '#ff0000';
                        document.getElementById('attack').style.color = '#ff0000';
                    } else {
                        document.getElementById('attack').textContent = 'NONE';
                        document.getElementById('alert').style.display = 'none';
                        document.getElementById('threat').style.color = '#0f0';
                        document.getElementById('attack').style.color = '#0f0';
                    }
                    
                    // Add log entry
                    const logTime = new Date().toLocaleTimeString();
                    let logMsg = `[${logTime}] `;
                    
                    if (data.attack.detected) {
                        logMsg += `ATTACK: ${data.attack.type} (${data.attack.confidence}%)`;
                    } else {
                        logMsg += `System normal | CPU: ${data.cpu}% | Conn: ${data.connections.total}`;
                    }
                    
                    logs.unshift(logMsg);
                    if (logs.length > 15) logs.pop();
                    
                    // Update log display
                    const logDiv = document.getElementById('log');
                    logDiv.innerHTML = logs.join('<br>');
                    
                    // Auto-scroll logs
                    logDiv.scrollTop = 0;
                })
                .catch(err => {
                    document.getElementById('log').innerHTML = 
                        '[ERROR] Failed to fetch metrics. Retrying...';
                });
        }
        
        // Initial update
        updateMetrics();
        
        // Update every 2 seconds (matching page refresh)
        setInterval(updateMetrics, 2000);
    </script>
</body>
</html>
'''

# API endpoint that returns all metrics
@app.route('/api')
def api_all():
    # Get real system metrics
    cpu = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory().percent
    
    try:
        load = ' '.join([str(x) for x in psutil.getloadavg()])
    except:
        load = '0.00 0.00 0.00'
    
    # Network stats
    net = psutil.net_io_counters()
    connections = len(psutil.net_connections())
    
    # Simulate connection types
    conn_types = {
        'total': connections,
        'established': int(connections * 0.7),
        'syn': int(connections * 0.1),
        'time_wait': int(connections * 0.15),
        'udp': int(connections * 0.05)
    }
    
    # Simulate attack detection (20% chance)
    attack_detected = random.random() < 0.2
    attack_types = ['SYN FLOOD', 'UDP AMPLIFICATION', 'HTTP FLOOD', 'SLOWLORIS']
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'cpu': round(cpu, 1),
        'memory': round(memory, 1),
        'load': load,
        'uptime': str(datetime.now() - datetime.fromtimestamp(psutil.boot_time())).split('.')[0],
        
        'connections': conn_types,
        'network': {
            'rx': net.bytes_recv,
            'tx': net.bytes_sent,
            'packets': net.packets_recv + net.packets_sent
        },
        
        'defense': random.choice(['enterprise', 'medium', 'basic']),
        'threat': 'high' if attack_detected else random.choice(['low', 'medium']),
        'firewall': True,
        
        'attack': {
            'detected': attack_detected,
            'type': random.choice(attack_types) if attack_detected else 'none',
            'confidence': random.randint(70, 99) if attack_detected else 0
        },
        
        'services': {
            'firewall': True,
            'ids': True,
            'web': True,
            'monitor': True
        }
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🌐 SINGLE-PAGE DDoS MONITOR")
    print("="*60)
    print("📊 URL: http://0.0.0.0:5001")
    print("🔄 Auto-refreshes every 2 seconds")
    print("📈 Shows all metrics on one page")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5003, debug=True)
