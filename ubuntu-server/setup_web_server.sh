#!/bin/bash

# Setup web server for DDoS testing

echo "==============================================="
echo "    Setting up Web Server for DDoS Testing"
echo "==============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "This script requires root privileges. Use: sudo $0"
    exit 1
fi

# Install Apache
echo "[+] Installing Apache web server..."
apt update
apt install -y apache2

# Create test pages
echo "[+] Creating test pages..."

# Main index page
cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Test Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            padding: 40px 0;
            background: rgba(0,0,0,0.3);
            border-radius: 20px;
            margin-bottom: 30px;
        }
        h1 {
            font-size: 3em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        .status-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .status-card {
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 25px;
            transition: transform 0.3s ease;
        }
        .status-card:hover {
            transform: translateY(-5px);
            background: rgba(255,255,255,0.15);
        }
        .status-card h3 {
            font-size: 1.5em;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .metric {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .endpoints {
            background: rgba(0,0,0,0.2);
            border-radius: 15px;
            padding: 25px;
            margin-top: 30px;
        }
        .endpoints h3 {
            margin-bottom: 15px;
            font-size: 1.8em;
        }
        .endpoint-list {
            list-style: none;
        }
        .endpoint-list li {
            padding: 12px;
            margin: 8px 0;
            background: rgba(255,255,255,0.1);
            border-radius: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .endpoint-list a {
            color: #4cd964;
            text-decoration: none;
            font-weight: bold;
        }
        .endpoint-list a:hover {
            text-decoration: underline;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.1);
            font-size: 0.9em;
            opacity: 0.7;
        }
        .live-badge {
            display: inline-block;
            background: #4cd964;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        .server-info {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 10px;
        }
        .info-item {
            background: rgba(255,255,255,0.1);
            padding: 10px 20px;
            border-radius: 10px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Enterprise DDoS Test Server</h1>
            <div class="subtitle">Real-time attack simulation and defense monitoring</div>
            <div class="live-badge">● LIVE</div>
            
            <div class="server-info">
                <div class="info-item">📡 IP: <span id="server-ip">192.168.1.5</span></div>
                <div class="info-item">🖥️ Host: <span id="server-host">$(hostname)</span></div>
                <div class="info-item">⏰ Uptime: <span id="server-uptime">Loading...</span></div>
            </div>
        </div>
        
        <div class="status-container" id="status-container">
            <!-- Status will be updated by JavaScript -->
            <div class="status-card">
                <h3>📊 Connections</h3>
                <div class="metric" id="connections">0</div>
                <div>Active connections</div>
            </div>
            
            <div class="status-card">
                <h3>⚡ CPU Load</h3>
                <div class="metric" id="cpu-load">0%</div>
                <div>System load average</div>
            </div>
            
            <div class="status-card">
                <h3>💾 Memory</h3>
                <div class="metric" id="memory-usage">0%</div>
                <div>RAM usage</div>
            </div>
            
            <div class="status-card">
                <h3>🌐 Traffic</h3>
                <div class="metric" id="network-traffic">0 KB/s</div>
                <div>Incoming rate</div>
            </div>
        </div>
        
        <div class="endpoints">
            <h3>🎯 Test Endpoints</h3>
            <ul class="endpoint-list">
                <li>
                    <span>Home Page</span>
                    <a href="/">/index.html</a>
                </li>
                <li>
                    <span>Large File (10MB - for bandwidth testing)</span>
                    <a href="/large-file.bin">/large-file.bin</a>
                </li>
                <li>
                    <span>API Status (JSON)</span>
                    <a href="/api/status">/api/status</a>
                </li>
                <li>
                    <span>Slow Response (5s delay)</span>
                    <a href="/slow">/slow</a>
                </li>
                <li>
                    <span>Error Page (500 Internal Error)</span>
                    <a href="/error">/error</a>
                </li>
                <li>
                    <span>CPU Intensive Calculation</span>
                    <a href="/cpu-intensive">/cpu-intensive</a>
                </li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Enterprise DDoS Attack & Defense Lab v3.0</p>
            <p>For educational purposes only | Last update: <span id="update-time">$(date)</span></p>
        </div>
    </div>
    
    <script>
        // Update metrics every 2 seconds
        function updateMetrics() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('connections').textContent = data.connections.toLocaleString();
                    document.getElementById('cpu-load').textContent = data.cpu_load + '%';
                    document.getElementById('memory-usage').textContent = data.memory_usage + '%';
                    document.getElementById('network-traffic').textContent = data.network_rx;
                    document.getElementById('update-time').textContent = new Date().toLocaleTimeString();
                })
                .catch(error => {
                    console.error('Error fetching metrics:', error);
                });
            
            // Update every 2 seconds
            setTimeout(updateMetrics, 2000);
        }
        
        // Start updating metrics
        updateMetrics();
    </script>
</body>
</html>
HTML

# Create large test file
echo "[+] Creating large test file (10MB)..."
dd if=/dev/zero of=/var/www/html/large-file.bin bs=1M count=10

# Create API endpoints
mkdir -p /var/www/html/api

# Status API
cat > /var/www/html/api/status.php << 'PHP'
<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

function get_connections() {
    $output = shell_exec("netstat -ant 2>/dev/null | wc -l");
    return intval(trim($output)) - 1; // Subtract header line
}

function get_cpu_load() {
    $load = sys_getloadavg();
    return round($load[0] * 100, 2);
}

function get_memory_usage() {
    $free = shell_exec("free | grep Mem | awk '{print $3/$2 * 100.0}'");
    return round(floatval(trim($free)), 2);
}

function get_network_traffic() {
    // Get network interface (simplified)
    $interface = shell_exec("ip route get 8.8.8.8 2>/dev/null | awk '{print \$5}'");
    $interface = trim($interface);
    
    if (empty($interface)) {
        return "0 KB/s";
    }
    
    $rx_bytes = file_get_contents("/sys/class/net/$interface/statistics/rx_bytes");
    $rx_bytes = intval(trim($rx_bytes));
    
    // Calculate rate (simplified - real implementation would track over time)
    if ($rx_bytes > 1048576) {
        $rate = round($rx_bytes / 1048576, 2) . " MB/s";
    } elseif ($rx_bytes > 1024) {
        $rate = round($rx_bytes / 1024, 2) . " KB/s";
    } else {
        $rate = $rx_bytes . " B/s";
    }
    
    return $rate;
}

$response = [
    'status' => 'online',
    'server' => gethostname(),
    'timestamp' => date('Y-m-d H:i:s'),
    'connections' => get_connections(),
    'cpu_load' => get_cpu_load(),
    'memory_usage' => get_memory_usage(),
    'network_rx' => get_network_traffic(),
    'defense_level' => 'enterprise', // This would be dynamic in real implementation
];

echo json_encode($response, JSON_PRETTY_PRINT);
?>
PHP

# Slow response endpoint
cat > /var/www/html/slow.php << 'PHP'
<?php
header('Content-Type: text/html');
sleep(5); // 5 second delay
echo "<h1>Slow Response Test</h1>";
echo "<p>This page intentionally delays for 5 seconds to simulate slow response.</p>";
echo "<p>Current time: " . date('Y-m-d H:i:s') . "</p>";
?>
PHP

# Error page
cat > /var/www/html/error.php << 'PHP'
<?php
http_response_code(500);
header('Content-Type: text/html');
echo "<h1>500 Internal Server Error</h1>";
echo "<p>This is a simulated server error page.</p>";
echo "<p>For testing error handling during attacks.</p>";
?>
PHP

# CPU intensive endpoint
cat > /var/www/html/cpu-intensive.php << 'PHP'
<?php
header('Content-Type: text/html');

// CPU intensive calculation
$start = microtime(true);

// Calculate large factorial
function factorial($n) {
    $result = 1;
    for ($i = 1; $i <= $n; $i++) {
        $result = bcmul($result, $i);
    }
    return $result;
}

// Do some CPU intensive work
$result = factorial(1000);
$end = microtime(true);
$time = round($end - $start, 4);

echo "<h1>CPU Intensive Test</h1>";
echo "<p>Calculated factorial of 1000 in {$time} seconds</p>";
echo "<p>This simulates CPU-intensive operations.</p>";
?>
PHP

# Create symbolic links
ln -sf /var/www/html/status.php /var/www/html/api/status
ln -sf /var/www/html/slow.php /var/www/html/slow
ln -sf /var/www/html/error.php /var/www/html/error
ln -sf /var/www/html/cpu-intensive.php /var/www/html/cpu-intensive

# Set permissions
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

# Enable Apache modules
a2enmod rewrite
systemctl restart apache2

echo ""
echo "✅ Web server setup complete!"
echo ""
echo "📡 Server Information:"
echo "   • IP Address: $(hostname -I | cut -d' ' -f1)"
echo "   • Web Server: http://$(hostname -I | cut -d' ' -f1)/"
echo "   • Status API: http://$(hostname -I | cut -d' ' -f1)/api/status"
echo ""
echo "🎯 Test endpoints are available for DDoS testing"
echo "==============================================="
