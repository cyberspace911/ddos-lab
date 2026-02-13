#!/usr/bin/python3
"""
ENTERPRISE DDoS MONITORING SYSTEM
Professional dashboard with historical data, attack visualization, and real-time monitoring
"""
from flask import Flask, jsonify, Response, request
from flask_socketio import SocketIO
from flask_cors import CORS
import psutil
import time
import os
import json
import sqlite3
from datetime import datetime, timedelta
import threading
import socket
import netifaces
import subprocess
import hashlib
from collections import deque
import pickle
import gzip
import numpy as np

app = Flask(__name__)
app.secret_key = 'enterprise_ddos_monitor_2024_secure_key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Database setup for historical data
def init_database():
    conn = sqlite3.connect('monitoring.db', check_same_thread=False)
    cursor = conn.cursor()
    
    # Metrics history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metrics_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cpu_percent REAL,
            memory_percent REAL,
            connections_total INTEGER,
            network_rx_bytes INTEGER,
            network_tx_bytes INTEGER,
            disk_usage_percent REAL,
            load_avg_1m REAL,
            attack_detected BOOLEAN,
            attack_type TEXT,
            attack_confidence REAL
        )
    ''')
    
    # Attacks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            start_time DATETIME,
            end_time DATETIME,
            attack_type TEXT,
            severity TEXT,
            peak_connections INTEGER,
            peak_cpu REAL,
            description TEXT,
            mitigation_action TEXT,
            resolved BOOLEAN DEFAULT 0
        )
    ''')
    
    # Network events table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            dest_port INTEGER,
            protocol TEXT,
            packet_size INTEGER,
            flags TEXT,
            threat_level TEXT
        )
    ''')
    
    # Create indexes for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics_history(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_time ON attacks(start_time)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON network_events(timestamp)')
    
    conn.commit()
    conn.close()

# Initialize database
init_database()

# In-memory cache for real-time data
realtime_cache = {
    'metrics': deque(maxlen=1000),  # Last 1000 metrics
    'alerts': deque(maxlen=100),
    'network_events': deque(maxlen=500),
    'active_attacks': [],
    'system_stats': {}
}

# Attack detection thresholds
THRESHOLDS = {
    'SYN_FLOOD': {'syn_ratio': 0.3, 'syn_count': 50},
    'UDP_FLOOD': {'udp_ratio': 0.4, 'udp_count': 100},
    'CONNECTION_FLOOD': {'conn_per_ip': 50},
    'HTTP_FLOOD': {'req_per_sec': 1000},
    'SLOWLORIS': {'incomplete_conn': 100},
    'MEMORY_EXHAUSTION': {'memory_percent': 95},
    'CPU_EXHAUSTION': {'cpu_percent': 95}
}

class AttackDetector:
    """Advanced DDoS attack detection engine"""
    
    def __init__(self):
        self.attack_patterns = {}
        self.ip_reputation = {}
        self.geo_cache = {}
        
    def analyze_traffic(self, connections, network_stats):
        """Analyze network traffic for attack patterns"""
        indicators = {
            'detected': False,
            'type': 'none',
            'confidence': 0,
            'severity': 'low',
            'indicators': [],
            'suspicious_ips': [],
            'timeline': []
        }
        
        # Get current metrics
        total_conns = len(connections)
        if total_conns == 0:
            return indicators
        
        # Analyze connection types
        syn_count = 0
        udp_count = 0
        ip_counts = {}
        port_counts = {}
        
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
            
            # Count connections per port
            if conn.laddr and conn.laddr.port:
                port = conn.laddr.port
                port_counts[port] = port_counts.get(port, 0) + 1
        
        # Check for SYN Flood
        syn_ratio = syn_count / total_conns
        if syn_ratio > THRESHOLDS['SYN_FLOOD']['syn_ratio'] and syn_count > THRESHOLDS['SYN_FLOOD']['syn_count']:
            indicators['detected'] = True
            indicators['type'] = 'SYN_FLOOD'
            indicators['confidence'] = min(100, int(syn_ratio * 100))
            indicators['severity'] = 'high' if syn_ratio > 0.5 else 'medium'
            indicators['indicators'].append(f'SYN Flood detected: {syn_count} SYN packets ({syn_ratio:.1%} ratio)')
        
        # Check for UDP Flood
        udp_ratio = udp_count / total_conns
        if udp_ratio > THRESHOLDS['UDP_FLOOD']['udp_ratio'] and udp_count > THRESHOLDS['UDP_FLOOD']['udp_count']:
            indicators['detected'] = True
            indicators['type'] = 'UDP_FLOOD'
            indicators['confidence'] = max(indicators['confidence'], min(100, int(udp_ratio * 100)))
            indicators['severity'] = 'high' if udp_ratio > 0.6 else 'medium'
            indicators['indicators'].append(f'UDP Flood detected: {udp_count} UDP packets ({udp_ratio:.1%} ratio)')
        
        # Check for Connection Flood
        for ip, count in ip_counts.items():
            if count > THRESHOLDS['CONNECTION_FLOOD']['conn_per_ip']:
                indicators['detected'] = True
                indicators['type'] = 'CONNECTION_FLOOD'
                indicators['confidence'] = max(indicators['confidence'], min(100, count))
                indicators['severity'] = 'high' if count > 100 else 'medium'
                indicators['suspicious_ips'].append({'ip': ip, 'connections': count})
                indicators['indicators'].append(f'Connection flood from {ip}: {count} connections')
        
        # Check for Port Scan
        if len(port_counts) > 50 and total_conns > 100:
            indicators['detected'] = True
            indicators['type'] = 'PORT_SCAN'
            indicators['confidence'] = max(indicators['confidence'], 75)
            indicators['severity'] = 'medium'
            indicators['indicators'].append(f'Possible port scan: {len(port_counts)} different ports targeted')
        
        # Update timeline
        indicators['timeline'].append({
            'timestamp': datetime.now().isoformat(),
            'event': 'traffic_analysis',
            'details': {
                'total_connections': total_conns,
                'syn_count': syn_count,
                'udp_count': udp_count,
                'unique_ips': len(ip_counts)
            }
        })
        
        return indicators

# Initialize attack detector
attack_detector = AttackDetector()

def get_comprehensive_metrics():
    """Get ALL system metrics with enhanced detail"""
    timestamp = datetime.now()
    
    try:
        # ========== SYSTEM METRICS ==========
        # CPU with per-core details
        cpu_percent_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
        cpu_percent_total = sum(cpu_percent_per_core) / len(cpu_percent_per_core) if cpu_percent_per_core else 0
        cpu_freq = psutil.cpu_freq()
        cpu_stats = psutil.cpu_stats()
        cpu_times = psutil.cpu_times_percent(interval=0.1)
        
        # Memory with detailed breakdown
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        # Disk with partition details
        disk_usage = psutil.disk_usage('/')
        disk_partitions = psutil.disk_partitions()
        disk_io = psutil.disk_io_counters()
        
        # ========== NETWORK METRICS ==========
        net_io = psutil.net_io_counters()
        net_connections = psutil.net_connections()
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        # Get active connections with details
        active_connections = []
        for conn in net_connections:
            try:
                active_connections.append({
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
            except:
                continue
        
        # ========== PROCESS METRICS ==========
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 
                                         'memory_info', 'num_threads', 'status', 'create_time', 'connections']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort processes
        top_cpu = sorted(processes, key=lambda x: x.get('cpu_percent', 0) or 0, reverse=True)[:15]
        top_memory = sorted(processes, key=lambda x: x.get('memory_percent', 0) or 0, reverse=True)[:15]
        
        # ========== SYSTEM INFO ==========
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime = datetime.now() - boot_time
        
        try:
            load_avg = os.getloadavg()
        except:
            load_avg = (0.0, 0.0, 0.0)
        
        # ========== SECURITY CHECKS ==========
        security_status = perform_security_checks()
        
        # ========== DDoS DETECTION ==========
        attack_indicators = attack_detector.analyze_traffic(net_connections, net_io)
        
        # Record attack if detected
        if attack_indicators['detected']:
            record_attack_event(attack_indicators)
            realtime_cache['active_attacks'].append({
                'start_time': timestamp.isoformat(),
                'type': attack_indicators['type'],
                'severity': attack_indicators['severity'],
                'confidence': attack_indicators['confidence']
            })
        
        # ========== BUILD RESPONSE ==========
        metrics = {
            'timestamp': timestamp.isoformat(),
            'system': {
                'hostname': socket.gethostname(),
                'uptime': str(uptime),
                'boot_time': boot_time.isoformat(),
                'users': [{'name': u.name, 'terminal': u.terminal, 'host': u.host, 
                          'started': datetime.fromtimestamp(u.started).isoformat()} 
                         for u in psutil.users()],
                'load_average': {
                    '1m': load_avg[0],
                    '5m': load_avg[1],
                    '15m': load_avg[2]
                },
                'temperature': get_temperature(),
                'battery': get_battery_info()
            },
            
            'cpu': {
                'cores': {
                    'physical': psutil.cpu_count(logical=False),
                    'logical': psutil.cpu_count(logical=True)
                },
                'usage': {
                    'total': cpu_percent_total,
                    'per_core': cpu_percent_per_core,
                    'user': cpu_times.user,
                    'system': cpu_times.system,
                    'idle': cpu_times.idle,
                    'iowait': getattr(cpu_times, 'iowait', 0)
                },
                'frequency': {
                    'current': cpu_freq.current if cpu_freq else 0,
                    'min': cpu_freq.min if cpu_freq else 0,
                    'max': cpu_freq.max if cpu_freq else 0
                },
                'stats': {
                    'ctx_switches': cpu_stats.ctx_switches,
                    'interrupts': cpu_stats.interrupts,
                    'soft_interrupts': cpu_stats.soft_interrupts,
                    'syscalls': cpu_stats.syscalls
                }
            },
            
            'memory': {
                'ram': {
                    'total': memory.total,
                    'available': memory.available,
                    'used': memory.used,
                    'free': memory.free,
                    'percent': memory.percent,
                    'active': getattr(memory, 'active', 0),
                    'inactive': getattr(memory, 'inactive', 0),
                    'buffers': getattr(memory, 'buffers', 0),
                    'cached': getattr(memory, 'cached', 0),
                    'shared': getattr(memory, 'shared', 0)
                },
                'swap': {
                    'total': swap.total,
                    'used': swap.used,
                    'free': swap.free,
                    'percent': swap.percent,
                    'sin': swap.sin,
                    'sout': swap.sout
                }
            },
            
            'disk': {
                'root': {
                    'total': disk_usage.total,
                    'used': disk_usage.used,
                    'free': disk_usage.free,
                    'percent': disk_usage.percent
                },
                'partitions': [
                    {
                        'device': part.device,
                        'mountpoint': part.mountpoint,
                        'fstype': part.fstype,
                        'opts': part.opts,
                        'usage': psutil.disk_usage(part.mountpoint)._asdict()
                    } for part in disk_partitions
                ],
                'io': {
                    'read_bytes': disk_io.read_bytes,
                    'write_bytes': disk_io.write_bytes,
                    'read_count': disk_io.read_count,
                    'write_count': disk_io.write_count,
                    'read_time': disk_io.read_time,
                    'write_time': disk_io.write_time
                }
            },
            
            'network': {
                'io': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'errin': net_io.errin,
                    'errout': net_io.errout,
                    'dropin': net_io.dropin,
                    'dropout': net_io.dropout
                },
                'interfaces': [
                    {
                        'name': name,
                        'addresses': [
                            {
                                'family': str(addr.family),
                                'address': addr.address,
                                'netmask': addr.netmask,
                                'broadcast': addr.broadcast
                            } for addr in addrs
                        ],
                        'stats': net_if_stats[name]._asdict() if name in net_if_stats else {}
                    } for name, addrs in net_if_addrs.items()
                ],
                'connections': {
                    'total': len(net_connections),
                    'active': active_connections,
                    'stats': analyze_connection_stats(net_connections)
                }
            },
            
            'processes': {
                'total': len(processes),
                'by_state': count_processes_by_state(processes),
                'top_by_cpu': top_cpu[:10],
                'top_by_memory': top_memory[:10],
                'thread_count': sum(p.get('num_threads', 1) for p in processes)
            },
            
            'security': security_status,
            
            'ddos': attack_indicators,
            
            'alerts': generate_system_alerts(memory, cpu_percent_total, len(net_connections), attack_indicators)
        }
        
        # Store in cache
        realtime_cache['metrics'].append(metrics)
        realtime_cache['system_stats'] = metrics
        
        # Store in database
        store_metrics_in_db(metrics)
        
        return metrics
        
    except Exception as e:
        print(f"Error getting metrics: {e}")
        return None

def analyze_connection_stats(connections):
    """Analyze connection statistics"""
    stats = {
        'tcp': {'total': 0, 'states': {}, 'ports': {}},
        'udp': 0,
        'unix': 0,
        'by_ip': {},
        'by_port': {}
    }
    
    for conn in connections:
        # TCP connections
        if conn.type == socket.SOCK_STREAM:
            stats['tcp']['total'] += 1
            state = conn.status
            stats['tcp']['states'][state] = stats['tcp']['states'].get(state, 0) + 1
            
            # Track ports
            if conn.laddr:
                port = conn.laddr.port
                stats['tcp']['ports'][port] = stats['tcp']['ports'].get(port, 0) + 1
                stats['by_port'][port] = stats['by_port'].get(port, 0) + 1
            
            # Track IPs
            if conn.raddr:
                ip = conn.raddr.ip
                stats['by_ip'][ip] = stats['by_ip'].get(ip, 0) + 1
        
        # UDP connections
        elif conn.type == socket.SOCK_DGRAM:
            stats['udp'] += 1
        
        # Unix sockets
        elif conn.family == socket.AF_UNIX:
            stats['unix'] += 1
    
    return stats

def count_processes_by_state(processes):
    """Count processes by their state"""
    states = {}
    for proc in processes:
        state = proc.get('status', 'unknown')
        states[state] = states.get(state, 0) + 1
    return states

def perform_security_checks():
    """Perform comprehensive security checks"""
    checks = {
        'firewall': check_firewall_status(),
        'ssh': check_ssh_security(),
        'updates': check_system_updates(),
        'intrusion_detection': check_intrusion_detection(),
        'file_integrity': check_file_integrity(),
        'user_security': check_user_security(),
        'network_security': check_network_security()
    }
    
    # Calculate security score
    score = 0
    max_score = len(checks) * 10
    
    for check, result in checks.items():
        if isinstance(result, bool) and result:
            score += 10
        elif isinstance(result, dict) and result.get('secure', False):
            score += 10
    
    checks['security_score'] = int((score / max_score) * 100) if max_score > 0 else 0
    
    return checks

def check_firewall_status():
    """Check firewall status"""
    try:
        # Check UFW
        result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
        if 'Status: active' in result.stdout:
            return {'active': True, 'type': 'ufw', 'rules': len(result.stdout.split('\n')) - 2}
        
        # Check iptables
        result = subprocess.run(['sudo', 'iptables', '-L', '-n'], capture_output=True, text=True)
        if result.returncode == 0:
            return {'active': True, 'type': 'iptables', 'rules': len(result.stdout.split('\n'))}
        
        return {'active': False, 'type': 'none'}
    except:
        return {'active': False, 'type': 'unknown'}

def check_ssh_security():
    """Check SSH security configuration"""
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            config = f.read()
        
        checks = {
            'root_login_disabled': 'PermitRootLogin no' in config or 'PermitRootLogin prohibit-password' in config,
            'password_auth_disabled': 'PasswordAuthentication no' in config,
            'protocol_2': 'Protocol 2' in config,
            'max_auth_tries': 'MaxAuthTries' in config,
            'client_alive_interval': 'ClientAliveInterval' in config
        }
        
        return checks
    except:
        return {'error': 'Cannot read SSH config'}

def check_system_updates():
    """Check for system updates"""
    try:
        result = subprocess.run(['apt-get', 'update'], capture_output=True, text=True)
        if result.returncode == 0:
            result = subprocess.run(['apt-get', 'upgrade', '--dry-run'], capture_output=True, text=True)
            updates = len([line for line in result.stdout.split('\n') if 'upgraded' in line])
            return {'updates_available': updates > 0, 'count': updates}
    except:
        pass
    return {'updates_available': False, 'count': 0}

def check_intrusion_detection():
    """Check intrusion detection systems"""
    ids_systems = {
        'fail2ban': check_process('fail2ban'),
        'ossec': check_process('ossec'),
        'snort': check_process('snort'),
        'suricata': check_process('suricata')
    }
    
    active = [name for name, running in ids_systems.items() if running]
    return {'active_systems': active, 'count': len(active)}

def check_file_integrity():
    """Check file integrity monitoring"""
    try:
        # Check for aide or tripwire
        if os.path.exists('/var/lib/aide/aide.db'):
            return {'active': True, 'system': 'aide'}
        elif os.path.exists('/etc/tripwire'):
            return {'active': True, 'system': 'tripwire'}
    except:
        pass
    return {'active': False}

def check_user_security():
    """Check user account security"""
    try:
        result = subprocess.run(['awk', '-F:', '$2 == "" {print $1}', '/etc/shadow'], 
                              capture_output=True, text=True)
        empty_passwords = result.stdout.strip().split('\n') if result.stdout else []
        
        result = subprocess.run(['awk', '-F:', '$3 == "0" {print $1}', '/etc/passwd'], 
                              capture_output=True, text=True)
        root_users = result.stdout.strip().split('\n') if result.stdout else []
        
        return {
            'empty_passwords': len(empty_passwords),
            'root_users': root_users,
            'has_empty_passwords': len(empty_passwords) > 0
        }
    except:
        return {'error': 'Cannot check user security'}

def check_network_security():
    """Check network security"""
    try:
        # Check for listening services
        result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
        listening = []
        for line in result.stdout.split('\n')[2:]:
            if line:
                parts = line.split()
                if len(parts) >= 4:
                    listening.append(parts[3])
        
        return {'listening_services': listening, 'count': len(listening)}
    except:
        return {'error': 'Cannot check network security'}

def get_temperature():
    """Get system temperature if available"""
    try:
        if os.path.exists('/sys/class/thermal/thermal_zone0/temp'):
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                temp = int(f.read().strip()) / 1000
                return {'cpu': temp, 'unit': 'C'}
    except:
        pass
    return None

def get_battery_info():
    """Get battery information if available"""
    try:
        if hasattr(psutil, 'sensors_battery'):
            battery = psutil.sensors_battery()
            if battery:
                return {
                    'percent': battery.percent,
                    'plugged': battery.power_plugged,
                    'secsleft': battery.secsleft
                }
    except:
        pass
    return None

def generate_system_alerts(memory, cpu_percent, connections, attack_indicators):
    """Generate comprehensive system alerts"""
    alerts = []
    
    # Memory alerts
    if memory.percent > 95:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'memory',
            'message': f'Memory usage critical: {memory.percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Consider adding more RAM or killing memory-intensive processes'
        })
    elif memory.percent > 85:
        alerts.append({
            'level': 'WARNING',
            'type': 'memory',
            'message': f'Memory usage high: {memory.percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Monitor memory usage closely'
        })
    
    # CPU alerts
    if cpu_percent > 95:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'cpu',
            'message': f'CPU usage critical: {cpu_percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Check for runaway processes or consider load balancing'
        })
    elif cpu_percent > 85:
        alerts.append({
            'level': 'WARNING',
            'type': 'cpu',
            'message': f'CPU usage high: {cpu_percent:.1f}%',
            'timestamp': datetime.now().isoformat(),
            'action': 'Monitor CPU usage and check process list'
        })
    
    # Connection alerts
    if connections > 5000:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'connections',
            'message': f'Extremely high connection count: {connections}',
            'timestamp': datetime.now().isoformat(),
            'action': 'Possible DDoS attack or misconfiguration'
        })
    elif connections > 1000:
        alerts.append({
            'level': 'WARNING',
            'type': 'connections',
            'message': f'High connection count: {connections}',
            'timestamp': datetime.now().isoformat(),
            'action': 'Monitor network traffic'
        })
    
    # DDoS alerts
    if attack_indicators['detected']:
        alerts.append({
            'level': 'CRITICAL',
            'type': 'ddos',
            'message': f'DDoS attack detected: {attack_indicators["type"]} ({attack_indicators["confidence"]}% confidence)',
            'timestamp': datetime.now().isoformat(),
            'action': 'Activate mitigation strategies and block suspicious IPs',
            'details': attack_indicators
        })
    
    # Disk alerts
    try:
        disk = psutil.disk_usage('/')
        if disk.percent > 95:
            alerts.append({
                'level': 'CRITICAL',
                'type': 'disk',
                'message': f'Disk usage critical: {disk.percent:.1f}%',
                'timestamp': datetime.now().isoformat(),
                'action': 'Free up disk space immediately'
            })
        elif disk.percent > 85:
            alerts.append({
                'level': 'WARNING',
                'type': 'disk',
                'message': f'Disk usage high: {disk.percent:.1f}%',
                'timestamp': datetime.now().isoformat(),
                'action': 'Consider cleaning up old files'
            })
    except:
        pass
    
    return alerts

def store_metrics_in_db(metrics):
    """Store metrics in database"""
    try:
        conn = sqlite3.connect('monitoring.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO metrics_history 
            (timestamp, cpu_percent, memory_percent, connections_total, 
             network_rx_bytes, network_tx_bytes, disk_usage_percent, 
             load_avg_1m, attack_detected, attack_type, attack_confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            metrics['timestamp'],
            metrics['cpu']['usage']['total'],
            metrics['memory']['ram']['percent'],
            metrics['network']['connections']['total'],
            metrics['network']['io']['bytes_recv'],
            metrics['network']['io']['bytes_sent'],
            metrics['disk']['root']['percent'],
            metrics['system']['load_average']['1m'],
            metrics['ddos']['detected'],
            metrics['ddos']['type'],
            metrics['ddos']['confidence']
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error storing metrics: {e}")

def record_attack_event(attack_indicators):
    """Record attack event in database"""
    try:
        conn = sqlite3.connect('monitoring.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO attacks 
            (start_time, attack_type, severity, description)
            VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            attack_indicators['type'],
            attack_indicators['severity'],
            '; '.join(attack_indicators['indicators'])
        ))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error recording attack: {e}")

def get_historical_data(hours=24):
    """Get historical data for specified time period"""
    try:
        conn = sqlite3.connect('monitoring.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM metrics_history 
            WHERE timestamp >= datetime('now', ?)
            ORDER BY timestamp
        ''', (f'-{hours} hours',))
        
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        
        data = []
        for row in rows:
            data.append(dict(zip(columns, row)))
        
        conn.close()
        return data
    except Exception as e:
        print(f"Error getting historical data: {e}")
        return []

def get_attack_history(days=7):
    """Get attack history for specified period"""
    try:
        conn = sqlite3.connect('monitoring.db', check_same_thread=False)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM attacks 
            WHERE start_time >= datetime('now', ?)
            ORDER BY start_time DESC
        ''', (f'-{days} days',))
        
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        
        attacks = []
        for row in rows:
            attacks.append(dict(zip(columns, row)))
        
        conn.close()
        return attacks
    except Exception as e:
        print(f"Error getting attack history: {e}")
        return []

# ========== FLASK ROUTES ==========

@app.route('/')
def index():
    """Serve the main dashboard"""
    return '''
<!DOCTYPE html>
<html>
<head>
    <title>ENTERPRISE DDoS MONITORING SYSTEM</title>
    <meta charset="utf-8">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/socket.io-client@4.5.0/dist/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/luxon@3.3.0/build/global/luxon.min.js"></script>
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
            --success: #22c55e;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: var(--darker);
            color: var(--light);
            line-height: 1.6;
            overflow-x: hidden;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--primary-dark) 0%, #1e3a8a 100%);
            padding: 1.5rem 2rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            position: sticky;
            top: 0;
            z-index: 1000;
            backdrop-filter: blur(10px);
        }
        
        .header-content {
            max-width: 1800px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .logo-icon {
            font-size: 2rem;
            background: rgba(255, 255, 255, 0.1);
            width: 50px;
            height: 50px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .logo-text h1 {
            font-size: 1.5rem;
            font-weight: 700;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .logo-text p {
            font-size: 0.875rem;
            color: #94a3b8;
        }
        
        .status-indicator {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: var(--success);
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.5; }
            100% { opacity: 1; }
        }
        
        /* Main Layout */
        .container {
            max-width: 1800px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 2rem;
        }
        
        /* Sidebar */
        .sidebar {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .nav-card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
        }
        
        .nav-title {
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: #94a3b8;
            margin-bottom: 1rem;
        }
        
        .nav-list {
            list-style: none;
        }
        
        .nav-item {
            margin-bottom: 0.5rem;
        }
        
        .nav-link {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            color: #cbd5e1;
            text-decoration: none;
            border-radius: 8px;
            transition: all 0.2s;
        }
        
        .nav-link:hover, .nav-link.active {
            background: rgba(59, 130, 246, 0.2);
            color: #60a5fa;
        }
        
        .nav-link i {
            font-size: 1.25rem;
            width: 24px;
        }
        
        /* Stats Card */
        .stats-card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
        }
        
        .stat-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .stat-item:last-child {
            border-bottom: none;
        }
        
        .stat-label {
            font-size: 0.875rem;
            color: #94a3b8;
        }
        
        .stat-value {
            font-weight: 600;
            font-size: 1.125rem;
        }
        
        /* Main Content */
        .main-content {
            display: flex;
            flex-direction: column;
            gap: 2rem;
        }
        
        /* Grid Layout */
        .grid {
            display: grid;
            gap: 1.5rem;
        }
        
        .grid-2 {
            grid-template-columns: repeat(2, 1fr);
        }
        
        .grid-3 {
            grid-template-columns: repeat(3, 1fr);
        }
        
        .grid-4 {
            grid-template-columns: repeat(4, 1fr);
        }
        
        /* Cards */
        .card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 1.5rem;
            backdrop-filter: blur(10px);
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .card:hover {
            transform: translateY(-4px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        
        .card-title {
            font-size: 1.125rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .card-title i {
            color: var(--primary);
        }
        
        .card-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        
        .badge-success { background: rgba(34, 197, 94, 0.2); color: #86efac; }
        .badge-warning { background: rgba(245, 158, 11, 0.2); color: #fde68a; }
        .badge-danger { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
        .badge-info { background: rgba(59, 130, 246, 0.2); color: #93c5fd; }
        
        /* Metrics */
        .metric {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            background: rgba(15, 23, 42, 0.5);
            border-radius: 12px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            margin-bottom: 0.75rem;
        }
        
        .metric:last-child {
            margin-bottom: 0;
        }
        
        .metric-label {
            font-size: 0.875rem;
            color: #94a3b8;
        }
        
        .metric-value {
            font-size: 1.5rem;
            font-weight: 700;
        }
        
        .metric-change {
            font-size: 0.875rem;
        }
        
        .metric-change.positive { color: var(--success); }
        .metric-change.negative { color: var(--danger); }
        
        /* Progress Bars */
        .progress {
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            margin-top: 0.5rem;
            overflow: hidden;
        }
        
        .progress-bar {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }
        
        .progress-cpu { background: linear-gradient(90deg, #3b82f6, #8b5cf6); }
        .progress-memory { background: linear-gradient(90deg, #10b981, #0d9488); }
        .progress-disk { background: linear-gradient(90deg, #f59e0b, #d97706); }
        .progress-network { background: linear-gradient(90deg, #ef4444, #dc2626); }
        
        /* Charts */
        .chart-container {
            height: 300px;
            margin-top: 1rem;
            position: relative;
        }
        
        /* Tables */
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th {
            text-align: left;
            padding: 1rem;
            background: rgba(15, 23, 42, 0.5);
            color: #94a3b8;
            font-weight: 600;
            font-size: 0.875rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .table td {
            padding: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .table tr:last-child td {
            border-bottom: none;
        }
        
        .table tr:hover {
            background: rgba(255, 255, 255, 0.05);
        }
        
        /* Alerts */
        .alert {
            padding: 1rem;
            border-radius: 12px;
            margin-bottom: 1rem;
            display: flex;
            align-items: flex-start;
            gap: 1rem;
            border-left: 4px solid;
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
        
        .alert-icon {
            font-size: 1.5rem;
            margin-top: 0.125rem;
        }
        
        .alert-content {
            flex: 1;
        }
        
        .alert-title {
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .alert-message {
            font-size: 0.875rem;
            color: #cbd5e1;
        }
        
        /* Tabs */
        .tabs {
            display: flex;
            gap: 0.5rem;
            background: rgba(15, 23, 42, 0.5);
            padding: 0.5rem;
            border-radius: 12px;
            margin-bottom: 1.5rem;
        }
        
        .tab {
            padding: 0.75rem 1.5rem;
            background: transparent;
            border: none;
            color: #94a3b8;
            cursor: pointer;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.2s;
        }
        
        .tab:hover {
            background: rgba(255, 255, 255, 0.1);
        }
        
        .tab.active {
            background: var(--primary);
            color: white;
        }
        
        /* Tab Content */
        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        /* Attack Visualization */
        .attack-visualization {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            height: 400px;
        }
        
        .attack-map {
            background: rgba(15, 23, 42, 0.5);
            border-radius: 12px;
            padding: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        
        .attack-node {
            position: absolute;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .attack-node.center {
            width: 60px;
            height: 60px;
            background: var(--danger);
            color: white;
            box-shadow: 0 0 30px rgba(239, 68, 68, 0.5);
            z-index: 10;
        }
        
        .attack-node.attacker {
            background: var(--warning);
            color: black;
            font-size: 0.875rem;
        }
        
        .attack-connection {
            position: absolute;
            height: 2px;
            background: rgba(239, 68, 68, 0.3);
            transform-origin: 0 0;
        }
        
        /* Timeline */
        .timeline {
            position: relative;
            padding-left: 2rem;
        }
        
        .timeline::before {
            content: '';
            position: absolute;
            left: 7px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: rgba(255, 255, 255, 0.1);
        }
        
        .timeline-item {
            position: relative;
            margin-bottom: 2rem;
        }
        
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -2rem;
            top: 4px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: var(--primary);
        }
        
        .timeline-item.critical::before {
            background: var(--danger);
        }
        
        .timeline-item.warning::before {
            background: var(--warning);
        }
        
        .timeline-time {
            font-size: 0.875rem;
            color: #94a3b8;
            margin-bottom: 0.25rem;
        }
        
        .timeline-content {
            font-size: 0.875rem;
        }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.8);
            z-index: 2000;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(5px);
        }
        
        .modal.active {
            display: flex;
            animation: fadeIn 0.3s ease;
        }
        
        .modal-content {
            background: var(--dark);
            border-radius: 20px;
            padding: 2rem;
            max-width: 800px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        /* Responsive */
        @media (max-width: 1200px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            .grid-4 {
                grid-template-columns: repeat(2, 1fr);
            }
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }
            
            .grid-2, .grid-3, .grid-4 {
                grid-template-columns: 1fr;
            }
            
            .header-content {
                flex-direction: column;
                gap: 1rem;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">
                <div class="logo-icon">🛡️</div>
                <div class="logo-text">
                    <h1>ENTERPRISE DDoS MONITORING SYSTEM</h1>
                    <p>Real-time Threat Detection & Historical Analytics</p>
                </div>
            </div>
            <div class="status-indicator">
                <div class="status-dot"></div>
                <span id="system-status">Monitoring Active</span>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="dashboard">
            <!-- Sidebar -->
            <div class="sidebar">
                <div class="nav-card">
                    <div class="nav-title">Navigation</div>
                    <ul class="nav-list">
                        <li class="nav-item">
                            <a href="#overview" class="nav-link active">
                                <i>📊</i>
                                <span>Dashboard</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#network" class="nav-link">
                                <i>🌐</i>
                                <span>Network Analysis</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#attacks" class="nav-link">
                                <i>⚔️</i>
                                <span>Attack History</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#security" class="nav-link">
                                <i>🔒</i>
                                <span>Security</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#reports" class="nav-link">
                                <i>📈</i>
                                <span>Reports</span>
                            </a>
                        </li>
                        <li class="nav-item">
                            <a href="#settings" class="nav-link">
                                <i>⚙️</i>
                                <span>Settings</span>
                            </a>
                        </li>
                    </ul>
                </div>
                
                <div class="stats-card">
                    <div class="nav-title">Quick Stats</div>
                    <div class="stat-item">
                        <span class="stat-label">Uptime</span>
                        <span class="stat-value" id="quick-uptime">--</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">CPU Load</span>
                        <span class="stat-value" id="quick-load">--</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Memory</span>
                        <span class="stat-value" id="quick-memory">--%</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Connections</span>
                        <span class="stat-value" id="quick-connections">--</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Threat Level</span>
                        <span class="stat-value" id="quick-threat">LOW</span>
                    </div>
                </div>
            </div>
            
            <!-- Main Content -->
            <div class="main-content">
                <!-- Alerts Section -->
                <div id="alerts-section"></div>
                
                <!-- Dashboard Tab Content -->
                <div id="overview" class="tab-content active">
                    <!-- System Metrics -->
                    <div class="grid grid-4">
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">
                                    <i>💻</i>
                                    <span>CPU Usage</span>
                                </div>
                                <div class="card-badge" id="cpu-badge">Normal</div>
                            </div>
                            <div class="metric">
                                <div>
                                    <div class="metric-label">Total Usage</div>
                                    <div class="metric-value" id="cpu-total">0%</div>
                                </div>
                                <div class="metric-change" id="cpu-change">--</div>
                            </div>
                            <div class="progress">
                                <div class="progress-bar progress-cpu" id="cpu-bar" style="width: 0%"></div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">
                                    <i>🧠</i>
                                    <span>Memory</span>
                                </div>
                                <div class="card-badge" id="memory-badge">Normal</div>
                            </div>
                            <div class="metric">
                                <div>
                                    <div class="metric-label">Used</div>
                                    <div class="metric-value" id="memory-used">0 GB</div>
                                </div>
                                <div class="metric-change" id="memory-change">--</div>
                            </div>
                            <div class="progress">
                                <div class="progress-bar progress-memory" id="memory-bar" style="width: 0%"></div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">
                                    <i>💾</i>
                                    <span>Disk</span>
                                </div>
                                <div class="card-badge" id="disk-badge">Normal</div>
                            </div>
                            <div class="metric">
                                <div>
                                    <div class="metric-label">Usage</div>
                                    <div class="metric-value" id="disk-usage">0%</div>
                                </div>
                                <div class="metric-change" id="disk-change">--</div>
                            </div>
                            <div class="progress">
                                <div class="progress-bar progress-disk" id="disk-bar" style="width: 0%"></div>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">
                                    <i>🌐</i>
                                    <span>Network</span>
                                </div>
                                <div class="card-badge" id="network-badge">Normal</div>
                            </div>
                            <div class="metric">
                                <div>
                                    <div class="metric-label">Throughput</div>
                                    <div class="metric-value" id="network-throughput">0 MB/s</div>
                                </div>
                                <div class="metric-change" id="network-change">--</div>
                            </div>
                            <div class="progress">
                                <div class="progress-bar progress-network" id="network-bar" style="width: 0%"></div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Charts Section -->
                    <div class="grid grid-2">
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">
                                    <i>📈</i>
                                    <span>System Load (24h)</span>
                                </div>
                            </div>
                            <div class="chart-container">
                                <canvas id="load-chart"></canvas>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">
                                    <i>🔗</i>
                                    <span>Network Connections</span>
                                </div>
                            </div>
                            <div class="chart-container">
                                <canvas id="connections-chart"></canvas>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Real-time Data -->
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i>⚡</i>
                                <span>Real-time Monitoring</span>
                            </div>
                            <div class="tabs">
                                <button class="tab active" onclick="switchRealTimeTab('processes')">Processes</button>
                                <button class="tab" onclick="switchRealTimeTab('connections')">Connections</button>
                                <button class="tab" onclick="switchRealTimeTab('events')">Events</button>
                            </div>
                        </div>
                        
                        <div id="processes-tab" class="tab-content active">
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
                                    <!-- Processes will be loaded here -->
                                </tbody>
                            </table>
                        </div>
                        
                        <div id="connections-tab" class="tab-content">
                            <table class="table" id="connections-table">
                                <thead>
                                    <tr>
                                        <th>Protocol</th>
                                        <th>Local Address</th>
                                        <th>Remote Address</th>
                                        <th>Status</th>
                                        <th>PID</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <!-- Connections will be loaded here -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Network Analysis Tab -->
                <div id="network" class="tab-content">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i>🎯</i>
                                <span>DDoS Detection & Analysis</span>
                            </div>
                        </div>
                        
                        <div class="attack-visualization">
                            <div class="attack-map" id="attack-map">
                                <!-- Attack visualization will be rendered here -->
                            </div>
                            <div>
                                <div class="card">
                                    <div class="card-header">
                                        <div class="card-title">
                                            <i>📊</i>
                                            <span>Attack Metrics</span>
                                        </div>
                                    </div>
                                    <div id="attack-metrics">
                                        <!-- Attack metrics will be loaded here -->
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="timeline" id="attack-timeline">
                            <!-- Attack timeline will be loaded here -->
                        </div>
                    </div>
                </div>
                
                <!-- Attack History Tab -->
                <div id="attacks" class="tab-content">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i>📋</i>
                                <span>Attack History</span>
                            </div>
                            <div class="tabs">
                                <button class="tab active" onclick="switchAttackTab('recent')">Recent</button>
                                <button class="tab" onclick="switchAttackTab('statistics')">Statistics</button>
                                <button class="tab" onclick="switchAttackTab('patterns')">Patterns</button>
                            </div>
                        </div>
                        
                        <div id="recent-attacks" class="tab-content active">
                            <table class="table" id="attacks-table">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Type</th>
                                        <th>Severity</th>
                                        <th>Confidence</th>
                                        <th>Duration</th>
                                        <th>Impact</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <!-- Attacks will be loaded here -->
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <!-- Security Tab -->
                <div id="security" class="tab-content">
                    <div class="grid grid-2">
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">
                                    <i>🛡️</i>
                                    <span>Security Status</span>
                                </div>
                                <div class="card-badge" id="security-score">100%</div>
                            </div>
                            <div id="security-checks">
                                <!-- Security checks will be loaded here -->
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <div class="card-title">
                                    <i>🔐</i>
                                    <span>Services Status</span>
                                </div>
                            </div>
                            <div id="services-status">
                                <!-- Services status will be loaded here -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modals -->
    <div class="modal" id="attack-details-modal">
        <div class="modal-content">
            <div class="card-header">
                <div class="card-title">
                    <i>⚔️</i>
                    <span>Attack Details</span>
                </div>
                <button onclick="closeModal('attack-details-modal')" style="background: none; border: none; color: #94a3b8; cursor: pointer; font-size: 1.5rem;">×</button>
            </div>
            <div id="attack-details-content">
                <!-- Attack details will be loaded here -->
            </div>
        </div>
    </div>
    
    <script>
        // Global variables
        let socket = null;
        let charts = {};
        let realTimeData = {
            metrics: [],
            alerts: [],
            attacks: [],
            processes: [],
            connections: []
        };
        
        // Initialize WebSocket
        function initWebSocket() {
            socket = io();
            
            socket.on('connect', () => {
                console.log('Connected to WebSocket');
                updateStatus('connected');
            });
            
            socket.on('metrics_update', (data) => {
                updateRealtimeData(data);
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
            // Load chart
            const loadCtx = document.getElementById('load-chart').getContext('2d');
            charts.load = new Chart(loadCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'CPU Load',
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
                    plugins: {
                        legend: {
                            labels: { color: '#94a3b8' }
                        }
                    },
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
                        },
                        {
                            label: 'SYN Connections',
                            data: [],
                            borderColor: '#f59e0b',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            tension: 0.4,
                            fill: true
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: '#94a3b8' }
                        }
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#94a3b8' }
                        },
                        y: {
                            beginAtZero: true,
                            grid: { color: 'rgba(255, 255, 255, 0.1)' },
                            ticks: { color: '#94a3b8' }
                        }
                    }
                }
            });
        }
        
        // Update real-time data
        function updateRealtimeData(data) {
            // Update quick stats
            document.getElementById('quick-uptime').textContent = data.system.uptime.split('.')[0];
            document.getElementById('quick-load').textContent = data.system.load_average['1m'].toFixed(2);
            document.getElementById('quick-memory').textContent = data.memory.ram.percent.toFixed(1) + '%';
            document.getElementById('quick-connections').textContent = data.network.connections.total;
            document.getElementById('quick-threat').textContent = data.ddos.detected ? 'HIGH' : 'LOW';
            
            // Update CPU
            document.getElementById('cpu-total').textContent = data.cpu.usage.total.toFixed(1) + '%';
            document.getElementById('cpu-bar').style.width = data.cpu.usage.total + '%';
            updateBadge('cpu', data.cpu.usage.total);
            
            // Update Memory
            const memUsedGB = (data.memory.ram.used / 1024 / 1024 / 1024).toFixed(1);
            document.getElementById('memory-used').textContent = memUsedGB + ' GB';
            document.getElementById('memory-bar').style.width = data.memory.ram.percent + '%';
            updateBadge('memory', data.memory.ram.percent);
            
            // Update Disk
            document.getElementById('disk-usage').textContent = data.disk.root.percent.toFixed(1) + '%';
            document.getElementById('disk-bar').style.width = data.disk.root.percent + '%';
            updateBadge('disk', data.disk.root.percent);
            
            // Update Network
            const netThroughput = '--'; // Will be calculated from rates
            document.getElementById('network-throughput').textContent = netThroughput;
            updateBadge('network', 0); // Will be updated with actual metrics
            
            // Update charts
            updateCharts(data);
            
            // Update processes table
            updateProcessesTable(data.processes.top_by_cpu);
            
            // Update connections table
            updateConnectionsTable(data.network.connections.active);
            
            // Update alerts
            updateAlerts(data.alerts);
            
            // Store in history
            realTimeData.metrics.push(data);
            if (realTimeData.metrics.length > 100) {
                realTimeData.metrics.shift();
            }
        }
        
        function updateBadge(type, value) {
            const badge = document.getElementById(`${type}-badge`);
            let level = 'Normal';
            let badgeClass = 'badge-success';
            
            switch(type) {
                case 'cpu':
                case 'memory':
                case 'disk':
                    if (value > 90) {
                        level = 'Critical';
                        badgeClass = 'badge-danger';
                    } else if (value > 80) {
                        level = 'High';
                        badgeClass = 'badge-warning';
                    }
                    break;
                case 'network':
                    // Network badge logic
                    break;
            }
            
            badge.textContent = level;
            badge.className = `card-badge ${badgeClass}`;
        }
        
        function updateCharts(data) {
            const time = new Date(data.timestamp).toLocaleTimeString();
            
            // Update load chart
            if (charts.load) {
                charts.load.data.labels.push(time);
                charts.load.data.datasets[0].data.push(data.cpu.usage.total);
                charts.load.data.datasets[1].data.push(data.memory.ram.percent);
                
                if (charts.load.data.labels.length > 20) {
                    charts.load.data.labels.shift();
                    charts.load.data.datasets.forEach(dataset => dataset.data.shift());
                }
                
                charts.load.update('none');
            }
            
            // Update connections chart
            if (charts.connections) {
                if (!charts.connections.data.labels.includes(time)) {
                    charts.connections.data.labels.push(time);
                }
                charts.connections.data.datasets[0].data.push(data.network.connections.total);
                
                // Get SYN count
                const synCount = data.network.connections.stats?.tcp?.states?.SYN_RECV || 0;
                charts.connections.data.datasets[1].data.push(synCount);
                
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
            
            processes.forEach(proc => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${proc.pid}</td>
                    <td>${proc.name}</td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 60px; height: 6px; background: rgba(255, 255, 255, 0.1); border-radius: 3px;">
                                <div style="width: ${Math.min(100, proc.cpu_percent)}%; height: 100%; background: #3b82f6; border-radius: 3px;"></div>
                            </div>
                            <span>${proc.cpu_percent?.toFixed(1) || '0.0'}%</span>
                        </div>
                    </td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 60px; height: 6px; background: rgba(255, 255, 255, 0.1); border-radius: 3px;">
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
                tbody.appendChild(row);
            });
        }
        
        function updateConnectionsTable(connections) {
            const tbody = document.querySelector('#connections-table tbody');
            tbody.innerHTML = '';
            
            connections.slice(0, 10).forEach(conn => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${conn.family}</td>
                    <td>${conn.laddr || '-'}</td>
                    <td>${conn.raddr || '-'}</td>
                    <td>
                        <span class="badge ${conn.status === 'ESTABLISHED' ? 'badge-success' : 'badge-warning'}">
                            ${conn.status}
                        </span>
                    </td>
                    <td>${conn.pid || '-'}</td>
                `;
                tbody.appendChild(row);
            });
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-section');
            container.innerHTML = '';
            
            if (alerts.length === 0) {
                return;
            }
            
            alerts.forEach(alert => {
                const alertElement = document.createElement('div');
                alertElement.className = `alert alert-${alert.level.toLowerCase()}`;
                alertElement.innerHTML = `
                    <div class="alert-icon">
                        ${alert.level === 'CRITICAL' ? '🔴' : alert.level === 'WARNING' ? '🟡' : '🔵'}
                    </div>
                    <div class="alert-content">
                        <div class="alert-title">${alert.level}: ${alert.type}</div>
                        <div class="alert-message">${alert.message}</div>
                        <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 4px;">
                            ${new Date(alert.timestamp).toLocaleTimeString()}
                        </div>
                    </div>
                `;
                container.appendChild(alertElement);
            });
        }
        
        function handleAttackDetection(attack) {
            // Show attack alert
            const alert = {
                level: 'CRITICAL',
                type: 'DDoS ATTACK',
                message: `${attack.type} detected with ${attack.confidence}% confidence`,
                timestamp: new Date().toISOString()
            };
            showAlert(alert);
            
            // Update attack visualization
            updateAttackVisualization(attack);
            
            // Add to attack timeline
            addToAttackTimeline(attack);
            
            // Update attack metrics
            updateAttackMetrics(attack);
        }
        
        function updateAttackVisualization(attack) {
            const map = document.getElementById('attack-map');
            map.innerHTML = '';
            
            // Create center node (our server)
            const center = document.createElement('div');
            center.className = 'attack-node center';
            center.textContent = '🛡️';
            center.style.left = '50%';
            center.style.top = '50%';
            center.style.transform = 'translate(-50%, -50%)';
            map.appendChild(center);
            
            // Create attacker nodes
            const attackerCount = Math.min(10, attack.suspicious_ips?.length || 5);
            for (let i = 0; i < attackerCount; i++) {
                const angle = (i / attackerCount) * 2 * Math.PI;
                const radius = 150;
                const x = radius * Math.cos(angle);
                const y = radius * Math.sin(angle);
                
                const attacker = document.createElement('div');
                attacker.className = 'attack-node attacker';
                attacker.textContent = '⚔️';
                attacker.style.left = `calc(50% + ${x}px)`;
                attacker.style.top = `calc(50% + ${y}px)`;
                attacker.style.transform = 'translate(-50%, -50%)';
                
                // Create connection line
                const connection = document.createElement('div');
                connection.className = 'attack-connection';
                connection.style.left = '50%';
                connection.style.top = '50%';
                connection.style.width = `${radius}px`;
                connection.style.transform = `rotate(${angle}rad)`;
                
                map.appendChild(connection);
                map.appendChild(attacker);
            }
        }
        
        function addToAttackTimeline(attack) {
            const timeline = document.getElementById('attack-timeline');
            const item = document.createElement('div');
            item.className = `timeline-item ${attack.severity}`;
            
            item.innerHTML = `
                <div class="timeline-time">${new Date().toLocaleTimeString()}</div>
                <div class="timeline-content">
                    <strong>${attack.type}</strong> detected
                    <div style="color: #94a3b8; font-size: 0.875rem;">
                        Confidence: ${attack.confidence}% | Severity: ${attack.severity}
                    </div>
                </div>
            `;
            
            timeline.insertBefore(item, timeline.firstChild);
            
            // Keep only last 10 items
            while (timeline.children.length > 10) {
                timeline.removeChild(timeline.lastChild);
            }
        }
        
        function updateAttackMetrics(attack) {
            const container = document.getElementById('attack-metrics');
            container.innerHTML = `
                <div class="metric">
                    <div class="metric-label">Attack Type</div>
                    <div class="metric-value">${attack.type}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Confidence</div>
                    <div class="metric-value">${attack.confidence}%</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Severity</div>
                    <div class="metric-value">${attack.severity.toUpperCase()}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Suspicious IPs</div>
                    <div class="metric-value">${attack.suspicious_ips?.length || 0}</div>
                </div>
                <div style="margin-top: 1rem;">
                    <strong>Indicators:</strong>
                    <ul style="margin-top: 0.5rem; padding-left: 1.5rem; color: #94a3b8;">
                        ${attack.indicators?.map(ind => `<li>${ind}</li>`).join('') || '<li>No specific indicators</li>'}
                    </ul>
                </div>
            `;
        }
        
        function showAlert(alert) {
            // Implementation for showing alerts
            console.log('Alert:', alert);
        }
        
        function updateStatus(status) {
            const indicator = document.querySelector('.status-dot');
            const text = document.getElementById('system-status');
            
            switch(status) {
                case 'connected':
                    indicator.style.background = '#22c55e';
                    text.textContent = 'Monitoring Active';
                    break;
                case 'disconnected':
                    indicator.style.background = '#ef4444';
                    text.textContent = 'Connection Lost';
                    break;
                default:
                    indicator.style.background = '#f59e0b';
                    text.textContent = 'Connecting...';
            }
        }
        
        function switchRealTimeTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('#processes-tab, #connections-tab, #events-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(`${tabName}-tab`).classList.add('active');
            
            // Update tab buttons
            document.querySelectorAll('#processes-tab, #connections-tab, #events-tab').forEach(btn => {
                btn.previousElementSibling.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active');
                });
            });
            event.target.classList.add('active');
        }
        
        function switchAttackTab(tabName) {
            // Implementation for switching attack tabs
        }
        
        function showAttackDetails(attackId) {
            // Implementation for showing attack details
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).classList.remove('active');
        }
        
        // Load initial data
        async function loadInitialData() {
            try {
                const response = await fetch('/api/comprehensive');
                const data = await response.json();
                if (data) {
                    updateRealtimeData(data);
                }
            } catch (error) {
                console.error('Failed to load initial data:', error);
            }
        }
        
        // Initialize everything
        document.addEventListener('DOMContentLoaded', () => {
            initCharts();
            initWebSocket();
            loadInitialData();
            
            // Start periodic updates
            setInterval(() => {
                // Refresh data every 5 seconds
                socket.emit('request_metrics');
            }, 5000);
        });
    </script>
</body>
</html>
'''

# API endpoints
@app.route('/api/comprehensive')
def api_comprehensive():
    """Get comprehensive metrics"""
    metrics = get_comprehensive_metrics()
    if metrics:
        return jsonify(metrics)
    return jsonify({'error': 'Failed to get metrics'}), 500

@app.route('/api/historical/<hours>')
def api_historical(hours):
    """Get historical data"""
    try:
        data = get_historical_data(int(hours))
        return jsonify(data)
    except:
        return jsonify([])

@app.route('/api/attacks/<days>')
def api_attacks(days):
    """Get attack history"""
    try:
        data = get_attack_history(int(days))
        return jsonify(data)
    except:
        return jsonify([])

# WebSocket events
@socketio.on('connect')
def handle_connect():
    print(f"Client connected: {request.sid}")
    emit('connected', {'message': 'Connected to Enterprise DDoS Monitor'})

@socketio.on('request_metrics')
def handle_request_metrics():
    metrics = get_comprehensive_metrics()
    if metrics:
        emit('metrics_update', metrics)
        
        # Check for alerts
        if metrics['alerts']:
            for alert in metrics['alerts']:
                if alert['level'] in ['CRITICAL', 'WARNING']:
                    emit('alert', alert)
        
        # Check for attacks
        if metrics['ddos']['detected']:
            emit('attack_detected', metrics['ddos'])

def background_monitoring():
    """Background monitoring thread"""
    while True:
        try:
            socketio.sleep(3)  # Update every 3 seconds
            
            metrics = get_comprehensive_metrics()
            if metrics:
                socketio.emit('metrics_update', metrics)
                
                # Send alerts if any
                if metrics['alerts']:
                    for alert in metrics['alerts']:
                        if alert['level'] in ['CRITICAL', 'WARNING']:
                            socketio.emit('alert', alert)
                
                # Send attack detection if any
                if metrics['ddos']['detected']:
                    socketio.emit('attack_detected', metrics['ddos'])
                    
        except Exception as e:
            print(f"Error in background monitoring: {e}")

# Start background thread
threading.Thread(target=background_monitoring, daemon=True).start()

if __name__ == '__main__':
    print("\n" + "="*100)
    print("🚀 ENTERPRISE DDoS MONITORING SYSTEM")
    print("="*100)
    print("📊 Dashboard URL: http://0.0.0.0:5001")
    print("⚡ Real-time monitoring with WebSocket updates")
    print("📈 Historical data tracking (stored in SQLite)")
    print("🛡️ Advanced DDoS attack detection")
    print("🔒 Comprehensive security monitoring")
    print("💾 All real system data with detailed metrics")
    print("="*100 + "\n")
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)
