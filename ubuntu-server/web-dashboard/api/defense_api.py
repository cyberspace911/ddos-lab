#!/usr/bin/python3
"""
API endpoints for defense system integration
"""

from flask import Blueprint, jsonify, request
import subprocess
import os

defense_api = Blueprint('defense_api', __name__)

@defense_api.route('/defense/status', methods=['GET'])
def get_defense_status():
    """Get current defense system status"""
    try:
        # Check iptables rules
        result = subprocess.run(['sudo', 'iptables', '-L', '-n', '-v'], 
                              capture_output=True, text=True)
        
        # Determine defense level
        lines = result.stdout.split('\n')
        defense_level = 'unknown'
        
        # Simple heuristic to determine defense level
        drop_count = sum(1 for line in lines if 'DROP' in line)
        syn_protection = any('SYN' in line for line in lines)
        
        if drop_count > 10 and syn_protection:
            defense_level = 'enterprise'
        elif drop_count > 5:
            defense_level = 'medium'
        elif drop_count == 0:
            defense_level = 'none'
        
        return jsonify({
            'status': 'running',
            'defense_level': defense_level,
            'rules_count': drop_count,
            'firewall_active': True
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@defense_api.route('/defense/set_level/<int:level>', methods=['POST'])
def set_defense_level(level):
    """Set defense level (0=none, 1=medium, 2=enterprise)"""
    try:
        defense_script = "/root/ddos-enterprise-lab/ubuntu-server/ddos_defense_controller.sh"
        
        if os.path.exists(defense_script):
            result = subprocess.run(['sudo', defense_script, 'level', str(level)], 
                                  capture_output=True, text=True)
            
            return jsonify({
                'success': True,
                'output': result.stdout,
                'level': level
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Defense controller not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@defense_api.route('/defense/backup', methods=['POST'])
def backup_defense_config():
    """Backup current defense configuration"""
    try:
        backup_dir = "/root/ddos-enterprise-lab/ubuntu-server/backup"
        os.makedirs(backup_dir, exist_ok=True)
        
        # Backup iptables rules
        subprocess.run(['sudo', 'iptables-save'], 
                      stdout=open(f"{backup_dir}/iptables_backup.rules", 'w'))
        
        # Backup sysctl settings
        subprocess.run(['sysctl', '-a'], 
                      stdout=open(f"{backup_dir}/sysctl_backup.conf", 'w'))
        
        return jsonify({
            'success': True,
            'backup_dir': backup_dir
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@defense_api.route('/defense/restore', methods=['POST'])
def restore_defense_config():
    """Restore defense configuration from backup"""
    try:
        backup_dir = "/root/ddos-enterprise-lab/ubuntu-server/backup"
        
        if os.path.exists(f"{backup_dir}/iptables_backup.rules"):
            subprocess.run(['sudo', 'iptables-restore'], 
                          stdin=open(f"{backup_dir}/iptables_backup.rules", 'r'))
        
        return jsonify({
            'success': True,
            'message': 'Configuration restored'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
