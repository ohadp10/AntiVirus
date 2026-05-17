import os
import time
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SandboxEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.logs = []

    def log_event(self, action, details):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {action}: {details}"
        self.logs.append(log_entry)
        print(log_entry)

    def on_created(self, event):
        if not event.is_directory: self.log_event("FILE CREATED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory: self.log_event("FILE DELETED", event.src_path)

    def on_modified(self, event):
        if not event.is_directory: self.log_event("FILE MODIFIED", event.src_path)

class LocalDynamicAnalyzer:
    def __init__(self, sandbox_dir=r"C:\Temp\SandboxTest"):
        self.sandbox_dir = sandbox_dir
        self.event_handler = SandboxEventHandler()
        self.observer = Observer()
        self.is_monitoring = False
        self.baseline_connections = set()
        
        if not os.path.exists(self.sandbox_dir):
            os.makedirs(self.sandbox_dir)

    def _get_active_ips(self):
        ips = set()
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ips.add(conn.raddr.ip)
        except Exception: pass
        return ips
            
    def start_monitoring(self):
        if not self.is_monitoring:
            self.baseline_connections = self._get_active_ips()
            self.observer.schedule(self.event_handler, self.sandbox_dir, recursive=True)
            self.observer.start()
            self.is_monitoring = True
            print("\n" + "="*50)
            print(f"[*] LOCAL DYNAMIC ANALYZER STARTED")
            print(f"    Monitoring Directory: {self.sandbox_dir}")
            print(f"    Baseline Network Connections Filtered: {len(self.baseline_connections)} IPs")
            print("="*50 + "\n")

    def check_network_activity(self):
        if not self.is_monitoring: return
        current_ips = self._get_active_ips()
        new_ips = current_ips - self.baseline_connections
        for ip in new_ips:
            if not ip.startswith("127.") and ip != "0.0.0.0":
                self.event_handler.log_event("NETWORK CONNECTION ALERT", f"Outbound traffic to IP: {ip}")
                self.baseline_connections.add(ip)

    def stop_monitoring(self):
        if self.is_monitoring:
            self.observer.stop()
            self.observer.join()
            self.is_monitoring = False
            print("\n[*] Local dynamic monitoring stopped.")
        return self.event_handler.logs