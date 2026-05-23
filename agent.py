import sys
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

def get_active_ips():
    ips = set()
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                ips.add(conn.raddr.ip)
    except: pass
    return ips

def monitor(target_exe):
    handler = SandboxEventHandler()
    observer = Observer()
    sandbox_dir = "C:\\Sandbox"
    
    baseline = get_active_ips()
    observer.schedule(handler, sandbox_dir, recursive=True)
    observer.start()
    
    import subprocess
    print(f"[*] Executing {target_exe} inside cloud sandbox...")
    try:
        proc = subprocess.Popen(target_exe, shell=True)
    except Exception as e:
        print(f"[!] Failed to execute: {e}")
        return
        
    print("[*] Monitoring file and network behavior for 10 seconds...")
    for _ in range(10):
        current_ips = get_active_ips()
        new_ips = current_ips - baseline
        for ip in new_ips:
            if not ip.startswith("127.") and ip != "0.0.0.0":
                handler.log_event("NETWORK CONNECTION ALERT", f"Outbound traffic to IP: {ip}")
                baseline.add(ip)
        time.sleep(1)
        
    try:
        proc.terminate()
    except: pass
    
    observer.stop()
    observer.join()
    
    # שומר את התוצאות לקובץ טקסט כדי שהמחשב שלך יוכל למשוך אותן בחזרה
    with open("C:\\Sandbox\\analysis_report.txt", "w") as f:
        for log in handler.logs:
            f.write(log + "\n")
    print("[*] Analysis complete. Logs saved to analysis_report.txt")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        monitor(sys.argv[1])
    else:
        print("Usage: python agent.py <path_to_malware.exe>")