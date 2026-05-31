import sys
import os
import time
import subprocess
import threading
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import frida

class SandboxFileMonitor(FileSystemEventHandler):
    def __init__(self, event_list):
        self.event_list = event_list
    # מאזינה ברקע למערכת ההפעלה

    def on_created(self, event):
        if not event.is_directory:
            self.event_list.append(f"[{time.strftime('%H:%M:%S')}] FILE CREATED: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            self.event_list.append(f"[{time.strftime('%H:%M:%S')}] FILE MODIFIED: {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            self.event_list.append(f"[{time.strftime('%H:%M:%S')}] FILE DELETED: {event.src_path}")


class AdvancedSandboxAgent:
    def __init__(self, malware_path):
        self.malware_path = malware_path
        self.watch_dir = os.path.dirname(malware_path)
        self.pcap_path = os.path.join(self.watch_dir, "network_capture.pcap")
        self.report_path = os.path.join(self.watch_dir, "analysis_report.txt")
        
        # הגדרות עבור ETW
        self.etw_trace_name = "MalwareETWTrace"
        self.etw_output_file = os.path.join(self.watch_dir, "trace.etl")
        
        self.file_events = []
        self.api_hooks_events = []
        self.network_events = []
        self.process_tree = {} 
        self.running = True

    def start_filesystem_watcher(self):
        """ מפעיל את ה-FileSystemWatcher באמצעות Watchdog """
        event_handler = SandboxFileMonitor(self.file_events)
        self.observer = Observer()
        self.observer.schedule(event_handler, self.watch_dir, recursive=True)
        self.observer.start()
        print("[+] FileSystemWatcher initialized.")

    def start_etw_monitoring(self):
        """ מפעיל האזנה ברמת ה-Kernel דרך מנגנון ETW האמיתי של Windows """
        print("[*] Starting ETW Kernel Monitoring...")
        # מוודאים שאין trace ישן שרץ
        subprocess.run(["logman", "stop", self.etw_trace_name, "-ets"], capture_output=True)
        
        # מתחילים רישום של תהליכים ואירועי רשת מליבת המערכת
        start_cmd = [
            "logman", "start", self.etw_trace_name, "-p", 
            "Microsoft-Windows-Kernel-Process", "0x10", "-ets", 
            "-o", self.etw_output_file
        ]
        subprocess.run(start_cmd, capture_output=True)
        print("[+] ETW Trace session active.")

    def run_network_capture(self):
        """ מפעיל את הניטור הפסיבי של הרשת """
        print("[*] Launching Tshark Network Promiscuous Sniffer...")
        tshark_cmd = ["tshark", "-i", "1", "-a", "duration:15", "-w", self.pcap_path]
        try:
            return subprocess.Popen(tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print("[-] Error: Tshark is not configured in the system Path.")
            return None

    def setup_dll_hooking(self, pid):
        """ מתחבר לתהליך הזדוני ומבצע DLL Hooking לפונקציות API קריטיות """
        try:
            session = frida.attach(pid)
            # סקריפט JS שמוזרק לזיכרון של התהליך ותופס את הפעולות שלו
            script_code = """
            Interceptor.attach(Module.findExportByName('kernel32.dll', 'VirtualAlloc'), {
                onEnter: function (args) {
                send({ api: 'VirtualAlloc', details: 'Allocated ' + args[1].toInt32() + ' bytes' });                }
            });
            Interceptor.attach(Module.findExportByName('kernel32.dll', 'CreateFileW'), {
                onEnter: function (args) {
                    send({ api: 'CreateFileW', details: 'Accessed file: ' + Memory.readUtf16String(args[0]) });
                }
            });
            """
            script = session.create_script(script_code)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    payload = message['payload']
                    self.api_hooks_events.append(f"[DLL HOOK] {payload['api']} -> {payload['details']}")
            
            script.on('message', on_message)
            script.load()
            print(f"[+] Frida DLL Hooking established successfully on PID {pid}.")
        except Exception as e:
            print(f"[-] Frida Hooking failed: {e}")

    def detonate_malware(self):
        print(f"[*] Detonating target binary: {os.path.basename(self.malware_path)}")
        try:
            # הפעלת הנוזקה
            proc = subprocess.Popen([self.malware_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # רושמים את התהליך הראשי לעץ התהליכים
            self.process_tree["Root"] = {"PID": proc.pid, "Children": []}
            
            # חיבור ה-DLL Hooking מיד לאחר ההפעלה
            time.sleep(0.5) 
            self.setup_dll_hooking(proc.pid)
            
            # נותנים לנוזקה זמן לרוץ
            time.sleep(10)
            
            if proc.poll() is None:
                proc.terminate()
                print("[*] Target execution timed out and was safely terminated.")
            else:
                print(f"[*] Target exited normally with exit code: {proc.returncode}")
                
        except Exception as e:
            print(f"[-] Critical error during detonation: {e}")

    def stop_etw_monitoring(self):
        """ עוצר את ה-ETW וממיר את התוצאות לפורמט קריא """
        print("[*] Stopping ETW and dumping data...")
        subprocess.run(["logman", "stop", self.etw_trace_name, "-ets"], capture_output=True)
        # בפרויקט אמיתי מעבירים את הקובץ xml_output לפארסר מורכב יותר
        xml_output = os.path.join(self.watch_dir, "trace.xml")
        subprocess.run(["tracerpt", self.etw_output_file, "-o", xml_output, "-of", "XML"], capture_output=True)
        print("[+] ETW Trace converted to XML.")

    def parse_pcap_protocols(self):
        """ מנתח את חבילות הרשת, כולל חילוץ חתימות JA3 מ-TLS """
        if not os.path.exists(self.pcap_path):
            return

        print("[*] Processing PCAP file through Advanced Protocol Parsers...")
        # 1. DNS
        try:
            dns_cmd = ["tshark", "-r", self.pcap_path, "-Y", "dns.flags.response == 0", "-T", "fields", "-e", "dns.qry.name"]
            res = subprocess.run(dns_cmd, capture_output=True, text=True)
            queries = set([line.strip() for line in res.stdout.split('\n') if line.strip()])
            for q in queries:
                self.network_events.append(f"[DNS QUERY] Requested Domain: {q}")
        except: pass

        # 2. HTTP
        try:
            http_cmd = ["tshark", "-r", self.pcap_path, "-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.user_agent", "-e", "http.request.method"]
            res = subprocess.run(http_cmd, capture_output=True, text=True)
            for line in res.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    host = parts[0] if len(parts) > 0 else "Unknown"
                    self.network_events.append(f"[HTTP REQUEST] Host: {host}")
        except: pass

        # 3. חישוב חתימות JA3 (תקשורת מוצפנת)
        try:
            ja3_cmd = ["tshark", "-r", self.pcap_path, "-Y", "tls.handshake.type == 1", "-T", "fields", "-e", "tls.handshake.ja3"]
            res = subprocess.run(ja3_cmd, capture_output=True, text=True)
            ja3_hashes = set([line.strip() for line in res.stdout.split('\n') if line.strip()])
            for h in ja3_hashes:
                self.network_events.append(f"[TLS/JA3 SIGNATURE] Encrypted traffic signature: {h}")
        except: pass

    def compile_final_report(self):
        print("[*] Compiling technical report...")
        report = []
        report.append(f"[*] Target File: {self.malware_path}")
        report.append(f"[*] Analysis Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        report.append("--- PROCESS TREE & ETW LOGS ---")
        report.append(json.dumps(self.process_tree, indent=4))

        report.append("\n--- API MONITORING (DLL HOOKING) ---")
        if self.api_hooks_events:
            report.extend(self.api_hooks_events)
        else:
            report.append("[+] No hooked API calls intercepted.")

        report.append("\n--- OS FILE SYSTEM LOGS (WATCHDOG) ---")
        if self.file_events:
            report.extend(list(dict.fromkeys(self.file_events)))
        else:
            report.append("[+] No anomalous file creation or data modification detected.")

        report.append("\n--- NETWORK PROTOCOL ANALYSIS & JA3 ---")
        if self.network_events:
            report.extend(self.network_events)
        else:
            report.append("[+] No network indicators or connection attempts captured.")

        with open(self.report_path, "w", encoding="utf-8") as f:
            for line in report:
                f.write(line + "\n")
        print(f"[+] Analysis successfully completed. Report saved at: {self.report_path}")

    def execute_pipeline(self):
        self.start_filesystem_watcher()
        self.start_etw_monitoring()
        tshark_proc = self.run_network_capture()
        
        time.sleep(2) 
        self.detonate_malware()
        
        self.running = False
        self.observer.stop()
        self.observer.join()
        
        self.stop_etw_monitoring()
        
        if tshark_proc:
            try:
                tshark_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tshark_proc.terminate()
                tshark_proc.wait()
                
        time.sleep(2) 
            
        self.parse_pcap_protocols()
        self.compile_final_report()
        
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[-] Usage: python agent.py <path_to_malware>")
        sys.exit(1)
        
    target = sys.argv[1]
    agent = AdvancedSandboxAgent(target)
    agent.execute_pipeline()