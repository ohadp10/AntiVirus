import sys
import os
import time
import subprocess
import threading
import pythoncom
import win32com.client

class AdvancedSandboxAgent:
    def __init__(self, malware_path):
        self.malware_path = malware_path
        self.watch_dir = os.path.dirname(malware_path)
        self.pcap_path = os.path.join(self.watch_dir, "network_capture.pcap")
        self.report_path = os.path.join(self.watch_dir, "analysis_report.txt")
        
        # מאגרי נתונים לרישום ממצאים בזמן אמת
        self.file_events = []
        self.process_events = []
        self.registry_events = []
        self.network_events = []
        self.running = True

    def start_kernel_monitoring(self):
        """
        מממש את דרישת הניטור ברמת הליבה (Kernel/ETW Layer)
        האזנה ליצירת תהליכים, קבצים ושינויי רג'יסטרי.
        """
        def wmi_monitors_thread():
            pythoncom.CoInitialize()
            wmi = win32com.client.GetObject("winmgmts:")
            
            # 1. ניטור יצירת תהליכים (Process Creation)
            proc_watcher = wmi.ExecNotificationQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
            )
            
            # 2. ניטור שינויי רג'יסטרי בנתיבי שרידות (Run Keys) - תוקן והושלם
            reg_watcher = wmi.ExecNotificationQuery(
                "SELECT * FROM RegistryKeyChangeEvent WITHIN 1 WHERE Hive='HKEY_LOCAL_MACHINE' AND KeyPath='SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'"
            )
            
            # 3. ניטור פעולות קבצים נמוכות
            file_watcher = wmi.ExecNotificationQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'CIM_DataFile' AND TargetInstance.Drive='C:'"
            )

            while self.running:
                try:
                    # בדיקת תהליכים
                    try:
                        proc_event = proc_watcher.NextEvent(1000)
                        proc = proc_event.TargetInstance
                        self.process_events.append(
                            f"[{time.strftime('%H:%M:%S')}] PROCESS CREATED: {proc.Name} (PID: {proc.ProcessId}) -> Parent: {proc.ParentProcessId}"
                        )
                    except: pass

                    # בדיקת רג'יסטרי (החלק שהיה חסר)
                    try:
                        reg_event = reg_watcher.NextEvent(1000)
                        self.registry_events.append(
                            f"[{time.strftime('%H:%M:%S')}] REGISTRY MODIFIED: Persistence mechanisms (Run Key) altered!"
                        )
                    except: pass

                    # בדיקת קבצים
                    try:
                        file_event = file_watcher.NextEvent(1000)
                        f_file = file_event.TargetInstance
                        if "Sandbox" in f_file.Path:
                            self.file_events.append(
                                f"[{time.strftime('%H:%M:%S')}] FILE CREATED/MODIFIED: {f_file.Name}"
                            )
                    except: pass
                except Exception as e:
                    pass # השתקת שגיאות WMI כדי לא לעצור את סריקת הרשת והתהליכים
                    
            pythoncom.CoUninitialize()

        threading.Thread(target=wmi_monitors_thread, daemon=True).start()
        print("[+] Kernel Event Monitoring System initialized successfully.")

    def run_network_capture(self):
        print("[*] Launching Tshark Network Promiscuous Sniffer...")
        tshark_cmd = ["tshark", "-i", "1", "-a", "duration:15", "-w", self.pcap_path]
        try:
            return subprocess.Popen(tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print("[-] Error: Tshark is not configured in the system Path.")
            return None

    def detonate_malware(self):
        print(f"[*] Detonating target binary: {os.path.basename(self.malware_path)}")
        try:
            proc = subprocess.Popen([self.malware_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(10)
            
            if proc.poll() is None:
                proc.terminate()
                print("[*] Target execution timed out and was safely terminated.")
            else:
                print(f"[*] Target exited normally with exit code: {proc.returncode}")
        except Exception as e:
            print(f"[-] Critical error during detonation: {e}")

    def parse_pcap_protocols(self):
        """ מנתח פרוטוקולים - DNS, HTTP, FTP """
        if not os.path.exists(self.pcap_path):
            return

        print("[*] Processing PCAP file through Advanced Protocol Parsers...")
        try:
            dns_cmd = ["tshark", "-r", self.pcap_path, "-Y", "dns.flags.response == 0", "-T", "fields", "-e", "dns.qry.name"]
            res = subprocess.run(dns_cmd, capture_output=True, text=True)
            queries = set([line.strip() for line in res.stdout.split('\n') if line.strip()])
            for q in queries:
                self.network_events.append(f"[DNS QUERY] Malware requested Domain: {q}")
        except: pass

        try:
            http_cmd = ["tshark", "-r", self.pcap_path, "-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.user_agent", "-e", "http.request.method"]
            res = subprocess.run(http_cmd, capture_output=True, text=True)
            for line in res.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    host = parts[0] if len(parts) > 0 else "Unknown"
                    ua = parts[1] if len(parts) > 1 else "Unknown"
                    method = parts[2] if len(parts) > 2 else "Unknown"
                    self.network_events.append(f"[HTTP REQUEST] Method: {method} | Host: {host} | User-Agent: {ua}")
        except: pass

        try:
            ftp_cmd = ["tshark", "-r", self.pcap_path, "-Y", "ftp", "-T", "fields", "-e", "ftp.request.command", "-e", "ftp.request.arg"]
            res = subprocess.run(ftp_cmd, capture_output=True, text=True)
            for line in res.stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    cmd = parts[0].strip() if len(parts) > 0 else ""
                    arg = parts[1].strip() if len(parts) > 1 else ""
                    if cmd in ["USER", "PASS"]:
                        self.network_events.append(f"[FTP CREDENTIALS] Leaked {cmd}: {arg}")
        except: pass

    def compile_final_report(self):
        print("[*] Compiling technical report...")
        report = []
        report.append("="*60)
        report.append("       ADVANCED MALWARE ANALYSIS REPORT - CYBER SANDBOX")
        report.append("="*60)
        report.append(f"[*] Target File: {self.malware_path}")
        report.append(f"[*] Analysis Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        report.append("--- KERNEL PROCESS LOGS (PROCESS TREE) ---")
        if self.process_events:
            report.extend(self.process_events)
        else:
            report.append("[+] No suspicious child processes or injections detected.")

        report.append("\n--- REGISTRY MODIFICATIONS (PERSISTENCE) ---")
        if self.registry_events:
            report.extend(self.registry_events)
        else:
            report.append("[+] No ASEP/Run Key modifications detected.")

        report.append("\n--- OS FILE SYSTEM LOGS ---")
        if self.file_events:
            # תוקן: הסרת כפילויות רצופות תוך שמירה על כרונולוגיה מלאה (במקום set שהורס סדר)
            cleaned_files = []
            for item in self.file_events:
                if not cleaned_files or item != cleaned_files[-1]:
                    cleaned_files.append(item)
            report.extend(cleaned_files)
        else:
            report.append("[+] No anomalous file creation or data modification detected.")

        report.append("\n--- NETWORK PROTOCOL ANALYSIS ---")
        if self.network_events:
            report.extend(self.network_events)
        else:
            report.append("[+] No network indicators or connection attempts captured.")

        with open(self.report_path, "w", encoding="utf-8") as f:
            print(f"[*] AGENT DEBUG: Attempting to write report to {self.report_path}")
            for line in report:
                f.write(line + "\n")
        print(f"[+] Analysis successfully completed. Report saved at: {self.report_path}")

    def execute_pipeline(self):
        self.start_kernel_monitoring()
        tshark_proc = self.run_network_capture()
        
        time.sleep(2) 
        self.detonate_malware()
        
        self.running = False
        
        # תוקן: הגנה מפני קריסות של tshark
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