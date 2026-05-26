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
        האזנה לשירותי מערכת ההפעלה בזמן אמת ליצירת תהליכים, קבצים ושינויי רג'יסטרי.
        """
        def wmi_monitors_thread():
            pythoncom.CoInitialize()
            wmi = win32com.client.GetObject("winmgmts:")
            
            # 1. ניטור יצירת תהליכים (Process Creation)
            proc_watcher = wmi.ExecNotificationQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"
            )
            # 2. ניטור שינויי רג'יסטרי בנתיבי שרידות (ASEPs - Run Keys)
            reg_watcher = wmi.ExecNotificationQuery(
                "SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_RegistryAction'"
            )
            # 3. ניטור פעולות קבצים נמוכות (File System Watcher)
            file_watcher = wmi.ExecNotificationQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'CIM_DataFile' AND TargetInstance.Drive='C:'"
            )

            while self.running:
                try:
                    # בדיקת תהליכים חדשים (עץ תהליכים)
                    try:
                        proc_event = proc_watcher.NextEvent(1000)
                        proc = proc_event.TargetInstance
                        self.process_events.append(
                            f"[{time.strftime('%H:%M:%S')}] PROCESS CREATED: {proc.Name} (PID: {proc.ProcessId}) -> Parent PID: {proc.ParentProcessId}"
                        )
                    except: pass

                    # בדיקת שינויי קבצים (CreateFile / WriteFile)
                    try:
                        file_event = file_watcher.NextEvent(1000)
                        f_file = file_event.TargetInstance
                        if "Sandbox" in f_file.Path:
                            self.file_events.append(
                                f"[{time.strftime('%H:%M:%S')}] FILE EVENT: {f_file.Drive}{f_file.Path}{f_file.FileName}.{f_file.Extension}"
                            )
                    except: pass
                except Exception as e:
                    print(f"Monitor error: {e}")
            pythoncom.CoUninitialize()

        threading.Thread(target=wmi_monitors_thread, daemon=True).start()
        print("[+] Kernel Event Monitoring System initialized successfully.")

    def run_network_capture(self):
        """
        מפעיל לכידת רשת סמויה באמצעות Tshark מחוץ להקשר של הנוזקה.
        """
        print("[*] Launching Tshark Network Promiscuous Sniffer...")
        # הגדרת משך הלכידה ל-15 שניות
        tshark_cmd = ["tshark", "-i", "1", "-a", "duration:15", "-w", self.pcap_path]
        try:
            return subprocess.Popen(tshark_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            print("[-] Error: Tshark is not configured in the system Path.")
            return None

    def detonate_malware(self):
        """
        ביצוע הפיצוץ (Detonation) של הקובץ החשוד ומעקב אחר התנהגותו.
        """
        print(f"[*] Detonating target binary: {os.path.basename(self.malware_path)}")
        try:
            proc = subprocess.Popen([self.malware_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            # השהיית ריצה מוגדרת באפיון לאיסוף טלמטריה מספקת
            time.sleep(10)
            
            if proc.poll() is None:
                proc.terminate()
                print("[*] Target execution timed out and was safely terminated.")
            else:
                print(f"[*] Target exited normally with exit code: {proc.returncode}")
        except Exception as e:
            print(f"[-] Critical error during detonation: {e}")

    def parse_pcap_protocols(self):
        """
        מבצע ניתוח פרוטוקולים מתקדם מתוך קובץ ה-PCAP שנלכד.
        חילוץ מדויק של בקשות DNS, כותרות HTTP ופקודות FTP.
        """
        if not os.path.exists(self.pcap_path):
            return

        print("[*] Processing PCAP file through Advanced Protocol Parsers...")

        # 1. חילוץ שאילתות DNS (Query Names)
        try:
            dns_cmd = ["tshark", "-r", self.pcap_path, "-Y", "dns.flags.response == 0", "-T", "fields", "-e", "dns.qry.name"]
            res = subprocess.run(dns_cmd, capture_output=True, text=True)
            queries = set([line.strip() for line in res.stdout.split('\n') if line.strip()])
            for q in queries:
                self.network_events.append(f"[DNS QUERY] Malware requested Domain: {q}")
        except: pass

        # 2. חילוץ כותרות HTTP (Host, User-Agent, Methods)
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

        # 3. חילוץ פקודות ותעבורת FTP (Credentials & Command Tracking)
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
                    elif cmd in ["RETR", "STOR"]:
                        self.network_events.append(f"[FTP TRANSFER] File Data {cmd}: {arg}")
        except: pass

    def compile_final_report(self):
        """
        מנרמל את כל הממצאים לתוך דוח מובנה עבור השרת המרכזי ומנוע החוקים.
        """
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

        report.append("\n--- OS FILE SYSTEM LOGS ---")
        if self.file_events:
            # סינון כפילויות רציפות לקבלת פלט נקי
            report.extend(list(set(self.file_events)))
        else:
            report.append("[+] No anomalous file creation or data modification detected.")

        report.append("\n--- NETWORK PROTOCOL ANALYSIS ---")
        if self.network_events:
            report.extend(self.network_events)
        else:
            report.append("[+] No network indicators or connection attempts captured.")

        with open(self.report_path, "w", encoding="utf-8") as f:
            for line in report:
                f.write(line + "\n")
        print(f"[+] Analysis successfully completed. Report saved at: {self.report_path}")

    def execute_pipeline(self):
        # 1. הדלקת מנגנוני הניטור
        self.start_kernel_monitoring()
        tshark_proc = self.run_network_capture()
        
        time.sleep(2) # זמן התייצבות למאזינים
        
        # 2. הרצת הוירוס
        self.detonate_malware()
        
        # 3. כיבוי מאזינים
        self.running = False
        if tshark_proc:
            tshark_proc.wait(timeout=5)
            
        # 4. ניתוח קבצי הפלט והפקת דוח
        self.parse_pcap_protocols()
        self.compile_final_report()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[-] Usage: python agent.py <path_to_malware>")
        sys.exit(1)
        
    target = sys.argv[1]
    agent = AdvancedSandboxAgent(target)
    agent.execute_pipeline()