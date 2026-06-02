import sys
import time
import subprocess
import threading
import json
import ctypes
import ctypes.wintypes as wintypes
import os
from win_apis import STARTUPINFO, PROCESS_INFORMATION, DEBUG_EVENT


# Custome File Monitor
class CustomDirectoryMonitor(threading.Thread):
    """
    מנגנון שעוקב אחרי שינויים במערכת הקבצים בעזרת Windows API
    שימוש בשפת c בעזרת python
    """
    def __init__(self, watch_dir, event_list):
        super().__init__()
        self.watch_dir = watch_dir 
        self.event_list = event_list
        self.running = True
        self.daemon = True

    def run(self):
        FILE_LIST_DIRECTORY = 0x0001 # הרשאה לקרוא את התוכן 
        FILE_SHARE_READ = 0x00000001 # הרשאות לתוכנות אחרות לקרוא, לכתוב ולמחוק
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3 # כדי לא לנעול את התיקייה, זה מבקש לפתוח אותה רק אם היא קיימת 
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000 # לקבל הרשאה ממערכת ההפעלה להתייחס לתיקייה כמו קובץ כדי לקבל handle
        NOTIFY_FILTERS = (0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000100) # סוגי התרעות מווינדוס: שינוי שם קובץ, שינוי שם תיקייה, שינוי תכונות, שינוי גודל, כתיבה אחרונה, ושינוי הרשאות אבטחה.

        # פתיחת חיבור ישיר לתיקייה ברמת מערכת ההפעלה
        # מחזיר hanle לתיקייה
        hDir = ctypes.windll.kernel32.CreateFileW(
            self.watch_dir, FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None
        )

        if hDir == -1:
            print("[-] Custom Monitor Error: Could not get directory handle.")
            return

        # הגדרה של בלוק זיכרון שלשם יגיעו הנתונים
        buffer = ctypes.create_string_buffer(8192)
        # כמה בתים של מידע נכתבו, ממיר את הסוג משתנה ל dword
        bytes_returned = wintypes.DWORD()

        ACTIONS = {1: "FILE CREATED", 2: "FILE DELETED", 3: "FILE MODIFIED"}

        while self.running:
            # האזנה שקטה דרך Windows API
            # נותנים לפונקציה הזאת את ההנדל של התיקייה את הבאפר שלשם ירשמו הנתונים
            result = ctypes.windll.kernel32.ReadDirectoryChangesW(
                hDir, buffer, ctypes.sizeof(buffer), True, 
                NOTIFY_FILTERS, ctypes.byref(bytes_returned), None, None
            )

            if result and bytes_returned.value > 0:
                offset = 0
                while True:
                    # קוד הפעולה בתים ממקיום 4 עד 8 והופכים אותם למספר שלם
                    action_code = int.from_bytes(buffer[offset+4:offset+8], byteorder='little')
                    # בתים ממיקום 8 עד 12 מציגים את אורך שם הקובץ
                    name_length = int.from_bytes(buffer[offset+8:offset+12], byteorder='little')
                    # בתים מ12 עד לאורך שם הקובץ הם שם הקובץ עצמו
                    name_bytes = buffer[offset+12:offset+12+name_length]
                    # ממירים את הבתים של שם הקובץ לטקסט קריא מסוג ascii
                    file_name = name_bytes.decode('utf-16le', errors='ignore')
                    

                    if action_code in ACTIONS:
                        action_str = ACTIONS[action_code]
                        full_path = os.path.join(self.watch_dir, file_name)
                        self.event_list.append(f"[{time.strftime('%H:%M:%S')}] [CUSTOM] {action_str}: {full_path}")
                    
                    # בתחילת ההודעה בבתים 0 עד 4 מופיע האופסט של ההודעה הבאה
                    next_entry_offset = int.from_bytes(buffer[offset:offset+4], byteorder='little')
                    # אם האופסט הוא 0 אז נגמרו ההודעות
                    if next_entry_offset == 0:
                        break
                    offset += next_entry_offset

# Custom Native Debugger
class CustomNativeDebugger(threading.Thread):
    """
    דיבאגר לוירוס - נותן מידע על טעינת ספריות dll 
    """
    def __init__(self, malware_path, event_list, process_tree):
        super().__init__()
        self.malware_path = malware_path
        self.event_list = event_list
        self.process_tree = process_tree
        self.running = True
        self.daemon = True

    def run(self):
        DEBUG_ONLY_THIS_PROCESS = 0x00000002

        startupinfo = STARTUPINFO()
        startupinfo.cb = ctypes.sizeof(startupinfo)
        processinfo = PROCESS_INFORMATION()

        # יצירת התהליך במצב Debug
        success = ctypes.windll.kernel32.CreateProcessW(
            None, self.malware_path, None, None, False, 
            DEBUG_ONLY_THIS_PROCESS, None, None, 
            ctypes.byref(startupinfo), ctypes.byref(processinfo)
        )

        if not success:
            print("[-] Custom Debugger Error: Failed to launch target.")
            return
            
        # רושמים את התהליך הראשי לעץ התהליכים
        self.process_tree["Root"] = {"PID": processinfo.dwProcessId, "Children": []}

        debug_event = DEBUG_EVENT()
        DBG_CONTINUE = 0x00010002
        start_time = time.time()

        while self.running and (time.time() - start_time < 10):
            # המתנה לאירוע חריג או פעולה של הוירוס
            if ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
                event_code = debug_event.dwDebugEventCode
                
                debug_messages = {
                    1: "[NATIVE DEBUGGER] EXCEPTION intercepted in target process.",
                    2: "[NATIVE DEBUGGER] Target spawned a new thread (TID: {tid}).",
                    6: "[NATIVE DEBUGGER] Target dynamically loaded a DLL into memory."
                    }
            
                if event_code in debug_messages.keys():
                    # שולף את ההודעה מהמילון, מציב את ה-TID (אם צריך), ודוחף לרשימה
                    self.event_list.append(debug_messages[event_code].format(tid=debug_event.dwThreadId))

                elif event_code == 5: # EXIT_PROCESS_DEBUG_EVENT
                    ctypes.windll.kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)
                    print("[*] Target exited normally within debugger.")
                    break
                
                # שחרור הוירוס להמשך פעולה
                ctypes.windll.kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)

        ctypes.windll.kernel32.DebugActiveProcessStop(processinfo.dwProcessId)
        ctypes.windll.kernel32.TerminateProcess(processinfo.hProcess, 0)
        ctypes.windll.kernel32.CloseHandle(processinfo.hProcess)
        ctypes.windll.kernel32.CloseHandle(processinfo.hThread)


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
        
        # משתנים לשמירת האובייקטים של המנגנונים המותאמים אישית שלנו
        self.fs_monitor = None
        self.debugger = None

    def start_filesystem_watcher(self):
        """ מפעיל את ה-FileSystemWatcher המותאם אישית שלנו (CustomDirectoryMonitor) """
        self.fs_monitor = CustomDirectoryMonitor(self.watch_dir, self.file_events)
        self.fs_monitor.start()
        print("[+] Custom FileSystemWatcher initialized natively.")

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

    def detonate_malware(self):
        print(f"[*] Detonating target binary natively: {os.path.basename(self.malware_path)}")
        try:
            # הפעלת הנוזקה דרך הדיבאגר המותאם אישית שלנו (מחליף את הקריאה ל-subprocess.Popen ול-frida)
            self.debugger = CustomNativeDebugger(self.malware_path, self.api_hooks_events, self.process_tree)
            self.debugger.start()
            
            # נותנים לנוזקה זמן לרוץ (הדיבאגר מוגבל בפנים ל-10 שניות)
            self.debugger.join(timeout=12)
            
            if self.debugger.is_alive():
                print("[*] Target execution timed out and debugger is stopping it.")
                self.debugger.running = False
                self.debugger.join()
                
        except Exception as e:
            print(f"[-] Critical error during native detonation: {e}")

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

        report.append("\n--- API MONITORING (NATIVE DEBUGGER) ---")
        if self.api_hooks_events:
            report.extend(self.api_hooks_events)
        else:
            report.append("[+] No debug events intercepted.")

        report.append("\n--- OS FILE SYSTEM LOGS (CUSTOM MONITOR) ---")
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
        
        # עצירת מנגנון הקבצים המותאם אישית שלנו
        if self.fs_monitor:
            self.fs_monitor.running = False
        
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