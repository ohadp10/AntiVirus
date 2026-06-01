import sys
import time
import subprocess
import threading
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import frida
import ctypes
import ctypes.wintypes as wintypes
import threading
import time
import os


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
    מנגנון מיני-דיבאגר בסיסי ב-Python שמתמשק ל-Windows Debug API.
    מחליף את Frida על ידי מעקב אחרי אירועי מערכת (טעינת DLLs, חריגות, וכו') 
    ללא הזרקת קוד.
    """
    def __init__(self, malware_path, event_list):
        super().__init__()
        self.malware_path = malware_path
        self.event_list = event_list
        self.running = True
        self.daemon = True

    def run(self):
        DEBUG_ONLY_THIS_PROCESS = 0x00000002
        
        # מבנים של ווינדוס (Structures)
        class STARTUPINFO(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), 
                        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                        ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
                        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                        ("hStdError", wintypes.HANDLE)]

        class PROCESS_INFORMATION(ctypes.Structure):
            _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

        class DEBUG_EVENT(ctypes.Structure):
            _fields_ = [("dwDebugEventCode", wintypes.DWORD), ("dwProcessId", wintypes.DWORD),
                        ("dwThreadId", wintypes.DWORD), ("u", ctypes.c_byte * 160)]

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

        debug_event = DEBUG_EVENT()
        DBG_CONTINUE = 0x00010002
        start_time = time.time()

        while self.running and (time.time() - start_time < 10):
            # המתנה לאירוע חריג או פעולה של הוירוס
            if ctypes.windll.kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
                event_code = debug_event.dwDebugEventCode
                
                if event_code == 1:
                    self.event_list.append("[NATIVE DEBUGGER] EXCEPTION intercepted in target process.")
                elif event_code == 2:
                    self.event_list.append(f"[NATIVE DEBUGGER] Target spawned a new thread (TID: {debug_event.dwThreadId}).")
                elif event_code == 6: # LOAD_DLL_DEBUG_EVENT
                    self.event_list.append("[NATIVE DEBUGGER] Target dynamically loaded a DLL into memory.")
                elif event_code == 5: # EXIT_PROCESS_DEBUG_EVENT
                    ctypes.windll.kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)
                    break
                
                # שחרור הוירוס להמשך פעולה
                ctypes.windll.kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)

        ctypes.windll.kernel32.DebugActiveProcessStop(processinfo.dwProcessId)
        ctypes.windll.kernel32.TerminateProcess(processinfo.hProcess, 0)
        ctypes.windll.kernel32.CloseHandle(processinfo.hProcess)
        ctypes.windll.kernel32.CloseHandle(processinfo.hThread)


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
            Interceptor.attach(Module.findExportByName('advapi32.dll', 'RegSetValueExW'), {
                onEnter: function (args) {
                    // ברגע שוירוס מנסה לכתוב ערך לרג'יסטרי, נשלח את מחרוזת הקסם שההיוריסטיקה מחפשת
                    send({ api: 'RegSetValueExW', details: 'REGISTRY MODIFIED - Attempted to set registry key value' });
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