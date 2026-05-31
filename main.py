import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox

from database_manager import DatabaseManager
from virus_total_api import VirusTotalAPI
from static_analyzer import StaticAnalyzer
from dynamic_analyzer import DynamicAnalyzer
from heuristic_engine import HeuristicRuleEngine

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class MalwareDetectionApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Malware Detection Software")
        self.geometry("1100x700")
        self.minsize(900, 600)

        self.target_file_path = None
        self.db_manager = DatabaseManager()
        self.vt_api = VirusTotalAPI()
        self.static_analyzer = None
        self.dynamic_analyzer = None
        self.static_status = None
        self.dynamic_logs = []
        self.final_report = {}

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        
        self.main_container = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_container.grid(row=0, column=1, sticky="nsew")
        self.main_container.grid_rowconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for F in (DashboardFrame, NewScanFrame, StaticAnalysisFrame, DynamicAnalysisFrame, FinalVerdictFrame):
            frame_name = F.__name__
            frame = F(parent=self.main_container, controller=self)
            self.frames[frame_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("DashboardFrame")

    def _build_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(3, weight=1)

        self.logo_label = ctk.CTkLabel(self.sidebar_frame, text="Malware Detection\nSoftware", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 30))

        self.btn_dashboard = ctk.CTkButton(self.sidebar_frame, text="Dashboard", command=lambda: self.show_frame("DashboardFrame"))
        self.btn_dashboard.grid(row=1, column=0, padx=20, pady=10)

        self.btn_new_scan = ctk.CTkButton(self.sidebar_frame, text="New Scan", command=lambda: self.show_frame("NewScanFrame"))
        self.btn_new_scan.grid(row=2, column=0, padx=20, pady=10)

    def show_frame(self, frame_name):
        frame = self.frames[frame_name]
        frame.tkraise()
        if frame_name == "DashboardFrame":
            frame.load_recent_scans()

# מסך 1: Dashboard
class DashboardFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller

        self.title = ctk.CTkLabel(self, text="Malware Detection Software", font=ctk.CTkFont(size=32, weight="bold"))
        self.title.pack(pady=(40, 20))

        self.subtitle = ctk.CTkLabel(self, text="Recent Scans", font=ctk.CTkFont(size=20))
        self.subtitle.pack(pady=(0, 10))

        self.table_frame = ctk.CTkScrollableFrame(self, width=800, height=400)
        self.table_frame.pack(pady=10, padx=40, fill="both", expand=True)

    def load_recent_scans(self):
        # ניקוי הטבלה הקיימת
        for widget in self.table_frame.winfo_children():
            widget.destroy()

        # כותרות הטבלה
        headers = ["File Name", "Hash", "Date", "Score", "Verdict"]
        for col, text in enumerate(headers):
            lbl = ctk.CTkLabel(self.table_frame, text=text, font=ctk.CTkFont(weight="bold"))
            lbl.grid(row=0, column=col, padx=15, pady=10, sticky="w")

        # משיכת נתונים מה-DB
        recent_scans = self.controller.db_manager.get_recent_scans(limit=10)
        
        if not recent_scans:
            no_data = ctk.CTkLabel(self.table_frame, text="No recent scans found.")
            no_data.grid(row=1, column=0, columnspan=5, pady=20)
            return

        for row_idx, scan in enumerate(recent_scans, start=1):
            file_name, file_hash, scan_date, threat_score, final_verdict = scan
            
            short_hash = f"{file_hash[:10]}..." if len(file_hash) > 10 else file_hash
            
            ctk.CTkLabel(self.table_frame, text=file_name).grid(row=row_idx, column=0, padx=15, pady=5, sticky="w")
            ctk.CTkLabel(self.table_frame, text=short_hash).grid(row=row_idx, column=1, padx=15, pady=5, sticky="w")
            ctk.CTkLabel(self.table_frame, text=str(scan_date)).grid(row=row_idx, column=2, padx=15, pady=5, sticky="w")
            ctk.CTkLabel(self.table_frame, text=str(threat_score)).grid(row=row_idx, column=3, padx=15, pady=5, sticky="w")
            
            color = "green" if final_verdict.lower() == "safe" else "red" if final_verdict.lower() == "malicious" else "yellow"
            ctk.CTkLabel(self.table_frame, text=final_verdict.upper(), text_color=color, font=ctk.CTkFont(weight="bold")).grid(row=row_idx, column=4, padx=15, pady=5, sticky="w")


# מסך 2: New Scan
class NewScanFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller

        self.title = ctk.CTkLabel(self, text="Start a New Scan", font=ctk.CTkFont(size=28, weight="bold"))
        self.title.pack(pady=(80, 40))

        self.lbl_selected = ctk.CTkLabel(self, text="No file selected", font=ctk.CTkFont(size=16, slant="italic"))
        self.lbl_selected.pack(pady=20)

        self.btn_select = ctk.CTkButton(self, text="Select File", command=self.select_file, width=200, height=40)
        self.btn_select.pack(pady=10)

        self.btn_start = ctk.CTkButton(self, text="Start Scan", command=self.start_scan, width=200, height=40, state="disabled", fg_color="green", hover_color="darkgreen")
        self.btn_start.pack(pady=20)

    def select_file(self):
        file_path = filedialog.askopenfilename(title="Select an Executable", filetypes=[("Executable Files", "*.exe")])
        
        if file_path:
            if file_path.lower().endswith('.exe'):
                self.controller.target_file_path = file_path
                self.lbl_selected.configure(text=f"Selected: {os.path.basename(file_path)}")
                self.btn_start.configure(state="normal")
            else:
                messagebox.showerror("Invalid File Format", "Error: Please select a valid .exe file only.")
                
                self.lbl_selected.configure(text="No file selected")
                self.btn_start.configure(state="disabled")

    def start_scan(self):
        self.btn_start.configure(state="disabled")
        self.controller.show_frame("StaticAnalysisFrame")
        self.controller.frames["StaticAnalysisFrame"].begin_static_process()


# מסך 3: Static Analysis
class StaticAnalysisFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller

        self.title = ctk.CTkLabel(self, text="Static Analyze", font=ctk.CTkFont(size=28, weight="bold"))
        self.title.pack(pady=(30, 20))

        # תיבת טקסט יפה להצגת התוצאות
        self.results_box = ctk.CTkTextbox(self, width=800, height=400, font=ctk.CTkFont(family="Consolas", size=14))
        self.results_box.pack(pady=10, padx=40, fill="both", expand=True)

        self.btn_continue = ctk.CTkButton(self, text="Waiting for Static Analyazing...", width=250, height=45, state="disabled")
        self.btn_continue.pack(pady=20)

    def append_text(self, text):
        self.results_box.insert("end", text + "\n")
        self.results_box.see("end")

    def begin_static_process(self):
        self.results_box.delete("1.0", "end")
        self.btn_continue.configure(text="Waiting for Static Analyazing...", state="disabled")
        self.append_text("[*] Initializing Static Analysis Engine...")
        
        # הרצה בתהליכון נפרד
        threading.Thread(target=self._run_static_analysis, daemon=True).start()

    def _run_static_analysis(self):
        target = self.controller.target_file_path
        self.controller.static_analyzer = StaticAnalyzer(target, self.controller.db_manager, self.controller.vt_api)
        
        self.append_text(f"[*] Target: {os.path.basename(target)}\n" + "-"*40)
        
        status = self.controller.static_analyzer.begin_analyzing()
        self.controller.static_status = status
        results = self.controller.static_analyzer.results

        self.append_text(f"\n[ PE Validation ]: {'Valid' if results.get('is_valid_pe') else 'Invalid'}")
        self.append_text(f"[ Entry Point ]: {results.get('entry_point')} (Section: {results.get('ep_section')})")
        self.append_text(f"[ Packed/Encrypted ]: {'Yes (High Entropy/UPX)' if results.get('is_packed') else 'No'}")
        self.append_text(f"[ Full File Hash ]: {results.get('file_hash')}")
        self.append_text(f"[ Known Reputation ]: {results.get('is_hash_malicious').upper()}")
        
        if results.get("suspicious_imports"):
            self.append_text(f"\n[ Suspicious APIs ]: {', '.join(results.get('suspicious_imports'))}")
            
        self.append_text(f"\n[ Assembly Risk Score ]: {results.get('assembly_risk_score')}/100")

        self.after(500, self._finalize_static, status)

    def _finalize_static(self, status):
        if status == "INVALID_PE":
            self.append_text("\n[-] ERROR: Invalid PE format. Cannot continue.")
            messagebox.showerror("Error", "Invalid PE format. Scan aborted.")
            self.controller.show_frame("DashboardFrame")
        elif status == "KNOWN_MALICIOUS":
            self.append_text("\n[!!!] CRITICAL: Known malware detected by Hash. Bypassing dynamic analysis.")
            self.btn_continue.configure(text="View Final Verdict", state="normal", fg_color="orange", command=self.go_to_verdict_direct)
        else:
            self.append_text("\n[+] Static analysis completed successfully.")
            self.btn_continue.configure(text="Continue to Dynamic Analyzing", state="normal", fg_color="blue", command=self.go_to_dynamic)

    def go_to_dynamic(self):
        self.controller.show_frame("DynamicAnalysisFrame")
        self.controller.frames["DynamicAnalysisFrame"].begin_dynamic_process()
        
    def go_to_verdict_direct(self):
        # אם הקובץ זדוני בודאות, קופצים ישר לסוף
        self.controller.final_report = {
            "threat_score": 100,
            "final_verdict": "MALICIOUS",
            "insights": ["[STATIC] Hash matched a known malicious signature in Database/VirusTotal."]
        }
        self.controller.show_frame("FinalVerdictFrame")
        self.controller.frames["FinalVerdictFrame"].display_verdict()


# מסך 4: Dynamic Analysis
class DynamicAnalysisFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller

        self.title = ctk.CTkLabel(self, text="Dynamic Analyze", font=ctk.CTkFont(size=28, weight="bold"))
        self.title.pack(pady=(30, 20))

        self.results_box = ctk.CTkTextbox(self, width=800, height=400, font=ctk.CTkFont(family="Consolas", size=14))
        self.results_box.pack(pady=10, padx=40, fill="both", expand=True)

        self.btn_continue = ctk.CTkButton(self, text="Executing in AWS Sandbox...", width=250, height=45, state="disabled")
        self.btn_continue.pack(pady=20)

    def append_text(self, text):
        self.results_box.insert("end", text + "\n")
        self.results_box.see("end")

    def begin_dynamic_process(self):
        self.results_box.delete("1.0", "end")
        self.btn_continue.configure(text="Executing in AWS Sandbox...", state="disabled")
        self.append_text("[*] Provisioning isolated AWS EC2 Sandbox...\nWaiting for results.")
        
        threading.Thread(target=self._run_dynamic_analysis, daemon=True).start()

    def _run_dynamic_analysis(self):
        try:
            target = self.controller.target_file_path
            self.controller.dynamic_analyzer = DynamicAnalyzer(target)
            
            # הרצת האנליזה ושמירת הלוגים
            logs = self.controller.dynamic_analyzer.run_analysis()
            self.controller.dynamic_logs = logs
            
            if logs:
                self.append_text("\n[+] Dynamic Execution Completed. Analyzing Logs:\n" + "-"*40)
                for log in logs[:15]:
                    self.append_text(" -> " + log)
                if len(logs) > 15:
                    self.append_text(f"\n... and {len(logs)-15} more events captured.")
            else:
                self.append_text("\n[-] Execution failed or no events were captured.")

        except Exception as e:
            self.append_text(f"\n[-] Cloud Sandbox Error: {e}")
            self.controller.dynamic_logs = []

        self.after(500, self._finalize_dynamic)

    def _finalize_dynamic(self):
        self.append_text("\n[*] Passing data to Heuristic Engine...")
        self.btn_continue.configure(text="Continue", state="normal", fg_color="green", command=self.calculate_and_go)

    def calculate_and_go(self):
        # הרצת מנוע ההיוריסטיקה
        engine = HeuristicRuleEngine(self.controller.static_analyzer.results, self.controller.dynamic_logs)
        self.controller.final_report = engine.calculate_threat_score()
        
        # שמירה במסד נתונים ברקע
        def save_to_db():
            self.controller.db_manager.save_scan_report(
                file_name=os.path.basename(self.controller.target_file_path),
                file_hash=self.controller.static_analyzer.results.get("file_hash", ""),
                threat_score=self.controller.final_report["threat_score"],
                final_verdict=self.controller.final_report["final_verdict"],
                insights=self.controller.final_report["insights"],
                dynamic_logs=self.controller.dynamic_logs
            )
        threading.Thread(target=save_to_db, daemon=True).start()

        self.controller.show_frame("FinalVerdictFrame")
        self.controller.frames["FinalVerdictFrame"].display_verdict()


# מסך 5: Final Verdict
class FinalVerdictFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color="transparent")
        self.controller = controller

        self.title = ctk.CTkLabel(self, text="Final Verdict", font=ctk.CTkFont(size=36, weight="bold"))
        self.title.pack(pady=(60, 20))

        self.lbl_verdict = ctk.CTkLabel(self, text="UNKNOWN", font=ctk.CTkFont(size=50, weight="bold"))
        self.lbl_verdict.pack(pady=20)

        self.lbl_score = ctk.CTkLabel(self, text="Threat Score: 0/100", font=ctk.CTkFont(size=24))
        self.lbl_score.pack(pady=10)

        self.insights_box = ctk.CTkTextbox(self, width=700, height=200, font=ctk.CTkFont(size=14))
        self.insights_box.pack(pady=30)

        self.btn_home = ctk.CTkButton(self, text="Return to Dashboard", command=lambda: self.controller.show_frame("DashboardFrame"), width=200, height=45)
        self.btn_home.pack(pady=20)

    def display_verdict(self):
        report = self.controller.final_report
        verdict = report.get("final_verdict", "UNKNOWN").upper()
        score = report.get("threat_score", 0)

        # הגדרת צבעים
        if verdict == "SAFE":
            color = "#00cc00" # ירוק
        elif verdict == "SUSPICIOUS":
            color = "#ffcc00" # צהוב
        else:
            color = "#ff3333" # אדום

        self.lbl_verdict.configure(text=verdict, text_color=color)
        self.lbl_score.configure(text=f"Threat Score: {score}/100")

        # הצגת ההסברים
        self.insights_box.delete("1.0", "end")
        insights = report.get("insights", [])
        if insights:
            self.insights_box.insert("end", "Why did it get this score?\n" + "="*30 + "\n\n")
            for insight in insights:
                self.insights_box.insert("end", f" • {insight}\n")
        else:
            self.insights_box.insert("end", "No specific anomalous behaviors detected.")

        # בדיקה האם הקובץ מסוכן, ואם כן - הקפצת התראת מחיקה
        if verdict in ["MALICIOUS", "SUSPICIOUS"]:
            self.after(500, self.prompt_deletion)

    def prompt_deletion(self):
        target_file = self.controller.target_file_path
        if target_file and os.path.exists(target_file):
            response = messagebox.askyesno(
                "Threat Detected",
                f"The scanned file poses a threat to your system.\n\nDo you want to permanently delete it?\n\nFile: {os.path.basename(target_file)}"
            )
            
            if response: # אם המשתמש בחר כן
                try:
                    os.remove(target_file)
                    messagebox.showinfo("Deleted", "The malicious file has been successfully removed from your system.")
                    self.insights_box.insert("end", "\n\n[+] ACTION TAKEN: The malicious file was deleted by the user.")
                except Exception as e:
                    messagebox.showerror("Deletion Failed", f"Failed to delete the file. It might be running or require administrator privileges.\n\nError: {e}")

if __name__ == "__main__":
    app = MalwareDetectionApp()
    app.mainloop()