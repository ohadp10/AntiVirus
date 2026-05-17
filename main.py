import os
import shutil
import subprocess
import time
from static_analyzer import StaticAnalyzer
from database_manager import DatabaseManager
from local_dynamic import LocalDynamicAnalyzer
from dynamic_analyzer import CloudDynamicAnalyzer # מוכן לפעולה עתידית

if __name__ == "__main__":
    file_path = r"C:\path\to\your\dist\dummy_virus.exe" 
    USE_CLOUD = False # מתג שליטה: כרגע עובדים לוקאלית. כשיש AWS, נשנה ל-True.

    db = DatabaseManager()

    if os.path.exists(file_path):
        print("\n" + "="*50)
        print(f" SCANNING FILE: {os.path.basename(file_path)}")
        print("="*50)
        
        analyzer = StaticAnalyzer(file_path)
        
        print(f"[*] Calculating SHA256 Hash...")
        analyzer.calculateHash()
        
        if analyzer.checkMagicNumber():
            analyzer.analyzeHeader()
            analyzer.analyzeEntryPoint()
            analyzer.analyzeSections()
            analyzer.checkForPacking()
            analyzer.extractStrings()
            analyzer.analyzeAssembly()
            
            print("\n[*] Evaluating threat intelligence...")
            verdict, reasons = db.evaluate_threat(analyzer.results)
            
            if analyzer.results.get("header_warnings") and verdict == "Safe":
                verdict = "Suspicious"
                reasons.append("Marked as Suspicious due to PE Header anomalies")

            print(f"\n[i] Static Analysis Verdict: {verdict}")
            
            # --- שלב הניתוח הדינמי ---
            if verdict == "Suspicious":
                print("\n" + "!"*50)
                print("[!] FILE IS SUSPICIOUS! Launching Dynamic Sandbox Analysis...")
                print("!"*50)
                
                if USE_CLOUD:
                    # שימוש במערכת הענן (מוכן לפעולה כשיהיו מפתחות)
                    cloud_sandbox = CloudDynamicAnalyzer(file_path)
                    dynamic_logs = cloud_sandbox.run_analysis()
                else:
                    # שימוש במערכת המקומית
                    sandbox_folder = r"C:\Temp\SandboxTest"
                    sandbox_file_path = os.path.join(sandbox_folder, os.path.basename(file_path))
                    shutil.copy(file_path, sandbox_file_path)
                    
                    local_sandbox = LocalDynamicAnalyzer(sandbox_dir=sandbox_folder)
                    local_sandbox.start_monitoring()
                    
                    print(f"[*] Executing {os.path.basename(file_path)} inside local sandbox...")
                    process = subprocess.Popen(sandbox_file_path, shell=True)
                    
                    print("[*] Monitoring file and network behavior for 10 seconds...")
                    for _ in range(10):
                        local_sandbox.check_network_activity()
                        time.sleep(1)
                    
                    process.terminate()
                    dynamic_logs = local_sandbox.stop_monitoring()
                
                # קבלת ההחלטה הדינמית
                if len(dynamic_logs) > 0:
                    verdict = "Malicious"
                    reasons.append(f"Dynamic Analysis: Detected {len(dynamic_logs)} suspicious actions")
                else:
                    verdict = "Safe"
                    reasons.append("Dynamic Analysis: No harmful modifications detected")
            
            print("\n" + "#"*40)
            print(f" FINAL INTEGRATED VERDICT: >> {verdict} <<")
            print("#"*40)
            
            if reasons:
                print("\n[i] Combined Indicators:")
                for r in reasons: 
                    print(f"    - {r}")
            
            db.save_scan_results(analyzer.results, verdict)
            print("\n[V] Detailed scan report saved to MySQL.")
        else:
            print("\n[!] Scan aborted: The target is not a valid PE file.")
    else:
        print("\n[!] Error: File path does not exist.")