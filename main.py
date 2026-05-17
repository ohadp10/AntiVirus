import os
import shutil
import subprocess
import time
from static_analyzer import StaticAnalyzer
from database_manager import DatabaseManager
from dynamic_analyzer import DynamicAnalyzer

if __name__ == "__main__":
    # עדכן פה את הנתיב ל-exe החדש שלך!
    file_path = r"C:\Users\user\Desktop\MalwareDetection\dist\dummy_virus.exe" 
    db = DatabaseManager()

    if os.path.exists(file_path):
        print("\n" + "="*50)
        print(f" SCANNING FILE: {os.path.basename(file_path)}")
        print("="*50)
        
        analyzer = StaticAnalyzer(file_path)
        
        print(f"[*] Calculating SHA256 Hash...")
        analyzer.calculateHash()
        print(f"    Hash: {analyzer.results['hash']}")
        
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
            
            # שלב הניתוח הדינמי
            if verdict == "Suspicious":
                print("\n" + "!"*50)
                print("[!] FILE IS SUSPICIOUS! Launching Dynamic Sandbox Analysis...")
                print("!"*50)
                
                sandbox_folder = r"C:\Temp\SandboxTest"
                sandbox_file_path = os.path.join(sandbox_folder, os.path.basename(file_path))
                
                shutil.copy(file_path, sandbox_file_path)
                dynamic = DynamicAnalyzer(sandbox_dir=sandbox_folder)
                
                dynamic.start_monitoring()
                
                print(f"[*] Executing {os.path.basename(file_path)} inside sandbox...")
                process = subprocess.Popen(sandbox_file_path, shell=True)
                
                print("[*] Monitoring file and network behavior for 10 seconds...")
                # פה השינוי: במקום לישון 10 שניות, אנחנו בודקים את הרשת כל שנייה!
                for _ in range(10):
                    dynamic.check_network_activity()
                    time.sleep(1)
                
                process.terminate()
                dynamic_logs = dynamic.stop_monitoring()
                
                if len(dynamic_logs) > 0:
                    verdict = "Malicious"
                    reasons.append(f"Dynamic Analysis: Detected {len(dynamic_logs)} suspicious actions (Files/Network)")
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
            print("\n[!] Scan aborted: The target is not a valid Portable Executable (PE) file.")
    else:
        print("\n[!] Error: File path does not exist.")