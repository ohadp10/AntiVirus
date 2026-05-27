import os
from static_analyzer import StaticAnalyzer
from database_manager import DatabaseManager
from dynamic_analyzer import DynamicAnalyzer
from heuristic_engine import HeuristicRuleEngine
from virus_total_api import VirusTotalAPI

def main():
    print("="*60)
    print("         Malware Detection")
    print("="*60)

    # 1. הגדרת נתיב הקובץ לסריקה (תוכל לשנות פה לכל קובץ שתרצה לבדוק)
    target_file_path = r"C:\Users\user\Desktop\MalwareDetection\dist\advanced_dummy_virus.exe"
    
    # וידוא בסיסי שהקובץ קיים לפני שמתחילים
    if not os.path.exists(target_file_path):
        print(f"[!] Error: The target file was not found at: {target_file_path}")
        return

    print(f"[*] Target File: {target_file_path}")

    db_manager = DatabaseManager()
    vt_api = VirusTotalAPI()
    static_analyzer = StaticAnalyzer(target_file_path, db_manager, vt_api)
    dynamic_analyzer = DynamicAnalyzer(target_file_path)

    
    static_analyzer.begin_analyzing()
    cloud_logs = dynamic_analyzer.run_analysis()

    engine = HeuristicRuleEngine(static_analyzer.results, cloud_logs)
    final_report = engine.calculate_threat_score()

    print("="*45)
    print("--- FINAL VERDICT & THREAT SCORE ---")
    print("="*45)
    print(f"[*] Threat Score: {final_report['threat_score']}/100")
    print(f"[*] Verdict: {final_report['final_verdict']}")
    
    print("\n--- DETAILED INSIGHTS ---")
    if final_report["insights"]:
        for insight in final_report["insights"]:
            print(f" -> {insight}")
    else:
        print(" -> No specific suspicious insights found.")


    print("\n--- RAW DYNAMIC DATA (From Cloud Sandbox) ---")
    if cloud_logs:
        for log in cloud_logs:
            print(f" * {log}")
    else:
        print(" * No dynamic logs received or execution failed.")
        
    print("\n--- RAW STATIC DATA (For Debugging) ---")
    for key, value in static_analyzer.results.items():
        print(f" * {key}: {value}")

    # === מנגנון הכלה ונטרול (Remediation) ===
    score = final_report['threat_score']
    
    if score >= 40:
        print("\n" + "="*45)
        if score >= 75:
            print("[!!!] CRITICAL ALERT: The file is classified as MALICIOUS.")
        else:
            print("[!] WARNING: The file is classified as SUSPICIOUS.")
            
        # שואל את המשתמש אם למחוק את הקובץ
        user_choice = input(f"[*] Do you want to safely delete '{target_file_path}'? (Y/N): ").strip().lower()
        
        if user_choice == 'y':
            try:
                os.remove(target_file_path)
                print(f"[+] Success: The file was permanently deleted from the system.")
            except Exception as e:
                print(f"[-] Error: Could not delete the file. It might be running or locked. ({e})")
        else:
            print("[*] User opted to keep the file. Proceed with caution.")


if __name__ == "__main__":
    main()