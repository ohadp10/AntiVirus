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

    
    if static_analyzer.begin_analyzing() != True:
        cloud_logs = dynamic_analyzer.run_analysis()

        engine = HeuristicRuleEngine(static_analyzer.results, cloud_logs)
        final_report = engine.calculate_threat_score()

    file_hash = static_analyzer.results.get("file_hash", "")
    section_hashes = static_analyzer.results.get("section_hashes", {})
    network_iocs = static_analyzer.results.get("network_iocs", {})
    verdict = final_report["final_verdict"]

    # 1. שמירת דו"ח הסריקה המלא לתיעוד (Audit)
    db_manager.save_scan_report(
        file_name=os.path.basename(target_file_path),
        file_hash=static_analyzer.results["file_hash"],
        threat_score=final_report["threat_score"],
        final_verdict=final_report["final_verdict"],
        insights=final_report["insights"],
        dynamic_logs=cloud_logs
    )

    # 2. הוספת החתימה הראשית למאגר (Auto-Learning)
    if file_hash:
        db_manager.add_to_known_hashes(file_hash, verdict)
        
    # 3. הוספת חתימות המקטעים למאגר (Verdict Inheritance)
    if section_hashes:
        db_manager.learn_section_hashes(section_hashes, verdict)
        
    # 4. הוספת אינדיקטורים של רשת (IOCs) למאגר
    if network_iocs:
        db_manager.learn_network_iocs(network_iocs)

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