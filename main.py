import os
from static_analyzer import StaticAnalyzer
from database_manager import DatabaseManager
from virus_total_api import VirusTotalAPI

def main():
    print("="*60)
    print("         Malware Detection")
    print("="*60)

    # 1. הגדרת נתיב הקובץ לסריקה (תוכל לשנות פה לכל קובץ שתרצה לבדוק)
    target_file_path = r"C:\Users\user\Desktop\MalwareDetection\dist\dummy_virus.exe" 
    
    # וידוא בסיסי שהקובץ קיים לפני שמתחילים
    if not os.path.exists(target_file_path):
        print(f"[!] Error: The target file was not found at: {target_file_path}")
        return

    print(f"[*] Target File: {target_file_path}")

    db_manager = DatabaseManager()
    vt_api = VirusTotalAPI()
    static_analyzer = StaticAnalyzer(target_file_path, db_manager, vt_api)
    
    static_analyzer.begin_analyzing()
    
    print("\n>>> PIPELINE FINISHED <<<\n")
    print("--- FINAL COMPILED RESULTS ---")
    for key, value in static_analyzer.results.items():
        print(f" * {key}: {value}")

if __name__ == "__main__":
    main()