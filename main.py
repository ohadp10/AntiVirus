import os
from static_analyzer import StaticAnalyzer
from database_manager import DatabaseManager

if __name__ == "__main__":
    file_path = r"C:\Windows\System32\notepad.exe"
    db = DatabaseManager()

    if os.path.exists(file_path):
        print("\n" + "="*50)
        print(f" SCANNING FILE: {os.path.basename(file_path)}")
        print("="*50)
        
        analyzer = StaticAnalyzer(file_path)
        
        # 1. חישוב חתימת הקובץ
        print(f"[*] Calculating SHA256 Hash...")
        analyzer.calculateHash()
        print(f"    Hash: {analyzer.results['hash']}")
        
        # 2. אימות שמדובר בקובץ הרצה תקין (Magic Number)
        if analyzer.checkMagicNumber():
            
            # --- בדיקות ה-Header וה-Entry Point החדשות ---
            analyzer.analyzeHeader()
            analyzer.analyzeEntryPoint()
            
            # --- המשך הבדיקות הקיימות ---
            analyzer.analyzeSections()
            analyzer.checkForPacking()
            analyzer.extractStrings()
            analyzer.analyzeAssembly()
            
            # 3. קבלת החלטה סופית ממנוע החוקים במסד הנתונים
            print("\n[*] Evaluating threat intelligence...")
            verdict, reasons = db.evaluate_threat(analyzer.results)
            
            # הדפסת התוצאה למסך באופן מסודר
            print("\n" + "#"*40)
            print(f" FINAL VERDICT: >> {verdict} <<")
            print("#"*40)
            
            if analyzer.results.get("header_warnings"):
                print("\n[!] Header Anomalies Detected:")
                for warn in analyzer.results["header_warnings"]:
                    print(f"    - {warn}")
            
            if reasons:
                print("\n[i] Detection Indicators:")
                for r in reasons: 
                    print(f"    - {r}")
            
            if analyzer.results.get("found_ips"):
                print(f"\n[+] Extracted IPs: {analyzer.results['found_ips']}")
                
            if analyzer.results.get("found_urls"):
                print(f"\n[+] Extracted URLs: {analyzer.results['found_urls']}")

            # 4. שמירת כל תוצאות הסריקה המפורטות ל-DB
            db.save_scan_results(analyzer.results, verdict)
            print("\n[V] Detailed scan report saved to MySQL.")
            
        else:
            print("\n[!] Scan aborted: The target is not a valid Portable Executable (PE) file.")
    else:
        print("\n[!] Error: File path does not exist.")