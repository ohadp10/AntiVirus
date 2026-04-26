import os
from static_analyzer import StaticAnalyzer
from database_manager import DatabaseManager 

if __name__ == "__main__":
    fileToCheck = r"C:\Windows\System32\notepad.exe"

    print("Initializing Database...")
    db = DatabaseManager()

    if os.path.exists(fileToCheck):
        print(f"\n--- Starting Static Analysis for: {fileToCheck} ---")
        analyzer = StaticAnalyzer(fileToCheck)
        
        analyzer.calculateHash()
        analyzer.checkMagicNumber()
        
        if analyzer.results["is_pe"]:
            analyzer.analyzeSections()
            analyzer.checkForPacking()
            analyzer.extractStrings()
            analyzer.analyzeAssembly()
            
            print("\n=== STATIC ANALYSIS COMPLETE ===")
            print("Querying Threat Intelligence Database...")
            
            # --- הוספנו כאן את מנוע ההחלטות! ---
            verdict, reasons = db.evaluate_threat(analyzer.results)
            
            print("\n" + "="*40)
            print(f" FINAL VERDICT: >> {verdict.upper()} <<")
            print("="*40)
            print("Reasons/Indicators:")
            for r in reasons:
                print(f" - {r}")
            print("="*40)
            
            # שמירת התוצאות הסופיות (כולל הפסיקה) ל-DB
            db.save_scan_results(analyzer.results, verdict)
            print("\n[V] Full report saved to Database.")
            
        else:
            print("Scan aborted: Not a valid PE file.")
    else:
        print("File not found.")