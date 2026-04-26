import os
from static_analyzer import StaticAnalyzer
from database_manager import DatabaseManager

if __name__ == "__main__":
    file_path = r"C:\Windows\System32\notepad.exe"
    db = DatabaseManager()

    if os.path.exists(file_path):
        print(f"--- Starting Scan: {file_path} ---")
        analyzer = StaticAnalyzer(file_path)
        
        analyzer.calculateHash()
        if analyzer.checkMagicNumber():
            analyzer.analyzeSections()
            analyzer.checkForPacking()
            analyzer.extractStrings()
            analyzer.analyzeAssembly()
            
            verdict, reasons = db.evaluate_threat(analyzer.results)
            
            print("\n" + "="*30)
            print(f" VERDICT: {verdict}")
            print("="*30)
            for r in reasons: print(f" - {r}")
            
            db.save_scan_results(analyzer.results, verdict)
            print("\n[V] Scan completed and saved.")
        else:
            print("Not a valid PE file.")
    else:
        print("File not found.")