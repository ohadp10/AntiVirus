import os
from static_analyzer import StaticAnalyzer
from database_manager import DatabaseManager

if __name__ == "__main__":
    # נתיב הקובץ לבדיקה
    file_path = r"C:\Windows\System32\notepad.exe"
    
    # אתחול מנהל מסד הנתונים (וודא שהגדרת סיסמה בתוך המחלקה או פה)
    db = DatabaseManager()

    if os.path.exists(file_path):
        print(f"--- Starting Scan: {file_path} ---")
        analyzer = StaticAnalyzer(file_path)
        
        # 1. חישוב חתימת הקובץ
        analyzer.calculateHash()
        
        # 2. אימות שמדובר בקובץ הרצה תקין (Magic Number)
        if analyzer.checkMagicNumber():
            
            # --- בדיקות ה-Header וה-Entry Point החדשות ---
            # בדיקת תקינות הכותרות (תאריך, גודל וכו')
            analyzer.analyzeHeader()
            
            # בדיקה שנקודת הכניסה של הקוד לגיטימית
            analyzer.analyzeEntryPoint()
            
            # --- המשך הבדיקות הקיימות ---
            # ניתוח סקשנים וחישוב האש לכל אחד בנפרד[cite: 1]
            analyzer.analyzeSections()
            
            # בדיקה אם הקובץ דחוס (UPX וכדומה)[cite: 1]
            analyzer.checkForPacking()
            
            # חילוץ מחרוזות, IPs, ופענוח Base64/XOR[cite: 1]
            analyzer.extractStrings()
            
            # ניתוח קוד אסמבלי (Heuristics)[cite: 1]
            analyzer.analyzeAssembly()
            
            # 3. קבלת החלטה סופית ממנוע החוקים במסד הנתונים[cite: 1]
            verdict, reasons = db.evaluate_threat(analyzer.results)
            
            # הדפסת התוצאה למסך
            print("\n" + "="*30)
            print(f" VERDICT: {verdict}")
            print("="*30)
            
            # הדפסת האזהרות מה-Header אם קיימות
            if analyzer.results.get("header_warnings"):
                for warn in analyzer.results["header_warnings"]:
                    print(f" [!] Header Warning: {warn}")
            
            # הדפסת סיבות הפסיקה
            for r in reasons: 
                print(f" - {r}")
            
            # 4. שמירת כל תוצאות הסריקה המפורטות ל-DB[cite: 1]
            db.save_scan_results(analyzer.results, verdict)
            print("\n[V] Scan completed and saved to database.")
            
        else:
            print("Scan aborted: Not a valid PE file.")
    else:
        print("File not found.")