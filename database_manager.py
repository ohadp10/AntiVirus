import pymysql
from dotenv import load_dotenv
import os
import json

load_dotenv()

class DatabaseManager:
    def __init__(self):
        self.config = {
            'host': '127.0.0.1',
            'user': 'root',
            'password': os.getenv("db_password"),
            'database': 'malware_detection', 
            'connect_timeout': 3
        }
        self.connection = None
        self.cursor = None

    def open_connection(self):
        try:
            self.connection = pymysql.connect(**self.config)
            self.cursor = self.connection.cursor()
            print("[*] Database: Connection opened successfully.")
        except pymysql.MySQLError as err:
            print(f"[-] Database Error (on open): {err}")
        except Exception as err:
            print(f"[-] FATAL Database Error: {err}")

    def close_connection(self):
        try:
            if self.cursor:
                self.cursor.close()
            if self.connection and self.connection.open:
                self.connection.close()
                print("[*] Database: Connection closed successfully.")
        except pymysql.MySQLError as err:
            print(f"[-] Database Error (on close): {err}")
        finally:
            self.cursor = None
            self.connection = None

    def check_hash_file(self, file_hash):
        """
        בודקת בטבלת known_hashes האם ה-Hash של הקובץ קיים.
        """
        print(f"[*] Database: Checking file hash: {file_hash}")
        
        self.open_connection()
        
        if not self.connection or not self.connection.open:
            print("[-] Database: Cannot execute query without an active connection.")
            return None
            
        try:
            query = "SELECT verdict FROM known_hashes WHERE hash = %s"
            self.cursor.execute(query, (file_hash,))
            result = self.cursor.fetchone()
            
            if result:
                return result[0]
            return None
            
        except pymysql.MySQLError as err:
            print(f"[-] Database Query Error: {err}")
            return None
            
        finally:
            self.close_connection()
        

    def check_section_hash(self, section_name, section_hash):
        """
        בודקת בטבלת known_section_hashes האם השילוב של שם הסקשן וה-Hash שלו קיים.
        מחזירה 'safe', 'malicious' או None אם לא נמצא.
        """
        print(f"[*] Database: Checking section '{section_name}' with hash: {section_hash}")
        
        
        if not self.connection or not self.connection.open:
            print("[-] Database: Cannot execute query without an active connection.")
            return None
            
        try:
            # השאילתה דורשת התאמה גם של השם וגם של החתימה
            query = "SELECT verdict FROM known_section_hashes WHERE name = %s AND hash = %s"
            self.cursor.execute(query, (section_name, section_hash))
            result = self.cursor.fetchone()
            
            if result:
                verdict = result[0]
                print(f"[+] Database: Section '{section_name}' match found! Verdict: {verdict}")
                return verdict
                
            return None
            
        except pymysql.MySQLError as err:
            print(f"[-] Database Query Error (Section Hash): {err}")
            return None
            
    def check_ips_urls(self, ioc_value, ioc_type):
        """
        בודקת בטבלת known_iocs האם קיים אינדיקטור (IP או URL) לפי הסוג והערך שלו.
        מחזירה 'safe', 'malicious' או None אם לא נמצא.
        """
        print(f"[*] Database: Checking IOC ({ioc_type}): {ioc_value}")
        
        if not self.connection or not self.connection.open:
            print("[-] Database: Cannot execute query without an active connection.")
            return None
            
        try:
            # השאילתה בודקת התאמה גם של הערך וגם של הסוג (IP/URL)
            query = "SELECT verdict FROM known_iocs WHERE value = %s AND type = %s"
            self.cursor.execute(query, (ioc_value, ioc_type))
            result = self.cursor.fetchone()
            
            if result:
                verdict = result[0]
                print(f"[+] Database: IOC match found! Verdict: {verdict}")
                return verdict
                
            return None
            
        except pymysql.MySQLError as err:
            print(f"[-] Database Query Error (IOC Check): {err}")
            return None
        
    def save_scan_report(self, file_name, file_hash, threat_score, final_verdict, insights, dynamic_logs):
        """
        שומרת את תוצאות הסריקה המלאות (סטטי, דינמי והיוריסטי) לטבלת scan_history.
        """
        print(f"[*] Database: Saving scan report for '{file_name}'...")
        
        self.open_connection()
        if not self.connection or not self.connection.open:
            print("[-] Database: Cannot execute query without an active connection.")
            return False
            
        try:
            # המרת הרשימות של פייתון לפורמט JSON מובנה (String) ש-MySQL יודע לשמור
            # ensure_ascii=False מוודא שאם יש טקסט בעברית או תווים מיוחדים, הם יישמרו כראוי
            insights_json = json.dumps(insights, ensure_ascii=False) if insights else "[]"
            dynamic_logs_json = json.dumps(dynamic_logs, ensure_ascii=False) if dynamic_logs else "[]"
            
            # בניית שאילתת ההכנסה
            query = """
                INSERT INTO scan_history 
                (file_name, file_hash, threat_score, final_verdict, insights, dynamic_logs) 
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            # מיפוי הערכים לשאילתה
            values = (file_name, file_hash, threat_score, final_verdict, insights_json, dynamic_logs_json)
            
            # ביצוע השאילתה ושמירה סופית
            self.cursor.execute(query, values)
            self.connection.commit() 
            
            print("[+] Database: Scan report saved successfully to 'scan_history' table.")
            return True
            
        except pymysql.MySQLError as err:
            print(f"[-] Database Insert Error (Scan History): {err}")
            self.connection.rollback() # במקרה של שגיאה, מבטלים את הפעולה כדי לא לפגוע במסד הנתונים
            return False
            
        finally:
            self.close_connection()

    def add_to_known_hashes(self, file_hash, final_verdict):
        """
        מוסיף חתימה לטבלת known_hashes כדי שהמערכת "תלמד" לפעמים הבאות.
        תומך ב-SAFE, SUSPICIOUS ו-MALICIOUS.
        """
        # ממירים לאותיות קטנות כדי שיתאים ל-ENUM במסד הנתונים
        verdict_lower = final_verdict.lower()
        
        # מוודאים שהערך תקין (אחד משלושת המצבים שלנו)
        if verdict_lower not in ['safe', 'suspicious', 'malicious']:
            print(f"[-] Database: Unknown verdict '{final_verdict}', skipping auto-learning.")
            return False
            
        print(f"[*] Database: Auto-learning - Adding hash to known_hashes as '{verdict_lower}'...")
        
        self.open_connection()
        if not self.connection or not self.connection.open:
            print("[-] Database: Cannot execute query without an active connection.")
            return False
            
        try:
            # שימוש ב- INSERT IGNORE כדי שלא תקפוץ שגיאה אם החתימה כבר נלמדה בעבר
            query = "INSERT IGNORE INTO known_hashes (hash, verdict) VALUES (%s, %s)"
            self.cursor.execute(query, (file_hash, verdict_lower))
            self.connection.commit()
            
            # בדיקה אם באמת התווספה שורה חדשה או שהחתימה כבר הייתה קיימת
            if self.cursor.rowcount > 0:
                print(f"[+] Database: Hash successfully learned and added to known_hashes!")
            else:
                print(f"[*] Database: Hash already exists in known_hashes. No changes made.")
            return True
            
        except pymysql.MySQLError as err:
            print(f"[-] Database Insert Error (Known Hashes): {err}")
            self.connection.rollback()
            return False
            
        finally:
            self.close_connection()

    def learn_section_hashes(self, section_hashes_dict, final_verdict):
        """
        לומד חתימות של מקטעים (Sections) מתוך קובץ שנסרק.
        מעדכן בטבלת known_section_hashes רק מקטעים שהיו unknown.
        """
        verdict_lower = final_verdict.lower()
        
        # שוב, לומדים רק מקבצים שאנחנו בטוחים לגביהם (שחור או לבן)
        if verdict_lower not in ['safe', 'malicious']:
            return False
            
        self.open_connection()
        if not self.connection or not self.connection.open:
            print("[-] Database: Cannot execute query without an active connection.")
            return False
            
        try:
            added_count = 0
            # עוברים על כל הסקשנים במילון התוצאות
            for sec_name, data in section_hashes_dict.items():
                # מעדכנים רק מקטעים שהיו unknown (כלומר לא היו מוכרים למערכת עד עכשיו)
                if data.get("status") == "unknown":
                    sec_hash = data.get("hash")
                    
                    # INSERT IGNORE מונע קריסה אם במקרה המקטע כבר קיים
                    query = "INSERT IGNORE INTO known_section_hashes (name, hash, verdict) VALUES (%s, %s, %s)"
                    self.cursor.execute(query, (sec_name, sec_hash, verdict_lower))
                    
                    if self.cursor.rowcount > 0:
                        added_count += 1
                        
            self.connection.commit()
            
            if added_count > 0:
                print(f"[+] Database: Auto-learning - Successfully learned {added_count} new section hashes as '{verdict_lower}'.")
            else:
                print(f"[*] Database: No new section hashes to learn (all were already known).")
                
            return True
            
        except pymysql.MySQLError as err:
            print(f"[-] Database Insert Error (Section Hashes): {err}")
            self.connection.rollback()
            return False
            
        finally:
            self.close_connection()

    def learn_network_iocs(self, network_iocs_dict):
        """
        לומד אינדיקטורים של רשת (IPs ו-URLs) מתוך מילון התוצאות של הניתוח הסטטי.
        מעדכן בטבלת known_iocs רק אינדיקטורים שסווגו בוודאות כ-'safe' או 'malicious' (לרוב ע"י VirusTotal).
        """
        if not network_iocs_dict:
            return False
            
        self.open_connection()
        if not self.connection or not self.connection.open:
            print("[-] Database: Cannot execute query without an active connection.")
            return False
            
        try:
            added_count = 0
            # עוברים על כל האינדיקטורים במילון (מפתח = כתובת, ערך = סוג וסטטוס)
            for ioc_value, data in network_iocs_dict.items():
                ioc_type = data.get("type")
                status = data.get("status", "unknown").lower()
                
                # לומדים ושומרים רק אם הסטטוס מוחלט ולא unknown
                if status in ['safe', 'malicious']:
                    # INSERT IGNORE יכניס את הרשומה רק אם היא לא קיימת כבר בטבלה
                    query = "INSERT IGNORE INTO known_iocs (value, type, verdict) VALUES (%s, %s, %s)"
                    self.cursor.execute(query, (ioc_value, ioc_type, status))
                    
                    if self.cursor.rowcount > 0:
                        added_count += 1
                        
            self.connection.commit()
            
            if added_count > 0:
                print(f"[+] Database: Auto-learning - Successfully learned {added_count} new network IOCs (IPs/URLs).")
            else:
                print(f"[*] Database: No new network IOCs to learn (all were already known or unknown).")
                
            return True
            
        except pymysql.MySQLError as err:
            print(f"[-] Database Insert Error (Network IOCs): {err}")
            self.connection.rollback()
            return False
            
        finally:
            self.close_connection()