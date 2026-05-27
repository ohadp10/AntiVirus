import pymysql
from dotenv import load_dotenv
import os

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