import pymysql
import json

#יצירת מחלקה של מנהל מסד הנתונים
class DatabaseManager:
    def __init__(self, host="127.0.0.1", user="root", password="ohadp2006"):
        self.host = host
        self.user = user
        self.password = password
        self.database_name = "malware_detection_db"

    def connect(self):
        return pymysql.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database_name,
            charset='utf8mb4'
        )

    #מחליט האם הקובץ לגיטימי או לא
    def evaluate_threat(self, results_dict):
        verdict = "Unknown"
        reasons = []
        try:
            conn = self.connect()
            with conn.cursor() as cursor:
                # בדיקת Hash 
                cursor.execute("SELECT status, description FROM known_hashes WHERE file_hash = %s", (results_dict['hash'],))
                res = cursor.fetchone()
                if res:
                    return res[0].capitalize(), [f"Recognized Hash: {res[1]}"]

                # בדיקת IPs
                for ip in results_dict.get('found_ips', []):
                    cursor.execute("SELECT description FROM known_iocs WHERE indicator = %s", (ip,))
                    if cursor.fetchone():
                        verdict = "Malicious"
                        reasons.append(f"Blacklisted IP: {ip}")

                if results_dict['is_packed']: reasons.append("File is packed (UPX/Other)")
                if results_dict['assembly_score'] > 15: reasons.append("High assembly risk score")
                
                if not reasons: verdict = "Safe"
                elif verdict != "Malicious": verdict = "Suspicious"
                
                return verdict, reasons
        except Exception as e:
            return "Error", [str(e)]

    #שומר את תוצאות הסריקה במסד נתונים
    def save_scan_results(self, results_dict, final_verdict):
        try:
            conn = self.connect()
            with conn.cursor() as cursor:
                # 1. שמירה בטבלה ראשית
                sql = """INSERT INTO scan_results 
                         (file_hash, is_pe, sections_ok, is_packed, assembly_score, found_ips, found_urls, final_verdict, decoded_strings) 
                         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
                
                cursor.execute(sql, (
                    results_dict['hash'], results_dict['is_pe'], results_dict['sections_ok'],
                    results_dict['is_packed'], results_dict['assembly_score'],
                    json.dumps(results_dict['found_ips']), json.dumps(results_dict['found_urls']),
                    final_verdict, json.dumps(results_dict['decoded_strings'])
                ))
                
                scan_id = cursor.lastrowid
                
                # 2. שמירת האשים של סקשנים
                for s_name, s_hash in results_dict['section_hashes'].items():
                    cursor.execute("INSERT INTO section_hashes (scan_id, section_name, section_hash) VALUES (%s, %s, %s)",
                                   (scan_id, s_name, s_hash))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"DB Save Error: {e}")