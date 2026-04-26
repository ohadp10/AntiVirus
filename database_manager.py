import pymysql
import json

class DatabaseManager:
    def __init__(self, host="127.0.0.1", user="root", password="ohadp2006"):
        self.host = host
        self.user = user
        self.password = password
        self.database_name = "malware_detection_db"

    def connect(self):
        """פונקציית התחברות בסיסית ונקייה למסד הנתונים"""
        return pymysql.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database_name,
            charset='utf8mb4'
        )

    def evaluate_threat(self, results_dict):
        """
        מקבלת את תוצאות הסריקה, בודקת מול מסד הנתונים ומחזירה החלטה סופית.
        """
        verdict = "Suspicious"
        reasons = []
        
        try:
            conn = self.connect()
            with conn.cursor() as cursor:
                # 1. רשימה לבנה/שחורה של קבצים
                file_hash = results_dict.get('hash')
                cursor.execute("SELECT status, description FROM known_hashes WHERE file_hash = %s", (file_hash,))
                hash_result = cursor.fetchone()
                
                if hash_result:
                    if hash_result[0] == 'safe':
                        return "Safe", [f"Hash recognized in Whitelist ({hash_result[1]})"]
                    elif hash_result[0] == 'malicious':
                        return "Malicious", [f"Hash recognized in Blacklist ({hash_result[1]})"]

                # 2. רשימה שחורה של כתובות רשת
                found_ips = results_dict.get('found_ips', [])
                for ip in found_ips:
                    cursor.execute("SELECT description FROM known_iocs WHERE indicator = %s AND type = 'ip'", (ip,))
                    ip_result = cursor.fetchone()
                    if ip_result:
                        verdict = "Malicious"
                        reasons.append(f"Blacklisted IP found: {ip} ({ip_result[0]})")
                
                # 3. כללים היוריסטיים
                if results_dict.get('assembly_score', 0) > 15:
                    reasons.append("High assembly heuristic score (Suspicious flow)")
                if results_dict.get('is_packed', False):
                    reasons.append("File is packed/obfuscated")
                if not results_dict.get('sections_ok', True):
                    reasons.append("Non-standard PE sections detected")

                if len(reasons) == 0:
                    verdict = "Unknown / Low Risk"
                    reasons.append("No suspicious indicators found.")
                
                return verdict, reasons

        except Exception as e:
            print(f"Error evaluating threat: {e}")
            return "Error", [str(e)]
        finally:
            if 'conn' in locals() and conn.open:
                conn.close()

    def save_scan_results(self, results_dict, final_verdict):
        """שומרת את כל הנתונים כולל ההחלטה הסופית ב-DB"""
        try:
            conn = self.connect()
            with conn.cursor() as cursor:
                insert_query = """
                INSERT INTO scan_results 
                (file_hash, is_pe, sections_ok, is_packed, assembly_score, found_ips, found_urls, final_verdict) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """
                ips_str = json.dumps(results_dict.get('found_ips', []))
                urls_str = json.dumps(results_dict.get('found_urls', []))
                data = (
                    results_dict.get('hash'), results_dict.get('is_pe'),
                    results_dict.get('sections_ok'), results_dict.get('is_packed'),
                    results_dict.get('assembly_score'), ips_str, urls_str, final_verdict
                )
                cursor.execute(insert_query, data)
            conn.commit()
        except Exception as e:
            print(f"[!] Error saving to database: {e}")
        finally:
            if 'conn' in locals() and conn.open:
                conn.close()