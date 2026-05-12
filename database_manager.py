import pymysql
import json
import requests
import time

#יצירת מחלקה של מנהל מסד הנתונים
class DatabaseManager:
    def __init__(self, host="127.0.0.1", user="root", password="ohadp2006"):
        self.host = host
        self.user = user
        self.password = password
        self.database_name = "malware_detection_db"
        # המפתח האישי שלך ל-VirusTotal
        self.api_key = "YOUR_API_KEY_HERE" 

    def connect(self):
        return pymysql.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database_name,
            charset='utf8mb4'
        )

    def check_virustotal_hash(self, file_hash):
        """בודק את חתימת הקובץ ב-VirusTotal"""
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"accept": "application/json", "x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return stats['malicious']
            return 0
        except: return 0

    def check_virustotal_ip(self, ip):
        """בדיקת כתובת IP ב-VirusTotal"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return stats['malicious']
            return 0
        except: return 0

    def check_virustotal_url(self, target_url):
        """בדיקת URL ב-VirusTotal"""
        import base64
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"accept": "application/json", "x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                return stats['malicious']
            return 0
        except: return 0

    #מחליט האם הקובץ לגיטימי או לא
    def evaluate_threat(self, results_dict):
        verdict = "Unknown"
        reasons = []
        
        # בדיקה ב-VirusTotal ל-Hash
        vt_hash_res = self.check_virustotal_hash(results_dict['hash'])
        if vt_hash_res > 0:
            reasons.append(f"VirusTotal: {vt_hash_res} engines flagged this Hash")
            verdict = "Malicious"

        # בדיקה ב-VirusTotal לכתובות IP שנמצאו
        for ip in results_dict.get('found_ips', []):
            vt_ip_res = self.check_virustotal_ip(ip)
            if vt_ip_res > 0:
                reasons.append(f"VirusTotal: IP {ip} flagged by {vt_ip_res} engines")
                verdict = "Malicious"

        # בדיקה ב-VirusTotal לכתובות URL שנמצאו
        for target_url in results_dict.get('found_urls', []):
            vt_url_res = self.check_virustotal_url(target_url)
            if vt_url_res > 0:
                reasons.append(f"VirusTotal: URL {target_url} flagged by {vt_url_res} engines")
                verdict = "Malicious"

        try:
            conn = self.connect()
            with conn.cursor() as cursor:
                # בדיקת Hash 
                cursor.execute("SELECT status, description FROM known_hashes WHERE file_hash = %s", (results_dict['hash'],))
                res = cursor.fetchone()
                if res:
                    return res[0].capitalize(), [f"Recognized Hash: {res[1]}"]

                # בדיקה מול מאגר IOCs מקומי
                for ip in results_dict.get('found_ips', []):
                    cursor.execute("SELECT description FROM known_iocs WHERE indicator = %s", (ip,))
                    if cursor.fetchone():
                        verdict = "Malicious"
                        reasons.append(f"Blacklisted IP (Local DB): {ip}")

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