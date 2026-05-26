import requests
import os
import time
import base64

class VirusTotalAPI:
    def __init__(self, keys_file_path=r"keys\project_keys.txt"):
        self.base_url = "https://www.virustotal.com/api/v3"
        self.api_keys = self._load_keys(keys_file_path)
        self.current_key_index = 0
        self.request_count = 0
        
        if not self.api_keys:
            print("[-] VirusTotal API: No keys loaded. API will be disabled.")

    def _load_keys(self, file_path):
        """קוראת את מפתחות ה-API מתוך קובץ הטקסט"""
        keys = []
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                for line in file:
                    key = line.strip()
                    if key: # מוודא שהשורה לא ריקה
                        keys.append(key)
            print(f"[*] VirusTotal API: Successfully loaded {len(keys)} API keys.")
        else:
            print(f"[-] VirusTotal API Error: Keys file not found at {file_path}")
        return keys

    def _get_headers(self):
        """מייצרת את הכותרות לבקשה עם המפתח הנוכחי הפעיל"""
        if not self.api_keys:
            return None
        current_key = self.api_keys[self.current_key_index]
        return {
            "accept": "application/json",
            "x-apikey": current_key
        }

    def _prepare_request(self):
        """מנהלת את רוטציית המפתחות לפני כל בקשה"""
        if not self.api_keys:
            return False
            
        # VirusTotal מאפשר 4 בקשות לדקה בחינם. נתחלף אחרי 3 ליתר ביטחון.
        if self.request_count >= 3:
            self.current_key_index += 1
            self.request_count = 0
            
            # אם נגמרו לנו כל המפתחות, חוזרים להתחלה ועושים השהייה
            if self.current_key_index >= len(self.api_keys):
                print("[!] VirusTotal API: All keys exhausted for this minute. Resetting to first key and waiting 60 seconds...")
                time.sleep(60)
                self.current_key_index = 0
            else:
                print(f"[*] VirusTotal API: Switching to API Key #{self.current_key_index + 1}...")

        self.request_count += 1
        return True

    def check_file_hash(self, file_hash):
        """בדיקת Hash של קובץ או סקשן מול VirusTotal"""
        if not self._prepare_request():
            return None
            
        print(f"[*] VirusTotal API: Checking file hash: {file_hash}")
        url = f"{self.base_url}/files/{file_hash}"
        headers = self._get_headers()
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                print("[+] VirusTotal API: Hash not found in their database.")
                return "unknown"
                
            elif response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious_votes = stats.get('malicious', 0)
                
                print(f"[*] VirusTotal API Results: {malicious_votes} Engines detected as malicious.")
                
                if malicious_votes > 0:
                    return "malicious"
                else:
                    return "safe"
            else:
                print(f"[-] VirusTotal API Error: Received status code {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"[-] VirusTotal API Network Error: {e}")
            return None

    def check_ip_url(self, ioc_value, ioc_type):
        """
        בדיקת כתובת רשת.
        IP הולך ל- /ip_addresses/{ip}
        URL מחייב קידוד Base64 לפני השליחה ל- /urls/{url_id}
        """
        if not self._prepare_request():
            return None
            
        print(f"[*] VirusTotal API: Checking {ioc_type.upper()}: {ioc_value}")
        headers = self._get_headers()
        
        try:
            if ioc_type == 'ip':
                url = f"{self.base_url}/ip_addresses/{ioc_value}"
            elif ioc_type == 'url':
                # VirusTotal דורש קידוד Base64 בטוח לכתובות URL
                url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
                url = f"{self.base_url}/urls/{url_id}"
            else:
                return None

            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                return "unknown"
            elif response.status_code == 200:
                stats = response.json()['data']['attributes']['last_analysis_stats']
                if stats.get('malicious', 0) > 0:
                    return "malicious"
                return "safe"
            else:
                print(f"[-] VirusTotal API Error: Status {response.status_code}")
                return None
                
        except Exception as e:
            print(f"[-] VirusTotal API Network Error: {e}")
            return None