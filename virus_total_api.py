import requests

class VirusTotalAPI:
    def __init__(self):
        # הכנס כאן את מפתח ה-API שלך מ-VirusTotal
        self.api_key = "dadf49d702ed3657fd14ff940abc703300b9f6fe175c3868a41a8ae26840b718"
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def check_file_hash(self, file_hash):
        print(f"[*] VirusTotal API: Checking file hash: {file_hash}")
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 404:
                print("[+] VirusTotal API: Hash not found in their database.")
                return "unknown"
                
            # אם הבקשה הצליחה
            elif response.status_code == 200:
                data = response.json()
                
                # שליפת סטטיסטיקת ההצבעות של מנועי האנטי-וירוס
                stats = data['data']['attributes']['last_analysis_stats']
                malicious_votes = stats.get('malicious', 0)
                harmless_votes = stats.get('harmless', 0)
                undetected_votes = stats.get('undetected', 0)
                
                print(f"[*] VirusTotal API Results: {malicious_votes} Engines detected as malicious.")
                
                # הגדרת סף: אם אפילו מנוע אחד זיהה את זה כזדוני (או אפשר לשנות ליותר)
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