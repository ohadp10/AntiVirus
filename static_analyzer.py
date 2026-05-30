import pefile
from datetime import datetime 
import math
import subprocess
import os
import hashlib
import re
import base64
import capstone

class StaticAnalyzer:
    def __init__(self, file_path, db_manager=None, vt_api=None):
        self.file_path = file_path
        self.db_manager = db_manager
        self.vt_api = vt_api

        self.results = {
            # --- תוצאות סעיף 1: בדיקת כותרות (PE Headers) ---
            "is_valid_pe": False,          # האם הקובץ הוא באמת קובץ הרצה תקין
            "suspicious_header": False,    # האם מצאנו חריגות בתאריך הקימפול או בגודל הכותרת
            "entry_point": "",             # הכתובת ההקסדצימלית של נקודת הכניסה
            "ep_section": "",              # שם המקטע (Section) שבו נמצאת נקודת הכניסה
            "is_ep_suspicious": False,     # האם נקודת הכניסה נמצאת במקטע לא שגרתי

            # --- תוצאות סעיף 2: ניתוח מקטעים (Sections & Entropy) ---
            "sections_info": [],           # רשימה שתאחסן מילון לכל מקטע עם השם, הגדלים והאנטרופיה שלו
            "is_packed": False,             # דגל כללי שמעיד אם הקובץ דחוס/מוצפן (לפי UPX, אנטרופיה או יחסי גדלים)
            
            # ---  סעיף 3: זיהוי דחיסה ופריקה  ---
            "unpacked_successful": False,  # מסמן האם תהליך הפריקה של UPX הצליח במלואו

            # --- תוצאות סעיף 4: חישוב חתימות ובדיקת מוניטין ---
            "file_hash": "",               # חתימת SHA-256 של הקובץ המלא
            "is_hash_malicious": "unknown",# הסטטוס של הקובץ השלם ("malicious", "safe", "unknown")
            "section_hashes": {},           # מילון שישמור לכל שם סקשן את ה-hash והסטטוס שלו

            # --- תוצאות סעיף 5: חילוץ מחרוזות ופענוח (Strings & IOCs) ---
            "network_iocs": {},            # מילון שישמור כתובות IP ו-URLs שנמצאו (המפתח הוא הכתובת, הערך הוא הסטטוס)
            "decoded_strings": [],         # רשימה של מחרוזות שהצלחנו לפענח מקידוד Base64 או XOR
            "obfuscation_detected": False,  # דגל שנדלק אם זיהינו שימוש אקטיבי בהסתרת מחרוזות

            # --- תוצאות סעיף 6: הנדסה לאחור וניתוח API (Disassembly & IAT) ---
            "imported_functions": {},      # מילון של כל ה-DLLs והפונקציות שהקובץ טוען
            "suspicious_imports": [],      # רשימה מסוננת של פונקציות מסוכנות במיוחד שנמצאו
            "assembly_risk_score": 0,      # ציון הסיכון שחושב מניתוח פקודות האסמבלי
            "assembly_heuristics": {},     # אילו טקטיקות התחמקות ספציפיות זוהו בקוד
            "call_jmp_table": [],
            "is_assembly_suspicious": False # דגל סופי שאומר האם התנהגות הקוד ברמת המכונה חשודה
        }
        
    def verify_pe(self):
        """
        Checks PE Dos Header for Magic Number
        """
        print("[*] Step 1: Verifying PE Header and Entry Point...")
        try:
            # טעינת הקובץ באמצעות ספריית pefile.
            pe = pefile.PE(self.file_path)

            # --- 1. בדיקת Magic Number (וידוא שהקובץ הוא קובץ הרצה) ---
            if hex(pe.DOS_HEADER.e_magic) == '0x5a4d':
                print("[+] Success: Valid PE file detected (Magic Number: 0x4D5A).")
                self.results["is_valid_pe"] = True
            else:
                print("[-] Failed: The Magic Number does not match a valid PE file.")
                self.results["is_valid_pe"] = False
                return True# יציאה מוקדמת, אין טעם להמשיך לנתח קובץ שהוא לא PE

            # --- 2. בדיקת TimeDateStamp (זיהוי תאריכי קימפול מזויפים) ---
            timestamp = pe.FILE_HEADER.TimeDateStamp
            compile_date = datetime.utcfromtimestamp(timestamp)
            current_date = datetime.utcnow()
            print(f"[*] Compile Date: {compile_date}")
            
            # אם תאריך הקימפול הוא בעתיד או ישן בצורה קיצונית, זה מעיד על זיוף כותרות
            if compile_date > current_date:
                print("[!] Warning: Compile date is in the future! This is highly suspicious.")
                self.results["suspicious_header"] = True
            elif compile_date.year < 1990:
                print("[!] Warning: Compile date is suspiciously old (before Windows existed).")
                self.results["suspicious_header"] = True
            else:
                self.results["suspicious_header"] = False

            # --- 3. בדיקת SizeOfOptionalHeader (וידוא שלא החביאו נתונים בכותרת) ---
            # 224 זה הגודל התקני לארכיטקטורת 32-bit, ו-240 לארכיטקטורת 64-bit
            opt_header_size = pe.FILE_HEADER.SizeOfOptionalHeader
            if opt_header_size not in [224, 240]:
                print(f"[!] Warning: Non-standard SizeOfOptionalHeader detected: {opt_header_size} bytes.")
                self.results["suspicious_header"] = True

            # --- 4. בדיקת נקודת הכניסה (Entry Point) ---
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            ep_section = None
            
            # מעבר על כל הסקשנים כדי לבדוק לאיזה מקטע נופלת כתובת הכניסה בזיכרון
            for section in pe.sections:
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    ep_section = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                    break
            
            # שמירת הנתונים במילון התוצאות
            self.results["entry_point"] = hex(ep)
            self.results["ep_section"] = ep_section
            print(f"[*] Entry Point Address: {hex(ep)}")
            
            if ep_section:
                print(f"[*] Entry Point is located in section: {ep_section}")
                # רשימה של שמות סקשנים לגיטימיים שנועדו להריץ קוד
                standard_code_sections = ['.text', 'code', 'CODE', '.code', 'INIT']
                if ep_section.lower() not in standard_code_sections:
                    print("[!] Warning: Entry Point is in a non-standard section! This is a classic evasion technique.")
                    self.results["is_ep_suspicious"] = True
                else:
                    print("[+] Entry Point is in a standard code section.")
                    self.results["is_ep_suspicious"] = False
            else:
                # אם נקודת הכניסה לא שייכת לאף סקשן ידוע, הקובץ מנסה להריץ קוד מחוץ למבנה התקין
                print("[-] Warning: Could not map Entry Point to any known section. Highly suspicious!")
                self.results["is_ep_suspicious"] = True

        except Exception as e:
            print(f"[-] Error parsing file (Might not be a PE file at all, or it is corrupted): {e}")
            self.results["is_valid_pe"] = False


    def calculate_entropy(self, data_bytes):
        """
        פונקציית עזר מתמטית לחישוב אנטרופיית שאנון על מערך בתים.
        מחזירה ערך בין 0.0 ל-8.0.
        """
        if not data_bytes:
            return 0.0
            
        entropy = 0.0
        length = len(data_bytes)
        
        # יצירת מערך שכיחויות לכל אחד מ-256 הערכים האפשריים של בית (Byte)
        occurrences = [0] * 256
        for byte in data_bytes:
            occurrences[byte] += 1
            
        # הפעלת נוסחת שאנון
        for count in occurrences:
            if count > 0:
                p_x = float(count) / length
                entropy -= p_x * math.log2(p_x)
                
        return entropy
    

    def analyze_sections(self):
        """
        סעיף 2: ניתוח מקטעים וחישוב אנטרופיה
        בדיקת שמות הסקשנים, יחסי גדלים ואיתור קוד דחוס/מוצפן.
        """
        print("[*] Step 2: Analyzing Sections and Calculating Entropy...")
        try:
            pe = pefile.PE(self.file_path)
            sections_data = []
            is_file_packed = False
            
            for section in pe.sections:
                # חילוץ שם הסקשן וניקוי תווי NULL
                sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                virtual_size = section.Misc_VirtualSize
                raw_size = section.SizeOfRawData
                
                # --- 1. חישוב אנטרופיה למקטע ---
                sec_bytes = section.get_data()
                entropy_val = self.calculate_entropy(sec_bytes)
                
                # בדיקה אם האנטרופיה חריגה (מעל 7.2 מצביע על דחיסה/הצפנה לפי האפיון)
                is_high_entropy = entropy_val > 7.2
                
                # --- 2. בדיקת יחסי גדלים בזיכרון מול הדיסק ---
                # אם המקטע תופס הרבה יותר מקום בזיכרון מאשר על הדיסק (למשל פי 2)
                # זה סימן מובהק ל- Unpacking בזמן ריצה
                # מחריגים סקשנים של נתונים שבהם זה נורמלי שמוקצה זיכרון ריק מראש
                is_data_section = sec_name.lower() in ['.data', '.bss', '.rdata']
                suspicious_size = virtual_size > (raw_size * 2) and raw_size > 0 and not is_data_section
                
                # --- 3. בדיקת שמות מחשידים ---
                is_upx = "UPX" in sec_name.upper()
                if is_upx or is_high_entropy or suspicious_size:
                    is_file_packed = True
                
                # בניית דוח למקטע הנוכחי
                sec_info = {
                    "name": sec_name,
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                    "entropy": round(entropy_val, 2),
                    "is_high_entropy": is_high_entropy,
                    "suspicious_size": suspicious_size,
                    "is_upx": is_upx
                }
                sections_data.append(sec_info)
                
                # הדפסת ממצאים למסך עבור דיבאגינג
                print(f"    -> Section '{sec_name}': Entropy = {sec_info['entropy']}")
                if is_high_entropy:
                    print(f"       [!] Warning: High entropy detected! Section might be packed/encrypted.")
                if suspicious_size:
                    print(f"       [!] Warning: VirtualSize ({virtual_size}) is significantly larger than RawSize ({raw_size}).")
                    
            # שמירת התוצאות לשימוש במנוע ההיוריסטי בהמשך
            self.results["sections_info"] = sections_data
            self.results["is_packed"] = is_file_packed
            
            if is_file_packed:
                print("[!] Alert: File exhibits characteristics of being PACKED or ENCRYPTED.")
            else:
                print("[+] Sections look standard and unpacked.")
                
            return True
            
        except Exception as e:
            print(f"[-] Error during sections analysis: {e}")
            return False
        

    def detect_and_unpack(self):
        """
        סעיף 3: זיהוי דחיסה ופריקה (Unpacking)
        בדיקה האם הקובץ דחוס, ואם כן - הפעלת כלי UPX ואימות לפי גודל הקובץ.
        """
        print("\n[*] Step 3: Checking for packed executable and unpacking (UPX)...")
        
        is_packed = self.results.get("is_packed", False)
        
        try:
            pe = pefile.PE(self.file_path)
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if "UPX" in sec_name.upper():
                    is_packed = True
                    self.results["is_packed"] = True
                    break

            if not is_packed:
                print("[+] File does not appear to be packed. Moving to next step.")
                self.results["unpacked_successful"] = False
                return True

            print("[!] Packed file detected! Attempting to unpack using UPX...")
            
            output_dir = "unpacked_software"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            file_name = os.path.basename(self.file_path)
            if ".exe" in file_name.lower():
                unpacked_file_name = file_name.replace(".exe", "_unpacked.exe")
            else:
                unpacked_file_name = file_name + "_unpacked.exe"
            
            unpacked_path = os.path.join(output_dir, unpacked_file_name)
            original_file_path = self.file_path
            
            process = subprocess.run(
                ['upx', '-d', original_file_path, '-o', unpacked_path], 
                capture_output=True, text=True
            ) 

            if process.returncode == 0 and os.path.exists(unpacked_path):
                # --- התוספת מספר הפרויקט: וידוא שהקובץ גדל משמעותית ---
                original_size = os.path.getsize(original_file_path)
                unpacked_size = os.path.getsize(unpacked_path)
                
                if unpacked_size > original_size:
                    print(f"[+] Unpacked successfully to: {unpacked_path}")
                    print(f"    -> Size increased from {original_size} to {unpacked_size} bytes.")
                    self.file_path = unpacked_path
                    self.results["unpacked_successful"] = True
                    return True
                else:
                    print("[-] Unpacking finished, but file size did not increase. Might not be a valid unpack.")
                    self.results["unpacked_successful"] = False
                    return False
            else:
                if "NotPackedException" in process.stderr:
                    print("[-] Failed to unpack: File is NOT packed with UPX (Likely a custom packer or PyInstaller).")
                else:
                    print(f"[-] Failed to unpack. Error: {process.stderr}")
                    
                self.results["unpacked_successful"] = False
                return False
                
        except FileNotFoundError:
            print("[-] Error: UPX tool is not installed or not in the system PATH.")
            self.results["unpacked_successful"] = False
            return False
            
        except Exception as e:
            print(f"[-] Error during unpacking analysis: {e}")
            self.results["unpacked_successful"] = False
            return False

    def calculate_and_check_hashes(self):
        """
        סעיף 4: חישוב חתימות ובדיקת מוניטין (Hashing & Reputation)
        מחשב SHA-256 לכל הקובץ ולכל סקשן בנפרד, ובודק אותם מול ה-DB ו-VirusTotal.
        """
        print("\n[*] Step 4: Calculating Hashes and Checking Reputation...")
        
        # 1. חישוב חתימת Hash מלאה על כל הקובץ
        hasher = hashlib.sha256()
        try:
            with open(self.file_path, 'rb') as f:
                # קריאה בבלוקים כדי לא להעמיס על הזיכרון בקבצים גדולים
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            
            full_file_hash = hasher.hexdigest()
            self.results["file_hash"] = full_file_hash
            print(f"[*] Full File SHA-256: {full_file_hash}")
            
        except Exception as e:
            print(f"[-] Error calculating file hash: {e}")
            self.results["is_hash_malicious"] = "unknown"
            return False

        # --- אתחול סטטוס למקרה שהמקורות לא זמינים ---
        self.results["is_hash_malicious"] = "unknown"
        
        # 2. בדיקה מול מסד הנתונים המקומי (MySQL)
        if self.db_manager:
            try:
                # אנחנו מניחים שיש לך אתחול לחיבור (self.db_manager.open_connection() וכו')
                # במקום אחר או שהוא פתוח כברירת מחדל במחלקה שלו
                db_verdict = self.db_manager.check_hash_file(full_file_hash)
                
                if db_verdict == 'malicious':
                    print("[!] Alert: File hash found in local DB and marked as Malicious!")
                    self.results["is_hash_malicious"] = "malicious"
                    return True # חוסכים זמן, סיימנו את הניתוח
                elif db_sec_verdict == "suspicious":
                    print("[!] Alert: File hash found in local DB and marked as Suspicious!")
                    self.results["is_hash_malicious"] = "suspicious"
                    return True
                elif db_verdict == 'safe':
                    print("[+] Database: File hash is known and marked as Safe.")
                    self.results["is_hash_malicious"] = "safe"
                    return True 
            except Exception as e:
                print(f"[-] Error connecting to local Database: {e}")
        else:
            print("[-] Warning: Database Manager is not connected.")

        # 3. בדיקה מול מאגר המידע של VirusTotal
        if self.vt_api:
            try:
                vt_verdict = self.vt_api.check_file_hash(full_file_hash)
                if vt_verdict == 'malicious':
                    print("[!] Alert: File hash found in VirusTotal and marked as Malicious!")
                    self.results["is_hash_malicious"] = "malicious"
                    return True
                elif vt_verdict == 'safe':
                    print("[+] VirusTotal: File hash is known and marked as Safe.")
                    self.results["is_hash_malicious"] = "safe"
                    return True
            except Exception as e:
                print(f"[-] Error connecting to VirusTotal API: {e}")
        else:
            print("[-] Warning: VirusTotal API is not connected.")
            
        print("[+] Full file hash is unknown. Proceeding to calculate section hashes...")

        # 4. חישוב Hash פרטני לכל סקשן
        try:
            pe = pefile.PE(self.file_path)
            # אם לא פתחנו חיבור למסד הנתונים קודם, נוודא שהוא פתוח עכשיו
            if self.db_manager:
                self.db_manager.open_connection()
                
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                sec_data = section.get_data()
                
                if sec_data:
                    sec_hash = hashlib.sha256(sec_data).hexdigest()
                    print(f"    -> Section {sec_name}: {sec_hash}")
                    
                    status = "unknown"
                    
                    # בדיקת המקטע הספציפי מול מסד הנתונים המקומי
                    if self.db_manager:
                        try:
                            db_sec_verdict = self.db_manager.check_section_hash(sec_name, sec_hash)
                            if db_sec_verdict:
                                status = db_sec_verdict
                                if status == "malicious":
                                    print(f"       [!] Alert: Section '{sec_name}' identified as MALICIOUS in DB!")
                                elif status == "safe":
                                    print(f"       [+] Section '{sec_name}' identified as SAFE in DB.")
                        except Exception as e:
                            print(f"       [-] Error checking section hash in DB: {e}")
                    
                    # עדכון המילון הפרטני של הסקשן
                    self.results["section_hashes"][sec_name] = {
                        "hash": sec_hash,
                        "status": status
                    }
                    
        except Exception as e:
            print(f"[-] Error calculating section hashes: {e}")

        finally:
             if self.db_manager:
                try:
                    self.db_manager.close_connection()
                except:
                    pass
                    
    

    def _decode_base64_xor(self, content_bytes):
        """
        פונקציית עזר לחילוץ ופענוח מחרוזות מוסתרות (Base64 ו-XOR)
        """
        decoded_findings = []
        obfuscation_flag = False

        # 1. חיפוש תבניות Base64 (רצפים של אותיות, מספרים, + ו-/)
        # מחפשים מחרוזות באורך 16 תווים לפחות כדי למנוע זיהויי שווא (False Positives)
        b64_pattern = re.compile(rb'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        b64_matches = set(b64_pattern.findall(content_bytes))
        
        for match in b64_matches:
            try:
                decoded_bytes = base64.b64decode(match)
                # בודקים אם התוצאה היא טקסט קריא (ASCII)
                decoded_str = decoded_bytes.decode('utf-8')
                # סינון בסיסי: אם זה מכיל תווים הגיוניים ומילים
                if len(decoded_str) > 5 and re.match(r'^[\x20-\x7E]+$', decoded_str):
                    print(f"       [!] Alert: Decoded Base64 string found: {decoded_str}")
                    decoded_findings.append({"type": "base64", "original": match.decode(), "decoded": decoded_str})
                    obfuscation_flag = True
            except:
                pass # לא כל רצף שמתאים ל-Regex הוא באמת Base64 תקין

        # 2. חיפוש XOR בסיסי (בדיקה מול מפתחות נפוצים בנוזקות כמו 0x55, 0xAA, 0xFF)
        # כדי לא להכביד על זמן הריצה, נבדוק רק רצפים שנראים כמו טקסט אבל מוסתרים
        common_xor_keys = [0x55, 0xAA, 0xFF]
        
        # אנחנו מחפשים רצפי בתים שאם נעשה להם XOR עם המפתחות האלה, נקבל "http" או כתובות
        # (מטעמי יעילות בניתוח הסטטי, זה מימוש בסיסי. הניתוח הדינמי יתפוס את השאר)
        for key in common_xor_keys:
            target_magic = [ord('h') ^ key, ord('t') ^ key, ord('t') ^ key, ord('p') ^ key]
            magic_bytes = bytes(target_magic)
            
            if magic_bytes in content_bytes:
                print(f"       [!] Alert: Found XOR obfuscated content using key {hex(key)}!")
                obfuscation_flag = True
                decoded_findings.append({"type": "xor", "key": hex(key), "note": "Potential hidden URLs detected via XOR."})
                break # מספיק שמצאנו עדות אחת כדי להדליק את דגל ההסוואה

        return decoded_findings, obfuscation_flag
    
    def extract_and_check_network_iocs(self):
        """
        סעיף 5: חילוץ כתובות IP, URLs ופענוח מחרוזות מוסתרות
        """
        print("\n[*] Step 5: Extracting Strings, Decoding & Checking Network IOCs...")
        
        ip_pattern = re.compile(rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        url_pattern = re.compile(rb'https?://[a-zA-Z0-9./\-_?=]+')
        
        try:
            with open(self.file_path, 'rb') as f:
                content = f.read()
                
            # 1. ניסיון פענוח מחרוזות מוסתרות (Base64/XOR)
            decoded_strings, is_obfuscated = self._decode_base64_xor(content)
            self.results["decoded_strings"] = decoded_strings
            self.results["obfuscation_detected"] = is_obfuscated
            
            # 2. חילוץ IPs ו-URLs בטקסט גלוי
            extracted_ips = set(ip_pattern.findall(content))
            extracted_urls = set(url_pattern.findall(content))

            if self.db_manager:
                self.db_manager.open_connection()

            # עיבוד כתובות IP
            for ip_bytes in extracted_ips:
                ip_str = ip_bytes.decode('utf-8', errors='ignore')
                parts = ip_str.split('.')
                
                # סינון כתובות לא חוקיות וכתובות מקומיות רגילות
                if all(0 <= int(p) <= 255 for p in parts) and not ip_str.startswith("0.") and not ip_str.startswith("127."):
                    # התוספת שלנו: סינון מספרי גרסאות של ווינדוס (לרוב נגמרים ב-.0.0)
                    if ip_str.endswith(".0.0"):
                        continue
                    
                    self._evaluate_ioc(ip_str, 'ip')
                    
            # עיבוד כתובות URL
            for url_bytes in extracted_urls:
                url_str = url_bytes.decode('utf-8', errors='ignore')
                self._evaluate_ioc(url_str, 'url')

            if self.db_manager:
                self.db_manager.close_connection()
                
            return True
            
        except Exception as e:
            print(f"[-] Error extracting network IOCs and strings: {e}")
            return False
        
    
    def _evaluate_ioc(self, ioc_value, ioc_type):
        """פונקציית עזר לבדיקת האינדיקטור מול מסד הנתונים ו-VirusTotal"""
        status = "unknown"
        print(f"    -> Found {ioc_type.upper()}: {ioc_value}")
        
        # בדיקה מול מסד הנתונים המקומי
        if self.db_manager:
            try:
                db_verdict = self.db_manager.check_ips_urls(ioc_value, ioc_type)
                if db_verdict:
                    status = db_verdict
                    if status == 'malicious':
                        print(f"       [!] Alert: {ioc_type.upper()} identified as MALICIOUS in local DB!")
                    elif status == 'safe':
                        print(f"       [+] {ioc_type.upper()} identified as SAFE in local DB.")
            except Exception as e:
                print(f"       [-] DB Check Error: {e}")
                
        # בדיקה מול VirusTotal אם לא נמצא ב-DB
        if status == "unknown" and self.vt_api:
            try:
                vt_verdict = self.vt_api.check_ip_url(ioc_value, ioc_type)
                if vt_verdict:
                    status = vt_verdict
                    if status == 'malicious':
                        print(f"       [!] Alert: {ioc_type.upper()} identified as MALICIOUS in VirusTotal!")
                    elif status == 'safe':
                        print(f"       [+] {ioc_type.upper()} identified as SAFE in VirusTotal.")
            except Exception as e:
                print(f"       [-] VirusTotal Check Error: {e}")
                
        # הוספה למילון התוצאות הסופי (החלפתי את השם ל-network_iocs כדי שיתאים ל-__init__)
        self.results["network_iocs"][ioc_value] = {
            "type": ioc_type,
            "status": status
        }


    def analyze_assembly(self):
        """
        סעיף 6: הנדסה לאחור וניתוח IAT
        שליפת פונקציות API מחשידות, פירוק הקוד לאסמבלי, ומעקב אחרי שרשראות JMP/CALL.
        """
        print("\n[*] Step 6: Analyzing API Imports (IAT) and Disassembling Code...")

        try:
            pe = pefile.PE(self.file_path)
            
            # --- חלק א': חילוץ וניתוח Import Address Table (IAT) ---
            dangerous_apis = [
                'virtualalloc', 'virtualallocex', 'writeprocessmemory', 
                'createremotethread', 'loadlibrarya', 'getprocaddress', 
                'setwindowshookex', 'isdebuggerpresent', 'sleep'
            ]
            
            imports_dict = {}
            found_suspicious_apis = []
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    imports_dict[dll_name] = []
                    
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode('utf-8', errors='ignore')
                            imports_dict[dll_name].append(func_name)
                            if func_name.lower() in dangerous_apis:
                                found_suspicious_apis.append(func_name)
                                
            self.results["imported_functions"] = imports_dict
            self.results["suspicious_imports"] = found_suspicious_apis
            
            if found_suspicious_apis:
                print(f"    [!] Alert: Found {len(found_suspicious_apis)} highly suspicious API imports:")
                print(f"        -> {', '.join(found_suspicious_apis)}")
            else:
                print("    [+] No highly suspicious API imports detected.")

            # --- חלק ב': פירוק לאסמבלי (Capstone) ומעקב זרימת קוד ---
            if pe.FILE_HEADER.Machine == 0x8664:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                
            code_section = None
            for section in pe.sections:
                if section.Characteristics & 0x20000000:
                    code_section = section
                    break
                    
            if not code_section:
                print("    [-] Error: No executable code section found for disassembly.")
                return False
                
            code_data = code_section.get_data()
            risk_score = 0
            
            call_jmp_table = []
            chained_calls_detected = 0
            dynamic_api_resolutions = 0
            previous_instructions = [] 
            
            heuristics_found = {
                "rdtsc_anti_vm": False,
                "cpuid_evasion": False,
                "peb_direct_access": False,
                "dynamic_api_loading": False,
                "chained_execution": False
            }
            
            instructions = md.disasm(code_data, code_section.VirtualAddress)
            
            for i, inst in enumerate(instructions):
                if i >= 10000:
                    break
                    
                mnemonic = inst.mnemonic.lower()
                op_str = inst.op_str.lower()
                
                previous_instructions.append(mnemonic)
                if len(previous_instructions) > 3:
                    previous_instructions.pop(0)
                
                if mnemonic in ['call', 'jmp']:
                    call_jmp_table.append({
                        "address": hex(inst.address),
                        "type": mnemonic,
                        "target": op_str
                    })
                    
                    if len(previous_instructions) >= 2 and previous_instructions[-2] in ['call', 'jmp']:
                        chained_calls_detected += 1
                        
                if mnemonic == 'call' and 'push' in previous_instructions:
                    dynamic_api_resolutions += 1

                if mnemonic == 'rdtsc' and not heuristics_found["rdtsc_anti_vm"]:
                    risk_score += 10
                    heuristics_found["rdtsc_anti_vm"] = True
                    
                if mnemonic == 'cpuid' and not heuristics_found["cpuid_evasion"]:
                    risk_score += 10
                    heuristics_found["cpuid_evasion"] = True
                    
                if ('fs:[' in op_str and '30' in op_str) or ('gs:[' in op_str and '60' in op_str):
                    if not heuristics_found["peb_direct_access"]:
                        risk_score += 30
                        heuristics_found["peb_direct_access"] = True

            if chained_calls_detected > 30:
                print(f"    [!] Heuristic: Detected {chained_calls_detected} chained JMP/CALL instructions.")
                risk_score += 15
                heuristics_found["chained_execution"] = True
                
            if dynamic_api_resolutions > 15:
                print(f"    [!] Heuristic: Detected {dynamic_api_resolutions} dynamic API loading patterns (push followed by call).")
                risk_score += 20
                heuristics_found["dynamic_api_loading"] = True

            print(f"[*] Assembly Risk Score: {risk_score}")
            
            self.results["assembly_risk_score"] = risk_score
            self.results["assembly_heuristics"] = heuristics_found
            self.results["call_jmp_table"] = call_jmp_table 
            
            if risk_score >= 30 or len(found_suspicious_apis) > 3:
                print("[!] Alert: Code is considered HIGHLY SUSPICIOUS based on Assembly flow and IAT.")
                self.results["is_assembly_suspicious"] = True
            else:
                print("[+] Assembly flow and IAT look behaviorally normal.")
                self.results["is_assembly_suspicious"] = False
                
            return True

        except Exception as e:
            print(f"[-] Error during assembly and IAT analysis: {e}")
            return False


    def begin_analyzing(self):
        """
        main function that manages all of the analyzing steps
        """
        print("\n" + "="*45)
        print("--- STARTING ADVANCED STATIC ANALYSIS ---")
        print("="*45 + "\n")
        
        # 1. PE verification
        self.verify_pe()
        if not self.results.get("is_valid_pe"):
            print("[-] CRITICAL: File is not a valid PE. Stopping analysis.")
            return "INVALID_PE"
    
        # 2. Analyze sections
        self.analyze_sections()

        # 3. Detect UPX and decompression
        self.detect_and_unpack()

        # 4. Calculate Hash
        self.calculate_and_check_hashes()
        if self.results.get("is_hash_malicious") == "malicious":
            print("[!] CRITICAL: Full file hash is known as MALICIOUS. Stopping analysis.")
            return "KNOWN_MALICIOUS"

        # 5. Extract Ips and Urls
        self.extract_and_check_network_iocs()

        # 6. Assembly Analyze
        self.analyze_assembly()
        
        return "CONTINUE"
  
        