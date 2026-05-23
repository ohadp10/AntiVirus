import pefile
import subprocess
import hashlib

class StaticAnalyzer:
    def __init__(self, file_path, db_manager=None, vt_api=None):
        self.file_path = file_path
        self.db_manager = db_manager
        self.vt_api = vt_api

        self.results = {
            "is_valid_pe": False,
            "is_packed": False,
            "unpacked_succesfull": False,
            "file_hash": "",
            "section_hashes": {},
            "is_hash_malicious": "unknown", # "malicious", "safe", "unknown"
            "urls_ips": [],
            "assembly_commands": [],
            "assembly_risk_score": 0,
            "is_assembly_suspicious": False
        }
        
    def verify_pe(self):
        """
        1: Magic Number analyzing and Entry Point checking
        """
        print("[*] Step 1: Verifying PE Header and Entry Point...")
        try:
            pe = pefile.PE(self.file_path)

            if hex(pe.DOS_HEADER.e_magic) == '0x5a4d':
                print("[+] Success: Valid PE file detected (Magic Number: 0x4D5A).")
                self.results["is_valid_pe"] = True
                
                # --- בדיקת נקודת הכניסה (Entry Point) ---
                ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                ep_section = None
                
                # מעבר על כל הסקשנים כדי למצוא איפה נופלת כתובת הכניסה
                for section in pe.sections:
                    # בודקים אם הכתובת נמצאת בטווח של הסקשן הנוכחי בזיכרון
                    if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                        ep_section = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                        break
                
                # שמירת הנתונים במילון התוצאות
                self.results["entry_point"] = hex(ep)
                self.results["ep_section"] = ep_section
                
                print(f"[*] Entry Point Address: {hex(ep)}")
                if ep_section:
                    print(f"[*] Entry Point is located in section: {ep_section}")
                    
                    # בדיקה אם הסקשן שגרתי או חשוד
                    standard_code_sections = ['.text', 'code', 'CODE', '.code']
                    if ep_section.lower() not in standard_code_sections:
                        print("[!] Warning: Entry Point is in a non-standard section! This is highly suspicious.")
                        self.results["is_ep_suspicious"] = True
                    else:
                        print("[+] Entry Point is in a standard code section.")
                        self.results["is_ep_suspicious"] = False
                else:
                    print("[-] Warning: Could not map Entry Point to any known section.")
                    self.results["is_ep_suspicious"] = True

            else:
                #later add alert in gui that the file is not .exe
                print("[-] Failed: The Magic Number does not match a valid PE file.")
                self.results["is_valid_pe"] = False
                
        except Exception as e:
            print(f"[-] Error parsing file (Might not be a PE file at all): {e}")
            self.results["is_valid_pe"] = False


    def detect_and_unpack(self):
        """
        detecting if the file is packed if it is packed it tries to unpack it and change the 
        """
        print("[*] Step 2: Checking for packed executable (UPX)...")
        try:
            pe = pefile.PE(self.file_path)
            is_packed = False
            
            # מעבר על הסקשנים לאיתור חתימות דחיסה
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                if "UPX" in sec_name.upper():
                    is_packed = True
                    break
            
            self.results["is_packed"] = is_packed
            
            if is_packed:
                print("[!] Packed file detected (UPX sections found).")
                print("[*] Attempting to unpack using UPX...")
                
                original_file_path = self.file_path
                self.file_path.replace(".exe", "_unpacked.exe")
                
                process = subprocess.run(['upx', '-d', original_file_path, '-o', self.file_path], capture_output=True, text=True) 

                if process.returncode == 0:
                    print(f"[+] Unpacked successfully to: {self.file_path}")
                    # עדכון נתיב הקובץ במחלקה כדי שהשלבים הבאים ינתחו את הקובץ האמיתי
                    self.results["unpacked_successfull"] = True
                else:
                    print(f"[-] Failed to unpack. Error: {process.stderr}")
                    self.results["unpacked_successfull"] = False
            else:
                print("[+] File does not appear to be packed.")
                
        except Exception as e:
            print(f"[-] Error during unpacking analysis: {e}")

    
    def calculate_and_check_hashes(self):
        """
        calculating hash for the whole file, checks with DB and virtusTotal and than checks Section hashes with DB 
        """
        print("[*] Step 3: Calculating Hashes and Checking Reputation...")
        
        # 1. חישוב חתימת Hash מלאה על כל הקובץ
        hasher = hashlib.sha256()
        try:
            with open(self.file_path, 'rb') as f:
                buf = f.read()
                hasher.update(buf)
            full_file_hash = hasher.hexdigest()
            self.results["file_hash"] = full_file_hash
            print(f"[*] Full File SHA-256: {full_file_hash}")
        except Exception as e:
            print(f"[-] Error calculating file hash: {e}")
            return False

        if self.db_manager:
            db_verdict = self.db_manager.check_hash_file(full_file_hash)
            
            if db_verdict == 'malicious':
                print("[!] Alert: File hash found in local DB and marked as Malicious!")
                self.results["is_hash_malicious"] = "malicious"
                return 
                
            elif db_verdict == 'safe':
                print("[+] Database: File hash is known and marked as Safe.")
                self.results["is_hash_malicious"] = "safe"
                return
        else:
            print("[-] Warning: Database Manager is not connected.")

        
            
        if self.vt_api:
            vt_verdict = self.vt_api.check_file_hash(full_file_hash)
            if vt_verdict == 'malicious':
                print("[!] Alert: File hash found in VirusTotal and marked as Malicious!")
                self.results["is_hash_malicious"] = "malicious"
                return 
            elif vt_verdict == 'safe':
                print("[+] VirusTotal: File hash is known and marked as Safe.")
                self.results["is_hash_malicious"] = "safe"
                return
        else:
            print("[-] Warning: VirusTotal API is not connected.")

            
        print("[+] Full file hash is unknown. Proceeding to section hashes...")
        self.results["is_hash_malicious"] = "unknown"
        
        
        # 4. חישוב Hash לכל סקשן בנפרד ובדיקה
        try:
            pe = pefile.PE(self.file_path)
            self.db_manager.open_connection()
            for section in pe.sections:
                sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                sec_data = section.get_data()
                
                if sec_data:
                    sec_hash = hashlib.sha256(sec_data).hexdigest()
                    print(f"    -> Section {sec_name}: {sec_hash}")
                    
                    status = "unknown"
                    
                    # בדיקת הסקשן מול מסד הנתונים
                    if self.db_manager:
                        db_sec_verdict = self.db_manager.check_section_hash(sec_name, sec_hash)
                        if db_sec_verdict:
                            status = db_sec_verdict
                            if status == "malicious":
                                print(f"       [!] Alert: Section '{sec_name}' identified as MALICIOUS in DB!")
                            elif status == "safe":
                                print(f"       [+] Section '{sec_name}' identified as SAFE in DB.")
                    
                    # שמירת התוצאה
                    self.results["section_hashes"][sec_name] = {
                        "hash": sec_hash,
                        "status": status
                    }
                    
        except Exception as e:
            print(f"[-] Error calculating section hashes: {e}")

        finally:
            self.db_manager.close_connection()            


    def begin_analyzing(self):
        """
        main function that manages all of the analyzing steps
        """
        print("\n" + "="*45)
        print("--- STARTING ADVANCED STATIC ANALYSIS ---")
        print("="*45 + "\n")
        
        # 1. PE verification
        self.verify_pe()

        # GUI Error: file is not pe
        if self.results["is_valid_pe"] == False:
            return
            
        # 2. UPX detect and unpacking
        self.detect_and_unpack()

        # GUI Error: file is packed and was not able to unpack
        if self.results["is_packed"] == True and self.results["unpacked_successfull"] == False:
            return

        # 3. Calculating Hash
        self.calculate_and_check_hashes()

        if self.results["is_hash_malicious"] == "malicious" or "safe":
            return

        # 4. compare_with_virustotal()
        # 5. extract_strings()
        # 6. disassemble_code()
        