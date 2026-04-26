import hashlib
import pefile
import re
import base64
from capstone import *

class StaticAnalyzer:
    #יצירת מחלקה של המנתח
    def __init__(self, filepath):
        self.filepath = filepath
        self.results = {
            "hash": None,
            "is_pe": False,
            "sections_ok": False,
            "is_packed": False,
            "found_ips": [],
            "found_urls": [],
            "assembly_score": 0,
            "section_hashes": {},  
            "decoded_strings": [],
            "header_warnings": [],  
            "ep_check": "Unknown"  
        }
    #בודק את הכותרת של הקובץ    
    def analyzeHeader(self):
        try:
            pe = pefile.PE(self.filepath)
            print("\n--- Analyzing PE Header ---")
            
            # בדיקת גודל ה-Optional Header
            opt_header_size = pe.FILE_HEADER.SizeOfOptionalHeader
            is_64bit = pe.FILE_HEADER.Machine == 0x8664
            expected_size = 240 if is_64bit else 224
            
            if opt_header_size != expected_size:
                self.results["header_warnings"].append(f"Non-standard Optional Header size: {opt_header_size}")

            # בדיקת ה-TimeDateStamp
            timestamp = pe.FILE_HEADER.TimeDateStamp
            import datetime
            date = datetime.datetime.fromtimestamp(timestamp)
            if date.year > datetime.datetime.now().year or date.year < 2000:
                self.results["header_warnings"].append(f"Suspicious TimeDateStamp: {date}")

            # בדיקת כמות הסקשנים
            if pe.FILE_HEADER.NumberOfSections > 10:
                self.results["header_warnings"].append(f"High number of sections: {pe.FILE_HEADER.NumberOfSections}")
                
        except Exception as e:
            print(f"Error in analyzeHeader: {e}")

    #מנתח את הEntryPoint של הקובץ
    def analyzeEntryPoint(self):
        try:
            pe = pefile.PE(self.filepath)
            print("\n--- Checking Entry Point ---")
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            found_section = None
            for section in pe.sections:
                # בדיקה אם ה-EP נמצא בתוך הטווח של הסקשן
                if section.VirtualAddress <= ep < section.VirtualAddress + section.Misc_VirtualSize:
                    found_section = section
                    break
            
            if found_section:
                name = found_section.Name.decode('utf-8', errors='ignore').strip('\x00')
                # בדיקה אם ה-EP מצביע לסקשן חשוד
                if name not in ['.text', 'CODE']:
                    self.results["ep_check"] = f"Suspicious (EP in {name})"
                else:
                    self.results["ep_check"] = "Safe"
            else:
                self.results["ep_check"] = "Malicious (EP outside sections)"
        except Exception as e:
            print(f"Error in analyzeEntryPoint: {e}")

    #מחשב את החתימה של הקובץ
    def calculateHash(self):
        sha256_hash = hashlib.sha256()
        try:
            with open(self.filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            result = sha256_hash.hexdigest()
            self.results["hash"] = result
            return result
        except Exception as e:
            return str(e)

    def checkMagicNumber(self):
        try:
            with open(self.filepath, "rb") as f:
                magicbytes = f.read(2)
                self.results["is_pe"] = (magicbytes == b'MZ')
                return self.results["is_pe"]
        except Exception:
            return False

    #מנתח את הסקשנים של הקובץ
    def analyzeSections(self):
        try:
            pe = pefile.PE(self.filepath)
            print("\n--- Analyzing Sections & Section Hashes ---")
            suspicious_sections = []
            standard_sections = ['.text', '.data', '.rsrc', '.reloc', '.idata', '.pdata', '.rdata', '.didat']

            for section in pe.sections:
                #ניקוי שם הסקשן
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                
                #חישוב חתימה לכל סקשן בנפרד
                s_data = section.get_data()
                s_hash = hashlib.sha256(s_data).hexdigest()
                self.results['section_hashes'][name] = s_hash
                
                print(f" Section: {name:<10} | Hash: {s_hash[:15]}...")

                if name not in standard_sections:
                    suspicious_sections.append(name)

            self.results["sections_ok"] = (len(suspicious_sections) == 0)
            return self.results["sections_ok"]
        except Exception as e:
            print(f"Error sections: {e}")
            return False

    #בודק דחיסה בקובץ
    def checkForPacking(self):
        try:
            pe = pefile.PE(self.filepath)
            is_packed = False
            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                # זיהוי Upx לפי שם הסקשן
                if "upx" in name.lower():
                    is_packed = True
                # בדיקת יחס גודל חשוד
                if section.SizeOfRawData > 0 and section.Misc_VirtualSize > section.SizeOfRawData * 2:
                    is_packed = True
            
            self.results["is_packed"] = is_packed
            return is_packed
        except Exception:
            return False

    #מחלץ כתובות URL ו-IP
    def extractStrings(self):
        try:
            print("\n--- Extracting & Decoding Strings ---")
            with open(self.filepath, "rb") as f:
                data = f.read()
            
            # חילוץ מחרוזות ASCII
            strings = re.findall(rb'[ -~]{4,}', data)
            decoded_raw = [s.decode("utf-8", errors="ignore") for s in strings]
            
            # 1. חיפוש IPs ו-URLs
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            url_pattern = re.compile(r'https?://[^\s/$.?#].[^\s]*')
            
            ips = set()
            urls = set()
            for s in decoded_raw:
                found_ips = ip_pattern.findall(s)
                for ip in found_ips:
                    if ip != "0.0.0.0" and not ip.startswith("127."): ips.add(ip)
                
                found_urls = url_pattern.findall(s)
                for url in found_urls: urls.add(url)

            self.results["found_ips"] = list(ips)
            self.results["found_urls"] = list(urls)

            # 2. פענוח Base64
            b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){3,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
            for s in decoded_raw:
                if b64_pattern.fullmatch(s):
                    try:
                        decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
                        if len(decoded) > 4 and decoded.isprintable():
                            self.results["decoded_strings"].append(f"Base64: {decoded}")
                    except: pass
            
            # 3. בדיקת XOR
            for s in strings:
                xor_decoded = "".join([chr(b ^ 0xAA) for b in s])
                if xor_decoded.isprintable() and len(xor_decoded) > 10:
                    self.results["decoded_strings"].append(f"XOR(0xAA): {xor_decoded}")

        except Exception as e:
            print(f"Error strings: {e}")

    #מחפש פקודות אסמבלי חשודות בקובץ
    def analyzeAssembly(self):
        try:
            pe = pefile.PE(self.filepath)
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            base = pe.OPTIONAL_HEADER.ImageBase
            
            # מציאת הסקשן של ה-Entry Point
            code_data = pe.get_data(ep, 100)
            
            md = Cs(CS_ARCH_X86, CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else CS_MODE_32)
            score = 0
            for i in md.disasm(code_data, base + ep):
                if i.mnemonic in ['xor', 'jmp', 'call', 'loop']:
                    score += 5 if i.mnemonic == 'xor' else 2
            
            self.results["assembly_score"] = score
            return score
        except Exception:
            return 0