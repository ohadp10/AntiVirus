import hashlib
import pefile
import re
from capstone import *

class StaticAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        # מילון שישמור את כל התוצאות בצורה מסודרת (יעזור לנו מאוד כשנחבר את מסד הנתונים)
        self.results = {
            "hash": None,
            "is_pe": False,
            "sections_ok": False,
            "is_packed": False,
            "found_ips": [],
            "found_urls": [],
            "assembly_score": 0
        }

    def calculateHash(self):
        print("\n--- 1. Calculating Hash ---")
        sha256_hash = hashlib.sha256()
        try:
            with open(self.filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            result = sha256_hash.hexdigest()

            self.results["hash"] = result
            return result
        except FileNotFoundError:
            return "File Wasn't found"
        except Exception as e:
            return str(e)

    def checkMagicNumber(self):
        print("\n--- 2. Checking Magic Number ---")
        try:
            with open(self.filepath, "rb") as f:
                magicbytes = f.read(2)
                if magicbytes == b'MZ':
                    self.results["is_pe"] = True
                    return True
                else:
                    self.results["is_pe"] = False
                    return False
        except Exception as e:
            return str(e)

    def analyzeSections(self):
        try:
            pe = pefile.PE(self.filepath)
            print("\n--- 3. Analyzing file's sections ---")
            suspicious_sections = []

            for section in pe.sections:
                section_name = section.Name.decode('utf-8').strip('\x00')
                print(f"{section_name:<15} | {hex(section.Misc_VirtualSize):<15} | {hex(section.SizeOfRawData):<15}")
                standard_sections = ['.text', '.data', '.rsrc', '.reloc', '.idata', '.pdata', '.rdata', 'fothk', '.didat']
                
                if section_name not in standard_sections:
                    suspicious_sections.append(section_name)

            if suspicious_sections:
                print(f"\n[!] Warning: Found non-standard sections: {suspicious_sections}")
                self.results["sections_ok"] = False
                return False
            else:
                self.results["sections_ok"] = True
                return True
        except Exception as e:
            print("Error parsing pe file")
            return False

    def checkForPacking(self):
        try:
            pe = pefile.PE(self.filepath)
            print("\n--- 4. Checking for packing ---")

            skippable_sections = ['.data', '.rsrc', '.reloc', '.bss', '.didat']
            is_packed = False
            
            for section in pe.sections:
                section_name = section.Name.decode('utf-8').strip('\x00')
                virtualsize = section.Misc_VirtualSize
                rawsize = section.SizeOfRawData

                if "upx" in section_name.lower():
                    print("UPX Detected")
                    is_packed = True

                if section_name not in skippable_sections and rawsize > 0 and virtualsize > rawsize * 2:
                    print("suspicious ratio")
                    is_packed = True

            self.results["is_packed"] = is_packed

            if not is_packed:
                print("No obvious signs for packing")
                return False
            else:
                return True

        except Exception as e:
            print(f"Error checking for packing: {e}")
            return False       

    def extractStrings(self):
        try:
            print("\n--- 5. Extracting Strings & IOCs ---")
            with open(self.filepath, "rb") as f:
                data = f.read()
            
            ascii_strings = re.findall(rb'[ -~]{4,}', data)
            unicode_strings = re.findall(rb'(?:[\x20-\x7E][\x00]){4,}', data)
            
            decoded_ascii = [s.decode("utf-8") for s in ascii_strings]
            decoded_unicode = [s.decode("utf-16le") for s in unicode_strings]
            
            all_strings = decoded_ascii + decoded_unicode
            print(f"Total strings found: {len(all_strings)}")
            
            ips = set()
            urls = set()
            
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            url_pattern = re.compile(r'(?:http[s]?://|www\.)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

            for s in all_strings:
                found_ips = ip_pattern.findall(s)
                for ip in found_ips:
                    if ip != "0.0.0.0" and not ip.startswith("127."): 
                        ips.add(ip)

                found_urls = url_pattern.findall(s)
                for url in found_urls:
                    urls.add(url)
            
            self.results["found_ips"] = list(ips)
            self.results["found_urls"] = list(urls)

            if ips:
                print(f"[!] Found Potential IPs: {list(ips)[:5]}")
            else:
                print("[V] No suspicious IPs found.")

            if urls:
                print(f"[!] Found Potential URLs: {list(urls)[:5]}")
            else:
                print("[V] No URLs found.")
                
        except Exception as e:
            print(f"Error extracting strings: {e}")

    def analyzeAssembly(self):
        try:
            pe = pefile.PE(self.filepath)
            print("\n--- 6. Assembly Analysis (Heuristic Scoring) ---")

            entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = pe.OPTIONAL_HEADER.ImageBase
            
            entry_section = None
            for section in pe.sections:
                if section.VirtualAddress <= entry_point_rva < section.VirtualAddress + section.Misc_VirtualSize:
                    entry_section = section
                    break
            
            if not entry_section:
                return 0 

            entry_offset = entry_point_rva - entry_section.VirtualAddress + entry_section.PointerToRawData
            
            with open(self.filepath, "rb") as f:
                f.seek(entry_offset)
                code = f.read(100) 

            if pe.FILE_HEADER.Machine == 0x8664:
                md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                md = Cs(CS_ARCH_X86, CS_MODE_32)

            risk_score = 0
            
            for i in md.disasm(code, image_base + entry_point_rva):
                mnemonic = i.mnemonic
                
                if mnemonic == 'xor':
                    risk_score += 5   
                elif mnemonic == 'jmp':
                    risk_score += 2   
                elif mnemonic == 'call':
                    risk_score += 1   
                if mnemonic in ['loop', 'loope', 'loopne']:
                    risk_score += 10

            print(f"Final Heuristic Score: {risk_score}")
            self.results["assembly_score"] = risk_score
            
            SAFE_THRESHOLD = 15 
            
            if risk_score > SAFE_THRESHOLD:
                print(f"[!] HIGH RISK: Score {risk_score} exceeds threshold. Flagged as Suspicious.")
                return risk_score
            else:
                print(f"[V] LOW RISK: Score {risk_score} is within safe limits (Standard software behavior).")
                return risk_score

        except Exception as e:
            print(f"Error: {e}")
            return 0