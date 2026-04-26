#Malware Detection Software
import hashlib
import pefile
import re
from capstone import *

#חישוב החתימה ובדיקה מול מאגר נתונים
def calculateHash(filepath):
    print("\n--- 1. Calculating Hash ---")
    hash = hashlib.sha256()

    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash.update(byte_block)
            
            #בהמשך להוסיף בדיקה של החתימה במאגר נתונים
            return hash.hexdigest()
        
    except FileNotFoundError:
        return "File Wasn't found"
    except Exception as e:
        return e
    
#בדיקה האם הקובץ הוא קובץ PE לפי הmagic number
def checkMagicNumber(filepath):
    print("\n--- 2. Checking Magic Number ---")
    try:
        with open(filepath, "rb") as f:
            magicbytes = f.read(2)
            if magicbytes == b'MZ':
                return True
            else:
                return False
    except Exception as e:
        return e
    
#בדיקה האם יש סקשנים חשודים בקובץ
def analyzeSections(filepath):
    try:
        pe = pefile.PE(filepath)

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
            return False
        else:
            return True
    
    except Exception as e:
        print("Error parsing pe file")
        return False

#בדיקה האם הקובץ דחוס
def checkForPacking(filepath):
    try:
        pe = pefile.PE(filepath)
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

        if not is_packed:
            print("No obvious signs for packing")
            return False
        else:
            return True

    except Exception as e:
        print("Error checking for packing: {e}")
        return False      
    
#בדיקה האם יש מחרוזות עם כתובות חשודות
def extractStrings(filepath):
    try:
        print("\n--- 5. Extracting Strings & IOCs ---")
        with open(filepath, "rb") as f:
            data = f.read()
        
        # 1. חיפוש מחרוזות ASCII (רגיל)
        ascii_strings = re.findall(rb'[ -~]{4,}', data)
        
        # 2. חיפוש מחרוזות Unicode/Wide (טקסט של ווינדוס - אות, אפס, אות, אפס...)
        # התבנית מחפשת תו קריא ואחריו בייט null
        unicode_strings = re.findall(rb'(?:[\x20-\x7E][\x00]){4,}', data)
        
        # המרה וניקוי של הרשימות
        decoded_ascii = [s.decode("utf-8") for s in ascii_strings]
        decoded_unicode = [s.decode("utf-16le") for s in unicode_strings] # פענוח מיוחד לווינדוס
        
        all_strings = decoded_ascii + decoded_unicode
        
        print(f"Total strings found: {len(all_strings)}")
        
        # חיפוש IOCs בתוך כל המחרוזות שמצאנו
        ips = set()
        urls = set()
        
        # Regex לכתובות IP
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        # Regex לכתובות URL (כולל כאלה שמתחילים ב-www)
        url_pattern = re.compile(r'(?:http[s]?://|www\.)(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

        for s in all_strings:
            # בדיקת IP
            found_ips = ip_pattern.findall(s)
            for ip in found_ips:
                # סינון רעשים: נתעלם ממספרי גרסאות כמו 1.0.0.0
                if ip != "0.0.0.0" and not ip.startswith("127."): 
                    ips.add(ip)

            # בדיקת URL
            found_urls = url_pattern.findall(s)
            for url in found_urls:
                urls.add(url)
        
        # הדפסת תוצאות - בהמשך צריך לעשות בדיקה עם מאגר נתונים
        if ips:
            print(f"[!] Found Potential IPs: {list(ips)[:5]}") # מציג רק את ה-5 הראשונים
        else:
            print("[V] No suspicious IPs found.")

        if urls:
            print(f"[!] Found Potential URLs: {list(urls)[:5]}") # מציג רק את ה-5 הראשונים
        else:
            print("[V] No URLs found.")
            
    except Exception as e:
        print(f"Error extracting strings: {e}")

def analyzeAssembly(filepath):
    try:
        pe = pefile.PE(filepath)
        print("\n--- 6. Assembly Analysis (Heuristic Scoring) ---")

        # ... (אותו קוד חישוב כתובות כמו מקודם) ...
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase
        
        entry_section = None
        for section in pe.sections:
            if section.VirtualAddress <= entry_point_rva < section.VirtualAddress + section.Misc_VirtualSize:
                entry_section = section
                break
        
        if not entry_section:
            return 0 # ציון 0 אם לא הצלחנו לנתח

        entry_offset = entry_point_rva - entry_section.VirtualAddress + entry_section.PointerToRawData
        
        with open(filepath, "rb") as f:
            f.seek(entry_offset)
            code = f.read(100) # קוראים 100 בייטים

        # זיהוי ארכיטקטורה
        if pe.FILE_HEADER.Machine == 0x8664:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_32)

        # === כאן השינוי הגדול: מערכת ניקוד ===
        risk_score = 0
        
        for i in md.disasm(code, image_base + entry_point_rva):
            mnemonic = i.mnemonic
            
            # טבלת ניקוד
            if mnemonic == 'xor':
                risk_score += 5   # XOR חשוד יותר כי הוא משמש להצפנה
            elif mnemonic == 'jmp':
                risk_score += 2   # JMP הוא רגיל, אבל הרבה ממנו זה חשוד
            elif mnemonic == 'call':
                risk_score += 1   # CALL הוא הכי נפוץ ולגיטימי
            
            # דוגמה לזיהוי לולאה קצרה (חשוד מאוד!)
            if mnemonic in ['loop', 'loope', 'loopne']:
                risk_score += 10

        print(f"Final Heuristic Score: {risk_score}")
        
        # קביעת הסף (Threshold)
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


#נקודות לשיפור
#לבדוק את החתימות במאגר הנתונים, לבדוק חתימות זדוניות מוכרות ואולי גם להוסיף וויטליסט
#לבדוק כתובות חשודות מוכרות דרך מאגר נתונים
#בבדיקה של האנטרי פוינט צריך להגדיר סף ולהגדיר ציון לכל פעולה חשודה כדי לתת ציון סיכון יותר מדוייק

if __name__ == "__main__":
    fileToCheck = r"C:\Windows\System32\notepad.exe"

    print("scanning the file...")
    
    print("sha256 is: ", calculateHash(fileToCheck))

    print("MagicNumber: ", checkMagicNumber(fileToCheck))

    print(analyzeSections(fileToCheck))

    print(checkForPacking(fileToCheck))

    extractStrings(fileToCheck)

    analyzeAssembly(fileToCheck)
