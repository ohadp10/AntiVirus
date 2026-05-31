class HeuristicRuleEngine:
    def __init__(self, static_results, dynamic_logs):
        self.static_results = static_results
        self.dynamic_logs = dynamic_logs
        
        # מטריצת המשקולות
        self.weights = {
            "suspicious_ep": 15,
            "high_entropy_section": 20,
            "custom_packer": 15,
            "suspicious_api_import": 10,  # לכל פונקציה מסוכנת (מקסימום 30)
            "assembly_anti_vm": 20,
            "assembly_dynamic_chains": 20,
            "dynamic_process_creation": 15,
            "dynamic_registry_persistence": 25, # ניטור שרידות ברג'יסטרי
            "dynamic_code_injection": 40, 
            "dynamic_sensitive_file_drop": 20,
            "dynamic_ransomware_note": 15,
            "dynamic_system32_touch": 25,
            "dynamic_network_c2": 25,
            "dynamic_ftp_leak": 30
        }
        
        self.threat_score = 0
        self.insights = []

    def _evaluate_static_data(self):
        """שקלול הממצאים מהניתוח הסטטי (PE, IAT, Assembly, Entropy)"""
        
        # 1. נקודת כניסה חשודה
        if self.static_results.get("is_ep_suspicious"):
            self.threat_score += self.weights["suspicious_ep"]
            self.insights.append("[STATIC] Suspicious Entry Point detected (+15).")
            
        # 2. דחיסה או אנטרופיה גבוהה
        if self.static_results.get("is_packed"):
            if not self.static_results.get("unpacked_successful"):
                self.threat_score += self.weights["custom_packer"]
                self.insights.append("[STATIC] Unknown/Custom packer detected - potential evasion (+15).")
                
        for sec in self.static_results.get("sections_info", []):
            if sec.get("is_high_entropy"):
                self.threat_score += self.weights["high_entropy_section"]
                self.insights.append(f"[STATIC] High Entropy in section '{sec['name']}' indicating encrypted payload (+20).")
                break # מספיק סקשן אחד מוצפן כדי לתת את הניקוד
                
        # 3. ייבוא פונקציות API זדוניות
        suspicious_imports = self.static_results.get("suspicious_imports", [])
        if suspicious_imports:
            score_to_add = min(len(suspicious_imports) * self.weights["suspicious_api_import"], 30)
            self.threat_score += score_to_add
            self.insights.append(f"[STATIC] Found highly suspicious API imports: {', '.join(suspicious_imports)} (+{score_to_add}).")

        # 4. התחמקות ברמת האסמבלי
        asm_heuristics = self.static_results.get("assembly_heuristics", {})
        if asm_heuristics.get("rdtsc_anti_vm") or asm_heuristics.get("cpuid_evasion") or asm_heuristics.get("peb_direct_access"):
            self.threat_score += self.weights["assembly_anti_vm"]
            self.insights.append("[STATIC] Assembly heuristics indicate Anti-VM or Evasion techniques (+20).")
            
        # 5. זיהוי טעינה דינמית ושרשראות קריאה
        if asm_heuristics.get("dynamic_api_loading") or asm_heuristics.get("chained_execution"):
            self.threat_score += self.weights["assembly_dynamic_chains"]
            self.insights.append("[STATIC] Assembly flow shows chained execution or dynamic API loading (+20).")

    def _evaluate_dynamic_data(self):
        """שקלול הממצאים מהניתוח הדינמי בענן (ETW, Tshark)"""
        
        if not self.dynamic_logs:
            self.insights.append("[DYNAMIC] No dynamic logs available (Execution failed or timed out).")
            return

        for log in self.dynamic_logs:
            # 1. יצירת תהליכים נסתרים או כלי מערכת
            if "PROCESS CREATED" in log and any(p in log.lower() for p in ["cmd.exe", "powershell.exe", "vssadmin.exe"]):
                self.threat_score += self.weights["dynamic_process_creation"]
                self.insights.append(f"[DYNAMIC] Malware spawned a suspicious shell process (+15).")
                
            # 2. שינויי רג'יסטרי 
            if "REGISTRY MODIFIED" in log:
                self.threat_score += self.weights["dynamic_registry_persistence"]
                self.insights.append(f"[DYNAMIC] Malware modified Registry Run Keys for persistence (+25).")
                
            # 3. הזרקות קבצים זדוניים או פגיעה בקבצי מערכת
            if "FILE CREATED" in log or "FILE MODIFIED" in log:
                if any(ext in log.lower() for ext in [".exe", ".bat", ".dll", ".ps1"]):
                    self.threat_score += self.weights["dynamic_sensitive_file_drop"]
                    self.insights.append(f"[DYNAMIC] Dropped executable/script file to disk (+20).")
                elif "windows\\system32" in log.lower():
                    self.threat_score += self.weights["dynamic_system32_touch"]
                    self.insights.append(f"[DYNAMIC] Attempted to modify critical System32 directory (+25).")
                elif ".txt" in log.lower():
                    self.threat_score += self.weights["dynamic_ransomware_note"]
                    self.insights.append(f"[DYNAMIC] Suspicious text file created/modified (Potential Ransomware Note) (+15).")

            # 4. הזרקות קוד לזיכרון
            if "virtualallocex" in log.lower() or "writeprocessmemory" in log.lower() or "code injection" in log.lower():
                self.threat_score += self.weights["dynamic_code_injection"]
                self.insights.append(f"[DYNAMIC] Critical: Process memory injection or RWX allocation detected (+40).")

            # 5. בקשות רשת ודליפת מידע
            if "HTTP REQUEST" in log or "DNS QUERY" in log:
                self.threat_score += self.weights["dynamic_network_c2"]
                self.insights.append(f"[DYNAMIC] Network connection established (Potential C2 Beaconing) (+25).")
                
            if "FTP CREDENTIALS" in log:
                self.threat_score += self.weights["dynamic_ftp_leak"]
                self.insights.append(f"[DYNAMIC] Detected credential leak over FTP (+30).")

    def calculate_threat_score(self):
        """
        פונקציה ראשית המחשבת את הציון הסופי ומגדירה את הסטטוס.
        """
        print("\n[*] Heuristic Engine: Calculating Threat Score...")
        
        self._evaluate_static_data()
        self._evaluate_dynamic_data()
        
        if self.static_results.get("is_hash_malicious") == "safe":
            print("[*] Heuristic Engine: File verified as SAFE by reputation. Applying Whitelist reduction.")
            self.insights.append("[WHITELIST] Known safe software signature detected. Threat score strictly reduced.")
            self.threat_score = min(self.threat_score, 30)

        # חסימת הציון ל-100 כדי שלא יחרוג מהסקאלה
        if self.threat_score > 100:
            self.threat_score = 100
            
        if self.threat_score < 40:
            final_verdict = "SAFE"
        elif 40 <= self.threat_score <= 74:
            final_verdict = "SUSPICIOUS"
        else:
            final_verdict = "MALICIOUS"
            
        print(f"[*] Threat Score: {self.threat_score}/100")
        print(f"[*] Final Verdict: {final_verdict}")
        
        return {
            "threat_score": self.threat_score,
            "final_verdict": final_verdict,
            "insights": list(set(self.insights)) 
        }