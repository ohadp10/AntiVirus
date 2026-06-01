class HeuristicRuleEngine:
    def __init__(self, static_results, dynamic_logs):
        self.static_results = static_results
        self.dynamic_logs = dynamic_logs
        
        # 1. עץ האיומים (Behavioral Threat Tree)
        self.threat_tree = {
            "static": {
                "structure": {"suspicious_ep": 15},
                "obfuscation": {"custom_packer": 15, "high_entropy": 20},
                "imports": {"suspicious_api": 10},
                "assembly": {"anti_vm": 20, "dynamic_chains": 20}
            },
            "dynamic": {
                "process": {"shell_spawn": 15, "injection": 40},
                "registry": {"persistence": 25},
                "file_system": {"drop_exe": 20, "ransom_note": 15, "system32_touch": 25},
                "network": {"c2_beacon": 25, "ftp_leak": 30}
            }
        }
        
        self.threat_score = 0
        self.insights = []
        
        # מנגנוני מעקב חכמים
        self.flags = set() # אוסף דגלי התנהגות לטובת חישוב סינרגיה בסוף
        self.hit_counts = {} # סופר כמה פעמים הופעל כל חוק (לטובת מנגנון הדעיכה)

    def _add_score(self, category_path, insight_message, flag_to_add=None):
        """
        פונקציה חכמה להוספת ניקוד באמצעות מנגנון דעיכה (Decay).
        category_path: למשל ["static", "obfuscation", "high_entropy"]
        """
        # שליפת משקל הבסיס מתוך עץ ההחלטות
        base_score = self.threat_tree
        try:
            for key in category_path:
                base_score = base_score[key]
        except KeyError:
            return # נתיב לא חוקי בעץ

        # ניהול מנגנון הדעיכה (Decay)
        path_str = "->".join(category_path)
        hits = self.hit_counts.get(path_str, 0)
        
        # כל פגיעה נוספת באותו חוק שווה רק 75% מהפגיעה הקודמת
        decay_factor = 0.75 ** hits
        actual_score = int(base_score * decay_factor)
        
        if actual_score > 0:
            self.threat_score += actual_score
            self.hit_counts[path_str] = hits + 1
            
            # אם זו הפעם הראשונה, נוסיף את התובנה
            if hits == 0:
                self.insights.append(f"{insight_message} (+{actual_score})")
            
            # הוספת דגל התנהגות לטובת מנוע הסינרגיה
            if flag_to_add:
                self.flags.add(flag_to_add)

    def _evaluate_static_data(self):
        """ סריקת עץ הסטטיקה """
        # Structure
        if self.static_results.get("is_ep_suspicious"):
            self._add_score(["static", "structure", "suspicious_ep"], "[STATIC] Suspicious Entry Point detected.", "EVASION")
            
        # Obfuscation
        if self.static_results.get("is_packed") and not self.static_results.get("unpacked_successful"):
            self._add_score(["static", "obfuscation", "custom_packer"], "[STATIC] Unknown/Custom packer detected.", "OBFUSCATION")
            
        for sec in self.static_results.get("sections_info", []):
            if sec.get("is_high_entropy"):
                self._add_score(["static", "obfuscation", "high_entropy"], f"[STATIC] High Entropy in section '{sec['name']}' (Encrypted Payload).", "OBFUSCATION")
                break 
                
        # API Imports
        suspicious_imports = self.static_results.get("suspicious_imports", [])
        for api in suspicious_imports:
            self._add_score(["static", "imports", "suspicious_api"], f"[STATIC] Suspicious API import: {api}", "API_ABUSE")

        # Assembly Heuristics
        asm_heuristics = self.static_results.get("assembly_heuristics", {})
        if asm_heuristics.get("rdtsc_anti_vm") or asm_heuristics.get("cpuid_evasion") or asm_heuristics.get("peb_direct_access"):
            self._add_score(["static", "assembly", "anti_vm"], "[STATIC] Assembly heuristics indicate Anti-VM.", "EVASION")
            
        if asm_heuristics.get("dynamic_api_loading") or asm_heuristics.get("chained_execution"):
            self._add_score(["static", "assembly", "dynamic_chains"], "[STATIC] Assembly flow shows dynamic API loading.", "OBFUSCATION")

    def _evaluate_dynamic_data(self):
        """ סריקת עץ הדינמיקה על ידי פירוק לוגים מובנה """
        if not self.dynamic_logs:
            self.insights.append("[DYNAMIC] No dynamic logs available (Execution failed).")
            return

        for log in self.dynamic_logs:
            log_lower = log.lower()
            
            # Process Activity
            if "process created" in log_lower:
                if any(p in log_lower for p in ["cmd.exe", "powershell.exe", "vssadmin.exe"]):
                    self._add_score(["dynamic", "process", "shell_spawn"], "[DYNAMIC] Malware spawned a suspicious shell.", "SHELL_EXEC")
            
            if "virtualallocex" in log_lower or "writeprocessmemory" in log_lower or "code injection" in log_lower:
                self._add_score(["dynamic", "process", "injection"], "[DYNAMIC] Process memory injection detected.", "INJECTION")

            # Registry Activity
            if "registry modified" in log_lower:
                self._add_score(["dynamic", "registry", "persistence"], "[DYNAMIC] Registry modified for persistence.", "PERSISTENCE")

            # File System Activity
            if "file created" in log_lower or "file modified" in log_lower:
                if any(ext in log_lower for ext in [".exe", ".bat", ".dll", ".ps1"]):
                    self._add_score(["dynamic", "file_system", "drop_exe"], "[DYNAMIC] Dropped executable/script file to disk.", "FILE_DROP")
                elif "windows\\system32" in log_lower:
                    self._add_score(["dynamic", "file_system", "system32_touch"], "[DYNAMIC] Attempted to modify critical System32 directory.", "CRITICAL_FS")
                elif ".txt" in log_lower:
                    self._add_score(["dynamic", "file_system", "ransom_note"], "[DYNAMIC] Suspicious text file created (Potential Ransom Note).", "RANSOM_NOTE")

            # Network Activity
            if "http request" in log_lower or "dns query" in log_lower or "ja3 signature" in log_lower:
                self._add_score(["dynamic", "network", "c2_beacon"], "[DYNAMIC] Network connection established (Potential C2).", "NETWORK_C2")
            if "ftp credentials" in log_lower:
                self._add_score(["dynamic", "network", "ftp_leak"], "[DYNAMIC] Detected credential leak over FTP.", "DATA_LEAK")

    def _apply_synergy_rules(self):
        """
        מנוע הסינרגיה: מזהה דפוסי פעולה מורכבים המשלבים מספר פעולות יחד (Context-Aware Scoring).
        """
        if "OBFUSCATION" in self.flags and "NETWORK_C2" in self.flags and "FILE_DROP" in self.flags:
            self.threat_score = int(self.threat_score * 1.3)
            self.insights.append("[SYNERGY] Dropper Pattern Detected: Obfuscated file communicating externally to drop payloads (Score x1.3).")
            
        if "RANSOM_NOTE" in self.flags and "OBFUSCATION" in self.flags and "SHELL_EXEC" in self.flags:
            self.threat_score += 30
            self.insights.append("[SYNERGY] Ransomware Pattern Detected: Encrypted payload executing shells and dropping text files (+30).")
            
        if "PERSISTENCE" in self.flags and "INJECTION" in self.flags and "EVASION" in self.flags:
            self.threat_score = int(self.threat_score * 1.5)
            self.insights.append("[SYNERGY] Stealth APT Detected: Code injection combined with registry persistence and evasion techniques (Score x1.5).")

    def calculate_threat_score(self):
        print("\n[*] Heuristic Engine: Calculating Threat Score using Behavioral Tree & Synergy...")
        
        self._evaluate_static_data()
        self._evaluate_dynamic_data()
        self._apply_synergy_rules()
        
        if self.static_results.get("is_hash_malicious") == "safe":
            print("[*] Heuristic Engine: File verified as SAFE by reputation. Applying Whitelist reduction.")
            self.insights.append("[WHITELIST] Known safe software signature detected. Threat score heavily reduced.")
            self.threat_score = min(self.threat_score, 30)

        # נרמול הציון לטווח 0-100
        self.threat_score = min(100, max(0, self.threat_score))
            
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