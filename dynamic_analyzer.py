import time
import boto3
import paramiko
import os
from dotenv import load_dotenv

# טעינת משתני הסביבה מתוך קובץ ה-.env
load_dotenv()

class DynamicAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        
        # משיכת הנתונים בצורה מאובטחת
        self.aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        self.region = os.getenv("AWS_REGION")
        self.instance_id = os.getenv("AWS_INSTANCE_ID")
        self.admin_password = os.getenv("EC2_ADMIN_PASSWORD")
        self.key_pem_path = "sandbox_key.pem" 
        
        # אם משהו חסר ב-.env נזרוק שגיאה מיד
        if not all([self.aws_access_key, self.aws_secret_key, self.instance_id, self.admin_password]):
            raise ValueError("[-] Missing critical AWS credentials in .env file!")
        
        self.ec2 = boto3.client(
            'ec2',
            region_name=self.region,
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key
        )

    def start_sandbox_instance(self):
        print("[*] Cloud: Starting EC2 Sandbox Instance...")
        self.ec2.start_instances(InstanceIds=[self.instance_id])
        
        print("[*] Waiting for instance to become available in AWS...")
        waiter = self.ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[self.instance_id])
        
        response = self.ec2.describe_instances(InstanceIds=[self.instance_id])
        public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress')
        print(f"[+] Cloud: Sandbox is UP. Public IP: {public_ip}")
        return public_ip

    def stop_sandbox_instance(self):
        print("[*] Cloud: Stopping EC2 Sandbox Instance to save costs...")
        self.ec2.stop_instances(InstanceIds=[self.instance_id])
        print("[+] Cloud: Sandbox is DOWN.")

    def _connect_ssh_with_retry(self, public_ip, max_retries=6, delay=15):
        """פונקציית עזר שמנסה להתחבר ל-SSH מספר פעמים, כי לווינדוס לוקח זמן לעלות"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        print("[*] Waiting for Windows SSH service to initialize...")
        for attempt in range(max_retries):
            try:
                # המתנה לפני ניסיון חיבור
                time.sleep(delay)
                print(f"[*] SSH Connection attempt {attempt + 1}/{max_retries}...")
                ssh.connect(hostname=public_ip, username='Administrator', password=self.admin_password, timeout=10)
                print("[+] SSH Connected successfully!")
                return ssh
            except Exception as e:
                print(f"    [-] Attempt {attempt + 1} failed: {e}")
                
        raise ConnectionError("Could not connect to SSH after multiple attempts. Is the SSH service running on the EC2 instance?")

    def run_analysis(self):
        logs = []
        # 1. הדלקת המכונה
        public_ip = self.start_sandbox_instance()
        
        # 2. התחברות SSH חכמה
        try:
            ssh = self._connect_ssh_with_retry(public_ip)
        except Exception as e:
            print(f"[!] {e}")
            self.stop_sandbox_instance()
            return []
            
        filename = os.path.basename(self.file_path)
        remote_malware_path = f"C:\\Sandbox\\{filename}"
        remote_report_path = "C:\\Sandbox\\analysis_report.txt"
        
        try:
            print(f"[*] Uploading {filename} to Cloud Sandbox...")
            sftp = ssh.open_sftp()
            sftp.put(self.file_path, remote_malware_path)
            
            print("[*] Executing analysis agent in the cloud (Takes ~15-30 seconds)...")
            # הפעלת הסוכן (אותו נכתוב בשלב הבא)
            stdin, stdout, stderr = ssh.exec_command(f"python C:\\Sandbox\\agent.py {remote_malware_path}")
            
            # ממתינים שהפקודה תסיים לרוץ בענן
            exit_status = stdout.channel.recv_exit_status()
            
            print(f"[*] Agent finished with exit status: {exit_status}")
            print("[*] Downloading analysis report from Cloud...")
            
            try:
                sftp.get(remote_report_path, "cloud_report_temp.txt")
                with open("cloud_report_temp.txt", "r") as f:
                    logs = [line.strip() for line in f.readlines()]
                os.remove("cloud_report_temp.txt")
                print("[+] Report downloaded successfully.")
            except Exception as e:
                print(f"[!] Could not fetch report (Agent might have failed): {e}")
            
            sftp.close()
            
        except Exception as e:
            print(f"[!] Cloud analysis error: {e}")
        finally:
            ssh.close()
            # קריטי: מכבים את המכונה תמיד, גם אם הקוד קרס, כדי למנוע חיובים מיותרים ב-AWS
            self.stop_sandbox_instance()
            
        return logs

# בלוק בדיקה
if __name__ == "__main__":
    tester = DynamicAnalyzer(r"C:\Users\user\Desktop\MalwareDetection\dist\dummy_virus.exe") 
    results = tester.run_analysis()
    
    print("\n--- CLOUD ANALYSIS RESULTS ---")
    for r in results:
        print(r)