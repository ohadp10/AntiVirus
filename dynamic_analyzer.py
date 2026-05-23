import time
import boto3
import paramiko
import os

class CloudDynamicAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        
        # === הכנס את הפרטים שלך כאן ===
        self.aws_access_key = "AKIAYF3TY4K4522YKTN6"
        self.aws_secret_key = "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"
        self.region = "eu-central-1" # או us-east-1
        self.instance_id = "i-010522a2b5ae85d27"
        self.key_pem_path = "sandbox_key.pem" 
        # ===============================
        
        self.ec2 = boto3.client(
            'ec2',
            region_name=self.region,
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key
        )

    def start_sandbox_instance(self):
        print("[*] Cloud: Starting EC2 Sandbox Instance...")
        self.ec2.start_instances(InstanceIds=[self.instance_id])
        
        print("[*] Waiting for instance to become available...")
        waiter = self.ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[self.instance_id])
        
        response = self.ec2.describe_instances(InstanceIds=[self.instance_id])
        public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress')
        print(f"[+] Cloud: Sandbox is UP. IP: {public_ip}")
        return public_ip

    def stop_sandbox_instance(self):
        print("[*] Cloud: Stopping EC2 Sandbox Instance to save costs...")
        self.ec2.stop_instances(InstanceIds=[self.instance_id])
        print("[+] Cloud: Sandbox is DOWN.")

    def run_analysis(self):
        logs = []
        # 1. הדלקת המכונה
        public_ip = self.start_sandbox_instance()
        
        # מחכים קצת כדי ששירות ה-SSH של ווינדוס יספיק לעלות
        print("[*] Waiting 30 seconds for Cloud SSH service to initialize...")
        time.sleep(30) 
        
        filename = os.path.basename(self.file_path)
        remote_malware_path = f"C:\\Sandbox\\{filename}"
        remote_report_path = "C:\\Sandbox\\analysis_report.txt"
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            print(f"[*] Connecting via SSH to Cloud Sandbox...")
            # מתחברים עם משתמש Administrator וקובץ ה-pem
            admin_password = "B)8p88Vt3(JmHA*Pl7lKgS5T7jUO?s6E" 
            ssh.connect(hostname=public_ip, username='Administrator', password=admin_password)
            
            print(f"[*] Uploading {filename} to Cloud Sandbox...")
            sftp = ssh.open_sftp()
            sftp.put(self.file_path, remote_malware_path)
            
            print("[*] Executing analysis agent in the cloud (Takes ~10-15 seconds)...")
            stdin, stdout, stderr = ssh.exec_command(f"python C:\\Sandbox\\agent.py {remote_malware_path}")
            
            # ממתינים שהפקודה תסיים לרוץ בענן
            exit_status = stdout.channel.recv_exit_status()
            
            print("[*] Downloading analysis report from Cloud...")
            try:
                sftp.get(remote_report_path, "cloud_report_temp.txt")
                with open("cloud_report_temp.txt", "r") as f:
                    logs = [line.strip() for line in f.readlines()]
                os.remove("cloud_report_temp.txt") # מחיקת הקובץ הזמני המקומי
            except Exception as e:
                print(f"[!] Could not fetch report: {e}")
            
            sftp.close()
            
        except Exception as e:
            print(f"[!] Cloud analysis error: {e}")
        finally:
            ssh.close()
            self.stop_sandbox_instance()
            
        return logs

# בלוק בדיקה
if __name__ == "__main__":
    # נסה להריץ את זה על וירוס הדמי שיצרנו קודם!
    tester = CloudDynamicAnalyzer(r"C:\Users\user\Desktop\MalwareDetection\dist\dummy_virus.exe") 
    results = tester.run_analysis()
    
    print("\n--- CLOUD ANALYSIS RESULTS ---")
    for r in results:
        print(r)