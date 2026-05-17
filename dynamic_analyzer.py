import time
import boto3
import paramiko # עבור חיבור SSH/SFTP למכונה המרוחקת
import os

class CloudDynamicAnalyzer:
    def __init__(self, file_path):
        self.file_path = file_path
        
        # לכאן תזין את פרטי החשבון כשיהיו לך
        self.aws_access_key = "YOUR_AWS_ACCESS_KEY"
        self.aws_secret_key = "YOUR_AWS_SECRET_KEY"
        self.region = "eu-central-1" # אזור השרת
        self.instance_id = "YOUR_EC2_INSTANCE_ID" # המזהה של המכונה הווירטואלית
        self.key_pem_path = r"C:\path\to\your\aws_key.pem" # מפתח ההתחברות למכונה
        
        # יצירת מופע התחברות ל-AWS
        self.ec2 = boto3.client(
            'ec2',
            region_name=self.region,
            aws_access_key_id=self.aws_access_key,
            aws_secret_access_key=self.aws_secret_key
        )

    def start_sandbox_instance(self):
        """מדליק את המכונה ב-AWS"""
        print("[*] Cloud: Starting EC2 Sandbox Instance...")
        self.ec2.start_instances(InstanceIds=[self.instance_id])
        
        # מחכה שהמכונה תעלה ותקבל IP
        waiter = self.ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[self.instance_id])
        
        # קבלת ה-IP הציבורי של המכונה
        response = self.ec2.describe_instances(InstanceIds=[self.instance_id])
        public_ip = response['Reservations'][0]['Instances'][0].get('PublicIpAddress')
        print(f"[+] Cloud: Sandbox is UP. IP: {public_ip}")
        return public_ip

    def stop_sandbox_instance(self):
        """מכבה את המכונה בסיום הניתוח"""
        print("[*] Cloud: Stopping EC2 Sandbox Instance...")
        self.ec2.stop_instances(InstanceIds=[self.instance_id])
        print("[+] Cloud: Sandbox is DOWN.")

    def run_analysis(self):
        """פונקציה שתעלה את הקובץ לענן ותריץ אותו"""
        print(f"[*] Cloud: Preparing to analyze {os.path.basename(self.file_path)} in AWS...")
        # 1. הדלקת המכונה
        # 2. העברת הקובץ ב-SFTP
        # 3. הפעלת הסקריפט מרחוק
        # 4. משיכת הלוגים חזרה
        # 5. כיבוי המכונה
        
        # בינתיים מחזירים לוגים ריקים כהכנה
        return ["Cloud Analysis is ready to be fully implemented."]