import os
import sys
import time
import urllib.request

def malicious_payload():
    print("Muhahaha! I am a completely harmless test virus.")
    time.sleep(2)
    
    # 1. פעולת מערכת קבצים (Drop file)
    current_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    dropped_file = os.path.join(current_dir, "hacked_by_ohad.txt")
    
    with open(dropped_file, "w") as f:
        f.write("You have been caught by the Dynamic Analyzer!")
    print(f"Dropped a suspicious file at: {dropped_file}")
    
    # 2. פעולת רשת (Network Connection)
    time.sleep(2)
    try:
        print("Attempting to connect to external server...")
        # הוירוס מנסה להתחבר לכתובת חיצונית כדי להדליף מידע (משתמשים באתר סתמי לבדיקה)
        urllib.request.urlopen("http://example.com", timeout=3)
        print("Connection successful!")
    except Exception as e:
        print(f"Connection failed: {e}")

if __name__ == "__main__":
    malicious_payload()