import socket

print("1. Testing raw network connection to Port 3306...")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3) # חותך את זה אחרי 3 שניות

try:
    s.connect(("127.0.0.1", 3306))
    print("2. SUCCESS! The port is OPEN and Python is allowed in.")
    s.close()
except Exception as e:
    print(f"\n[!] FAILED! The door is closed/blocked. Error:\n{e}")