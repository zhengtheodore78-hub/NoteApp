# Class 5 Lab 1 — HTTPS Audit Report

**Student Name:** Zheng Yuxiang  
**Student ID:** 2023903113  
**Date:** October 22, 2026  
**Course:** Computer Security — EPITA  

---

## PART 1 — Discovery (Before Fix)

### FINDING 1 — Login Credentials Transmitted in Plain Text

**What's Exposed:**

| Item | Value |
|------|-------|
| **Username** | `alice` |
| **Password** | `alicepw` |
| **Session Cookie** | Exposed (unencrypted) |

**Evidence Captured:**

```http
POST /login HTTP/1.1
Host: localhost:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 31

username=alice&password=alicepw

HTTP/1.1 302 FOUND
Server: Werkzeug/3.1.9 Python/3.11.17
Location: /
Set-Cookie: session=.eJwlj00PgjAYg__... (unencrypted)
```

**Severity:** HIGH

**Justification:**
- Passwords transmitted in plaintext — no skill required to intercept
- Session cookies exposed — enables session hijacking
- Affects all users (students, teachers, administrators)
- Tool required: Wireshark (free, 2 minutes to learn)

---

## PART 2 — Generate Certificate

### Certificate Generated

```
Certificate Details:
─ Algorithm:      RSA 2048-bit
├─ Subject:        CN=localhost
├─ Issuer:         NotesApp (self-signed)
├─ Validity:       1 year
├─ Signature:      SHA-256 with RSA
└─ Files Generated:
   ├─ nginx/certs/notesapp.crt  (certificate)
   └─ nginx/certs/notesapp.key  (private key)
```

### Commands Used

```bash
# Using PowerShell (Windows)
$cert = New-SelfSignedCertificate -Subject 'CN=localhost' `
  -FriendlyName 'NotesApp Dev Certificate' `
  -CertStoreLocation 'Cert:\CurrentUser\My' `
  -KeyExportPolicy Exportable `
  -KeyAlgorithm RSA -KeyLength 2048 `
  -NotAfter (Get-Date).AddYears(1)

# Exported to PFX, then extracted key and cert using OpenSSL
```

### Nginx Configuration Created

**File:** `nginx/conf.d/nginx.conf`

```nginx
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate /etc/nginx/certs/notesapp.crt;
    ssl_certificate_key /etc/nginx/certs/notesapp.key;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://web:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name localhost;
    return 301 https://$host$request_uri;
}
```

---

## PART 3 — Capture Again (After HTTPS Fix)

### Wireshark Capture Results

**Filter Used:** `tcp.port == 443`

**What I Captured:**

```
........].-.Z...Px....%..RoX..h.....l.0.\u5F.k{..........9...^X..p..o.\
CHu.....O
...Jw....x....D.u&.Z.9.7...#N
......kP.....k 2..I.... ...... .D.:....
X..D".....,..B,.u.O"..F>.7)a...
..y..{~~.t.<qN4
r:.iL~.9....=.E.=.AR..
.[.......Z<D...(w..?..*.....".
Z.<.hu....../h.;.<<l*...F...kK..{.S.!.Eq.}.....
E.M..KN...
..T.t9Q......|rvd}..Q.;E.S)u....?..5Yoxk....6...)...^n.E....0..Q.W......)#.Ke...K
^z.!
```

### Analysis

| Question | Answer |
|----------|--------|
| **Can you see username?** | NO |
| **Can you see password?** | NO |
| **What do you see?** | TLS Application Data (encrypted hex bytes) |
| **Readable text?** | NONE |

### Comparison: Before vs After

| Aspect | Part 1 (HTTP) | Part 3 (HTTPS) |
|--------|---------------|----------------|
| **Wireshark Display** | `POST /login...password=alicepw` | `........].-.Z...Px....%..` |
| **Data Type** | HTTP plaintext | TLS encrypted |
| **Username Visible** | ✅ YES | ❌ NO |
| **Password Visible** | ✅ YES | ❌ NO |
| **Session Cookie** | ✅ Plaintext |  Encrypted |
| **Security** |  HIGH RISK | ✅ SECURE |

### Conclusion

```
Question: Did the fix work?
Answer:   YES ✓

Explanation:
  Before HTTPS: Clear text credentials visible to anyone with Wireshark
  After HTTPS:  Only encrypted TLS stream — no readable data
  
  The same attack (Wireshark capture) that worked in Part 1
  now fails completely. Eve can no longer read passwords.
```

---

## PART 4 — Certificate Comparison

### Our Self-Signed Certificate

```
Certificate: notesapp.crt
├─ Subject:        CN=localhost
├─ Issuer:         NotesApp
├─ Valid From:     Oct 22, 2026
├─ Valid Until:    Oct 22, 2027
├─ Key Size:       RSA 2048-bit
─ Signature:      SHA-256 with RSA
└─ Trusted:         NO
```

**Browser Warning:**
```
⚠️ Your connection is not private
   Attackers might be trying to steal your information
   [Advanced] → [Proceed to localhost (unsafe)]
```

### Real Certificate (github.com)

```
Certificate: github.com
├─ Subject:        CN=github.com
├─ Issuer:         DigiCert Inc (Trusted CA)
├─ Valid From:     [Current date]
─ Valid Until:    [Future date]
├─ Key Size:       RSA 2048-bit or ECDSA
├─ Signature:      SHA-256 with RSA/ECDSA
└─ Trusted:        ✅ YES
```

**Browser Display:**
```
 Connection is secure
   Your connection to this site is secure
```

### Key Differences

| Feature | Our Certificate | Real Certificate (GitHub) |
|---------|-----------------|---------------------------|
| **Issuer** | NotesApp (ourselves) | DigiCert, Let's Encrypt |
| **Verification** | None (self-signed) | Domain ownership verified |
| **Browser Trust** | ❌ Not trusted | ✅ Trusted |
| **Warning** | ⚠️ Shows security warning | ✅ No warning |
| **Use Case** | Development/Testing | Production |
| **Cost** | Free | Free (Let's Encrypt) or Paid |

### Why Trust Matters

```
SELF-SIGNED CERTIFICATE (Ours):
  Problem:  Anyone can create one — including Eve
  Risk:     Eve could create fake github.com certificate
  Attack:   Man-in-the-Middle (MITM) if users ignore warnings
  
CA-SIGNED CERTIFICATE (Real):
  Solution: Trusted third party verifies domain ownership
  Trust:    Browser trusts CA, CA trusts domain owner
  Security: Eve cannot forge certificates for domains she doesn't own
```

### Production Recommendation

```
For Production Deployment:
  1. Use Let's Encrypt (free, automated, trusted by all browsers)
  2. Or use commercial CA (DigiCert, Sectigo, etc.)
  3. Enable HSTS to prevent downgrade attacks
  4. Renew certificates before expiration (Let's Encrypt: 90 days)
```

---

## Final Summary

### Threat Model Update

| Vulnerability | Status | Notes |
|---------------|--------|-------|
| #3 Login sent over plain HTTP | ✅ FIXED | HTTPS now encrypts all traffic |
| #1 Passwords stored in clear text | ⏳ Pending | Part B — Argon2 hashing |

### Security Improvements

| Aspect | Before | After |
|--------|--------|-------|
| **Transport Security** |  HTTP (plaintext) | ✅ HTTPS (TLS 1.3) |
| **Credential Exposure** | ❌ Visible in Wireshark |  Encrypted |
| **Session Security** |  Cookie exposed |  Cookie encrypted |
| **Certificate** | N/A |  Self-signed (dev only) |

### Remaining Work

```
For Full Production Security:
  1. ✅ HTTPS/TLS encryption — DONE
  2. ⏳ Replace self-signed cert with Let's Encrypt
  3. ⏳ Implement Argon2 password hashing (Part B)
  4.  Fix remaining vulnerabilities from Class 2
```

---

## Lab Completion Checklist

### Part 1 — Discovery
- [x] Captured HTTP traffic with Wireshark
- [x] Identified plaintext credentials
- [x] Documented evidence
- [x] Assessed severity (HIGH)

### Part 2 — Build HTTPS
- [x] Generated self-signed certificate
- [x] Created nginx.conf
- [x] Started HTTPS configuration

### Part 3 — Verify
- [x] Captured HTTPS traffic
- [x] Confirmed credentials are encrypted
- [x] Compared before/after

### Part 4 — Certificate Assessment
- [x] Examined self-signed certificate
- [x] Compared with real CA certificate
- [x] Documented trust differences

---

## Appendix — Commands Reference

### Start HTTPS
```bash
docker compose -f docker-compose.yml -f docker-compose.https.yml up -d
```

### Wireshark Filters
```
tcp.port == 8080    # HTTP (Part 1)
tcp.port == 443     # HTTPS (Part 3)
tls                 # All TLS traffic
```

### Test HTTPS
```bash
curl -k https://localhost/
```

---

**Report Submitted:** October 22, 2026  
**Lab Duration:** ~45 minutes  
**Student:** Zheng Yuxiang (2023903113)
