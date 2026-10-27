# Class 6 Part 3 — Forge a Wristband (JWT) Lab Report

**Student Name:** Zheng Yuxiang
**Student ID:** 2023903113
**Date:** October 27, 2026
**Course:** Computer Security — EPITA
**Target flaw:** #4 — Forgeable JWT

---

## Prediction (before starting)

| Part | Question | Prediction |
|------|----------|------------|
| 1 | Will the server accept a token with **no signature at all**? | **YES** |
| 2 | Once `none` is rejected and a real HS256 signature is required, can we **still** forge a teacher token? | **YES** |

---

## PART 1 — Forge a token with `alg:none`

**Goal:** make NotesApp believe we are a teacher and read a grade that is not ours — no password, no key.

**Root cause.** `verify_jwt()` trusted the algorithm named in the attacker-controlled header. For `{"alg":"none"}` it returned the payload with **no signature check**:

```python
alg = header.get("alg", "").lower()
if alg == "none":
    return payload            # no verification at all (flaw #4)
```

**Forged token.** Header `{"alg":"none"}`, payload `{"user_id":1,"username":"admin","role":"admin"}`, empty signature (the trailing `.` is kept because the code does `token.split(".")`). The identity is read from the `Authorization: Bearer` header by `current_identity()`.

**Evidence.**

| Request | Status | Meaning |
|---------|--------|---------|
| `GET /api/notes/1` (no token) | `401` | normal rejection |
| `GET /api/notes/1` (forged `alg:none`, role=admin) | `200` | **exploit works — note returned** |

PoC: `forge_jwt.py`.

> No password. No key. We wrote the identity ourselves and told the server not to check — it believed us.

---

## FIRST FIX — reject `alg:none` and pin the algorithm

`verify_jwt()` rewritten so the **server**, not the token, decides the algorithm:

```python
alg = header.get("alg", "").lower()
if alg != "hs256":           # reject "none" and anything but HS256
    return None
signing_input = f"{h_b64}.{p_b64}".encode()
expected = _b64url(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest())
if hmac.compare_digest(expected, sig_b64):
    return payload
return None
```

**Re-test.** The same forged `alg:none` token is now rejected:

| Request | Status |
|---------|--------|
| forged `alg:none` token | `401` ✓ |

Normal login is unaffected (session cookie auth does not use the Bearer JWT).

---

## PART 2 — Crack the seal

The server now demands a valid HS256 signature. But `JWT_SECRET` defaults to **`s3cr3t`** (6 characters) — guessable in milliseconds. An **offline** dictionary attack against a single captured token recovers it, then we sign our own token.

```
captured alice token -> brute-force HMAC over header.payload with a wordlist
CRACKED — the secret is: 's3cr3t'
```

We then minted a **validly signed** teacher token for `prof.turing` (user_id 2, who teaches class 1) and read note 3:

**Evidence (against the reject-none + HS256-pinned server).**

| Token | Status | Meaning |
|-------|--------|---------|
| forged `alg:none` | `401` | hole 1 closed |
| HS256 signed with the **cracked** secret | `200` | **still exploited** — read bob's grade (Math, 12.6) |

PoC: `crack_jwt.py`.

> Closing one hole leaves the other open. Rejecting `none` is not enough while the secret is weak.

---

## Root cause & remediation

Flaw #4 is **two independent breaks**:

| Break | Cause | Fix | Status |
|-------|-------|-----|--------|
| No signature | `alg:none` accepted | reject `none` | ✅ done |
| Guessed secret | `JWT_SECRET = s3cr3t` (weak) | long random secret (256-bit) | ⏳ Class 7 lab |
| (hardening) | algorithm chosen by token | pin to HS256 server-side | ✅ done |

The complete fix requires **all three** together.

---

## Note on secret management (this commit)

- The AES comment-encryption key was removed from `web/encryption.py` source and is now loaded from the environment (`AES_KEY`), set in `.env` which is **gitignored** — no key material is committed. The value is unchanged so existing encrypted comments still decrypt.
- `JWT_SECRET` remains `s3cr3t` on purpose, pending the Class 7 remediation (long random secret).
