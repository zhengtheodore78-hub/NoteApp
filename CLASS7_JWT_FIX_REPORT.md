# Class 7 Lab — Close All Three Holes (JWT, flaw #4)

**Student Name:** Zheng Yuxiang
**Student ID:** 2023903113
**Date:** October 30, 2026
**Course:** Computer Security — EPITA
**Target flaw:** #4 — Forgeable JWT (final fix)

Builds on the Class 6 report (`CLASS6_JWT_FORGE_REPORT.md`), which found and
exploited both breaks. This lab closes all three holes.

---

## Prediction (before starting)

**After the fix, will the old forged tokens still work?** → **NO**
- The `alg:none` token is stopped by rule 1 (reject none).
- The token signed with the old secret `s3cr3t` is stopped by rule 3 (the
  signing secret changed, so its signature no longer matches).

---

## The three rules — held by the server, not the ticket

| # | Rule | Closes | Status |
|---|------|--------|--------|
| 1 | No seal → no entry (reject `alg:none`) | break 1 (no signature) | ✅ done (Class 6) |
| 2 | Only accept HS256 (server pins the algorithm) | the whole trick | ✅ done (Class 6) |
| 3 | Secret is long and random, from the environment | break 2 (guessed secret) | ✅ done (this lab) |

### Rule 3 implementation

- `JWT_SECRET` is now a **256-bit random value** (64 hex chars) generated with
  `secrets.token_hex(32)`, stored in `.env` (gitignored) — never committed.
- `docker-compose.yml` injects it into the container: `JWT_SECRET: ${JWT_SECRET}`.
- `web/app.py` no longer falls back to the weak `"s3cr3t"`; if `JWT_SECRET`
  is absent the app refuses to start:

```python
JWT_SECRET = os.environ.get("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET is not set (put a long random value in .env).")
```

`verify_jwt()` (rules 1 & 2, from Class 6) pins the algorithm server-side:

```python
alg = header.get("alg", "").lower()
if alg != "hs256":              # reject "none" and anything but HS256
    return None
# ... HS256 signature verified against JWT_SECRET ...
```

---

## Final test — 2 forged tokens + 1 real login

Run against the rebuilt server (`docker compose up -d --build`):

| Test | Token / action | Status | Result |
|------|----------------|--------|--------|
| Forged #1 | `alg:none` (Part 1) | `401` | bounced — no signature |
| Forged #2 | HS256 signed with old `s3cr3t` (Part 2) | `401` | bounced — wrong secret |
| Real login | `alice` / `alicepw` | `302` | success — legitimate auth unaffected |

Both old forged tickets bounce; a real login still works. Prediction **NO** confirmed.

---

## Why all three are needed

- Reject `none` alone → still forgeable by guessing a weak secret (Class 6 Part 2).
- Long secret alone → still bypassable via `alg:none`.
- Pin HS256 → stops the attacker choosing the algorithm (e.g. `none`, or an
  RS256/HS256 confusion).

Only the three together make the token trustworthy. The server — never the
ticket — decides how to check it.

---

## Secret management note

`.env` (gitignored) holds both `AES_KEY` and the new `JWT_SECRET`; neither is
committed. `SECRET_KEY` (Flask session cookie) remains a dev value and is out
of scope for flaw #4.
