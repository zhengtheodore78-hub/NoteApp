# Class 11 Lab — Requests you never meant to send (CSRF)

**Student Name:** Zheng Yuxiang
**Student ID:** 2023903113
**Date:** November 19, 2026
**Course:** Computer Security — EPITA
**Target flaw:** #11 — Cross-site request forgery (CSRF)

---

## The one idea
After login the browser attaches the session cookie to **every** request to
localhost:8080 by itself — even one another website asked it to send. NotesApp
only checked "is the cookie valid?", never "did this request come from my own
form?". So any page that makes the victim's browser POST /grades is accepted as
them. A cookie proves **who**, not **what they meant**.

## Part 1 — Break (cookie alone is trusted)
Logged in as `prof.turing`, then sent a forged `POST /grades` with only the
cookie (and a fake `Origin: http://evil.example`):
```
forged request: HTTP 302   -> accepted
```
Eve's note 10 became `20.0 / "Perfect work."`. The server never asked where the
request came from.

## Part 2 — Real attack (zero clicks)
A page `prize.html` on a *different* site (localhost:9000) with a hidden form
auto-submitting to `localhost:8080/grades`. With a teacher logged in, merely
**opening the link** changed note 10 to `19.5 / "Changed by Eve's page."` — the
teacher's own browser sent the request and attached the teacher's cookie. Eve
never touched NotesApp. (cross-site: request goes from :9000 to :8080.)

## Part 3 — Fix (a secret stamp only our forms print)
Three pieces (web/app.py + templates):
1. **Per-session token** — `secrets.token_urlsafe(32)`, exposed to templates as
   `csrf_token()`. Plus `SESSION_COOKIE_SAMESITE = "Lax"` (browser seatbelt).
2. **Check on every POST** — a `before_request` hook refuses any non-login POST
   whose `csrf_token` field does not match the session's, **fail-closed** (no
   stored token ⇒ refuse, so "" vs "" cannot pass):
   ```python
   if not expected or not hmac.compare_digest(sent, expected):
       abort(400, "CSRF token missing or wrong")
   ```
3. **Hidden field in every real form** —
   `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">` in
   teacher.html (1 form) and admin.html (3 forms: delete, create, ping).

Other sites cannot read the token (same-origin policy), so they cannot forge it.

## Part 4 — Proof
| Check | Result |
|-------|--------|
| forged POST /grades (no token) | **HTTP 400** — refused |
| real form (GET page → token → submit with token) | **HTTP 302** — saved, Eve back to 9.1 |
| browser: open prize.html while logged in | **400 Bad Request**, note 10 unchanged |

## Hand-in
```
CSRF — NotesApp flaw #11 closed
  Break:  prof.turing logged in, opened localhost:9000/prize.html
          note 10 -> 19.5, "Changed by Eve's page."
  Fix:    per-session token (secrets.token_urlsafe), checked on every POST,
          hidden csrf_token field in teacher.html (1) + admin.html (3)
  Closed: same page -> 400 Bad Request, grade unchanged
  Real use: teacher saves a grade [x]  admin add user [x]  admin ping [x]
```

## The deeper lesson
A cookie says who the browser belongs to, not whether that person chose to send
this request. Any state-changing request must also prove **intent** — a secret
only the server's own pages hold. `SameSite=Lax` helps but is the browser's
seatbelt; the server must not depend on it.
