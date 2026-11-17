# Class 9 Lab — Your words become commands, then take the power away

**Student Name:** Zheng Yuxiang
**Student ID:** 2023903113
**Date:** November 17, 2026
**Course:** Computer Security — EPITA
**Target flaws:** #8 — SQL injection (login) · #9 — Command injection (admin ping)

---

## The one idea
The server builds a sentence and hands it to an interpreter (the database = SQL,
the shell = OS commands). When user text is **glued** into that sentence, text
that contains the sentence's own punctuation (`'`, `--`, `;`) stops being data
and becomes command. The fix is always the same: **pass data as data, in its own
envelope — never glue it into the command.**

## Flaw #8 — SQL injection (login)

**Break:** username `admin' -- `, password `anything`.
The glued query became:
```
... WHERE username = 'admin' -- ' AND password = '...'
```
`'` closed the username blank; `-- ` commented out the whole `AND password`
check. Result: logged in as **admin with no password** — `/api/.../admin`
returned the full user table (ids, usernames, roles, delete buttons).

**Fix:** parameterised query — `%s` placeholders the driver fills with input as
data, never as SQL grammar:
```python
cur.execute("SELECT id, username, role, password FROM users WHERE username = %s", (username,))
```
Not "ban quotes" (you can never list every bad char) — stop gluing.

**Closed:** same `admin' -- ` now → login HTTP 200 (stays on login page), `/admin`
blocked. The quote is just a quote.

## Flaw #9 — Command injection (admin ping box)

**Break:** host `127.0.0.1; id; head -2 /etc/passwd`.
With `cmd = "ping -c 1 " + host` and `shell=True`, the shell read `;` as "run the
next command":
```
PING 127.0.0.1 ...
uid=1000(notesapp) gid=1000(notesapp) groups=1000(notesapp)   <- id ran
root:x:0:0:root:/root:/bin/bash                                <- /etc/passwd
```
Arbitrary command execution on the server (as user `notesapp` — the container is
not root, which limits but does not remove the RCE).

**Fix:** no shell; pass the command as an argument **list** so `host` is one
single argument from start to finish — there is no shell to read the `;`:
```python
subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=10)
```
Plus `valid_ping_host()` as a second wall (defence in depth).

**Closed:** same payload now → `Invalid host.`, no `id`/`passwd` output.

## Part 4 — real features still work
| Check | Result |
|-------|--------|
| alice login with real password | HTTP 302, dashboard shows her grades |
| plain `127.0.0.1` ping | works (`64 bytes from 127.0.0.1 ... 1 received`) |

Only the injected input is now inert.

## Hand-in
```
INJECTION — NotesApp flaws #8 (SQLi) and #9 (command injection) closed
  SQLi break:  username  admin' --   -> logged in as admin, password = none
  SQLi fix:    login() uses a parameterised query (%s + tuple), no string gluing
  SQLi closed: same username now -> login fails (HTTP 200), /admin blocked
  CmdI break:  host  127.0.0.1; id   -> ran id: uid=1000(notesapp)..., read /etc/passwd
  CmdI fix:    admin_ping() uses subprocess.run([...]) list, no shell=True (+ host validation)
  CmdI closed: same host now -> "Invalid host.", no command runs
  Real use:    alice login OK [x]   plain 127.0.0.1 ping OK [x]
```

## The deeper lesson
SQL and the shell were two languages, one mistake — text glued into a command
string. The same bug waits wherever text meets an interpreter (a database, a
shell, an HTML page = XSS, a file path). Always pass data as data.
