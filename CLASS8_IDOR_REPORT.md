# Class 8 Lab — Read anyone's grade, then lock the door

**Student Name:** Zheng Yuxiang
**Student ID:** 2023903113
**Date:** November 12, 2026
**Course:** Computer Security — EPITA
**Target flaw:** #7 — Broken access control (IDOR) in `/api/notes/<id>`

---

## Prediction
Logged in as `alice`, requesting `/api/notes/3` (not hers) → **someone else's grade**
(the server authenticates but never authorises).

## Part 1 — Proof you got in (IDOR)
As `alice` (user_id 6), walking the ids returned other students' grades:

| Request | Result |
|---------|--------|
| `/api/notes/1` | alice's own (Maths, 16.2) — allowed |
| **`/api/notes/3`** | **bob (student_id 7): Maths, grade 12.6, "Solid work, keep it up."** — leaked |
| `/api/notes/1..10` | the whole class (alice, bob, carol, dave, eve …) |

The server checked the wristband at the door (authentication) but never checked
whose locker was opened (authorisation). This is **IDOR — flaw #7**.

## Part 2 — The hole
`api_notes` asked only the first security question and skipped the second:
- **Authentication** — "are you logged in?" → `if not ident` ✓
- **Authorisation** — "is this note yours?" → never asked ✗

The note row already carries `student_id` (owner); `ident` already carries
`user_id`. The fix just compares them.

## Part 3 — The fix
Ownership check added right after the note is fetched:

```python
if not note or not can_read_note(ident, note):
    return jsonify({"error": "not found"}), 404
```

`can_read_note`: a **student** may read only `student_id == own user_id`; a
**teacher** may read notes of classes they teach; an **admin** may read any.

**Code chosen: [x] 404 not found   [ ] 403 forbidden** — 404 does not even
confirm the id exists, so an attacker cannot map which ids are real; 403 would
leak existence.

## Part 4 — Confirm real users still work
| Request | Expected | Result |
|---------|----------|--------|
| as alice, `/api/notes/3` | refused | `{"error":"not found"}` |
| as alice, `/api/notes/1` | her own note | Maths 16.2 ✓ |
| as prof.turing, `/api/notes/3` | works (teacher) | bob, Maths 12.6 ✓ |

Only the cross-student read is refused.

## The deeper lesson
The same bug hides anywhere a URL id names a user-owned object
(`/invoice/<id>`, `/message/<id>`, `/order/<id>`). The server must decide what
you may see from your identity, on every object — never trust the URL.
