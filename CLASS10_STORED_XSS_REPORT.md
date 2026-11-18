# Class 10 Lab — Your words run in someone's browser, then take the power away

**Student Name:** Zheng Yuxiang
**Student ID:** 2023903113
**Date:** November 18, 2026
**Course:** Computer Security — EPITA
**Target flaw:** #10 — Stored cross-site scripting (XSS) in grade comments

---

## The one idea
Last class was injection on the way IN (your input becomes a command on the
server — SQL, the shell). This class is injection on the way OUT: text the
server STORES becomes code in a victim's browser. A browser does not just show
a page, it obeys it — `<script>…</script>` is run, not displayed.

NotesApp rendered each grade comment with autoescaping switched off:
```jinja
<td>{% autoescape false %}{{ n.comment }}{% endautoescape %}</td>
```
`autoescape false` is the whole bug: it hands whatever a teacher stored to every
reader's browser as live code. And it is **stored** — written once, fires for
every student who later opens the page, attacker not present.

## Part 1 — Break (plant a script, watch it fire)
As teacher `prof.turing`, saved on note 1 (alice's):
```
comment = <script>alert('XSS by Eve')</script>
```
Fetched as alice → her dashboard contained, unescaped:
```html
<td><script>alert('XSS by Eve')</script></td>
```
In a real browser the alert fires — and it runs **as alice**, with her session
(it could steal her cookie or act as her). This is stored XSS, flaw #10.

## Part 2 — Fix (put the glass back)
The bug is one flag in two templates: `dashboard.html` (line 15) and
`teacher.html` (line 47). Removed the `autoescape false` wrapper and let the
template escape by default:
```jinja
<td>{{ n.comment }}</td>
```
Not "ban the word script" (you can never list every payload) — stop turning off
the safety. Default escaping turns `<` into `&lt;`, so a script tag is shown,
never run.

## Part 3 — Closed (same input, no code)
Re-saved the same `<script>` comment, viewed as alice → the page now contains:
```html
<td>&lt;script&gt;alert(&#39;XSS by Eve&#39;)&lt;/script&gt;</td>
```
Only the escaped text; no live `<script>`, no alert. The glass is back.

## Part 4 — Real comments still display right
Saved `score < 10 on part 1 & 2, see me` → shown as:
```html
<td>score &lt; 10 on part 1 &amp; 2, see me</td>
```
The browser renders it as the teacher wrote it (`<` is a less-than sign, not a
tag). Normal text works; only code is neutralised.

## Hand-in
```
STORED XSS — NotesApp flaw #10 closed
  Break:  note 1 comment = <script>alert('XSS by Eve')</script>
          as alice -> raw <script> in page (alert runs, as alice)
  Fix:    removed {% autoescape false %} in dashboard.html AND teacher.html
  Closed: same comment -> &lt;script&gt;..., shown as text, no alert
  Real use: "score < 10 ... & retry" displays correctly [x]
```

## The deeper lesson — escape on the way out
Injection in (SQL/shell) and injection out (XSS) are one family, both
directions: data stays data. Never hand user text to the browser as code —
escape it. If you genuinely need some HTML (bold, links), do not disable
escaping — sanitise with an allow-list (e.g. the `bleach` library) and keep only
safe tags.
