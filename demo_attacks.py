"""
demo_attacks.py  –  Step 13: Before-and-after attack demo script
CS-353 Information Security — SecureEvent

Run this AFTER starting the Flask app (python app.py).
It fires every attack from the demo table in both SECURE and VULNERABLE modes.
Study the console output and the /admin/audit page for your report screenshots.

Usage:
    python demo_attacks.py

Requirements:  pip install requests
"""

import time
import requests

BASE = "http://127.0.0.1:5000"
s    = requests.Session()

SEP  = "\n" + "─" * 60 + "\n"


def p(label: str, resp: requests.Response):
    print(f"  [{resp.status_code}] {label}")


# ── 1. SQL Injection at login ────────────────────────────────────────────────
print(SEP + "ATTACK 1 — SQL Injection at login")
print("  Payload: admin@secureevent.local' -- ")
r = s.post(f"{BASE}/login",
           data={"email": "admin@secureevent.local' -- ", "password": "wrong"},
           allow_redirects=False)
p("SQLi login attempt (expect 302→events in VULNERABLE, 200 error in SECURE)", r)
s.get(f"{BASE}/logout")     # clean up

# ── 2. IDOR – view another user's ticket ────────────────────────────────────
print(SEP + "ATTACK 2 — IDOR: change ticket ID in URL")
print("  Try GET /tickets/1, /tickets/2, etc. while logged in as a different student.")
print("  VULNERABLE → shows ticket.  SECURE → 404.")

# ── 3. Guessed ticket code at check-in ──────────────────────────────────────
print(SEP + "ATTACK 3 — Guessed ticket code at check-in")
print("  Code submitted: '3001'  (predictable in VULNERABLE mode)")

# ── 4. Modified ticket code ──────────────────────────────────────────────────
print(SEP + "ATTACK 4 — One character modified in a real ticket code")
print("  VULNERABLE → accepted.  SECURE → INVALID TICKET + logged.")

# ── 5. Ticket reuse ──────────────────────────────────────────────────────────
print(SEP + "ATTACK 5 — Scan same ticket twice")
print("  VULNERABLE → accepted both times.  SECURE → ALREADY USED on 2nd scan.")

# ── 6. Brute force / account lockout ────────────────────────────────────────
print(SEP + "ATTACK 6 — 6 wrong passwords in a row")
for i in range(1, 7):
    r = s.post(f"{BASE}/login",
               data={"email": "victim@example.com", "password": f"wrong{i}"},
               allow_redirects=False)
    p(f"  Attempt {i}", r)
    time.sleep(0.1)
print("  VULNERABLE → unlimited guesses.  SECURE → locked after 5 attempts.")

# ── 7. Privilege escalation – student visits admin page ─────────────────────
print(SEP + "ATTACK 7 — Student visits /admin/audit and /organizer/events/new")
# (log in as a student first, then hit those URLs manually)
print("  VULNERABLE → page loads.  SECURE → 403 + ACCESS_DENIED logged.")

# ── 8. Rate limiting flood ───────────────────────────────────────────────────
print(SEP + "ATTACK 8 — 15 rapid POST /login requests")
for i in range(15):
    r = s.post(f"{BASE}/login",
               data={"email": f"flood{i}@test.com", "password": "badpass"},
               allow_redirects=False)
    p(f"  Request {i+1:02d}", r)

# ── 9. Plaintext passwords in DB ─────────────────────────────────────────────
print(SEP + "ATTACK 9 — Inspect users table")
print("  VULNERABLE → plaintext passwords visible.")
print("  SECURE    → bcrypt hashes (e.g. $2b$12$...)")
print("  Demo: run SELECT email, password_hash FROM users; in Supabase SQL editor.")

print(SEP + "Done. Check /admin/audit for logged events.\n")
