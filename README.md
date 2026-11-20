# SecureEvent 🎟

**CS-353 Information Security** | Flask + Supabase (PostgreSQL) | 2026

> A university event-management system with a live **Vulnerable ↔ Secure** toggle for viva demonstrations.

---

## 👥 Team

| Member | Role |
|---|---|
| Muhammad Abdullah Rishi | [M1] Core app & DB schema |
| Muhammad Amein | [M2] Auth & access control |
| Laiba Naeem | [M3] Tickets, audit log, STRIDE, testing |

---

## 🔐 Security Features

| Feature | OWASP Category | CIA Goal |
|---|---|---|
| bcrypt password hashing (rounds=12) | Cryptographic Failures | Confidentiality |
| Parameterized SQL queries | Injection | Integrity |
| Account lockout after 5 failed attempts | Authentication Failures | Availability |
| HttpOnly + SameSite session cookies | Authentication Failures | Confidentiality |
| RBAC decorators (server-side session) | Broken Access Control | Confidentiality |
| Object-level ownership check on tickets | Broken Access Control | Confidentiality |
| HMAC-SHA256 signed ticket codes | Cryptographic Failures | Integrity |
| Atomic one-time check-in | Insecure Design | Integrity |
| Insert-only audit log | Logging & Monitoring Failures | Integrity |
| Rate limiting (Flask-Limiter) | Authentication Failures | Availability |
| Server-side input validation | Injection | Integrity |

---

## 🗂 Project Structure

```
secureevent/
├── app.py           # Flask routes + rate-limiter
├── config.py        # SECURE_MODE flag and secrets
├── db.py            # Supabase/PostgreSQL connection helper
├── security.py      # All security primitives
├── schema.sql       # PostgreSQL schema (run once in Supabase)
├── demo_attacks.py  # Step 13 attack demo script
├── requirements.txt
├── .env.example     # Template — copy to .env and fill in
├── .gitignore
└── templates/       # Jinja2 + TailwindCSS templates
    ├── base.html
    ├── login.html / register.html
    ├── events.html / new_event.html
    ├── my_tickets.html / ticket.html
    ├── checkin.html / attendees.html
    ├── audit.html / admin_users.html
    └── 403.html / 404.html / 429.html
```

---

## ⚙️ Setup

### 1. Clone & create virtual environment

```bash
git clone <your-repo-url>
cd secureevent

python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate    # Linux / Mac

pip install -r requirements.txt
```

### 2. Configure environment variables

```bash
cp .env.example .env
# Edit .env with your Supabase credentials and generated keys
```

Generate secret keys:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 3. Set up the database

1. Go to your **Supabase Dashboard → SQL Editor**
2. Paste and run the contents of `schema.sql`
3. Optionally insert a seed admin account (see the comment at the bottom of `schema.sql`)

Get your **connection details** from:  
`Supabase Dashboard → Settings → Database → Connection parameters`

### 4. Run the app

```bash
python app.py
```

Open → [http://127.0.0.1:5000](http://127.0.0.1:5000)

---

## 🎭 SECURE_MODE Demo Toggle

Edit `.env`:

```ini
SECURE_MODE=true    # All defences active
SECURE_MODE=false   # Intentionally vulnerable (demo only)
```

Restart the server after changing the flag. A colour banner at the top of every page shows the current mode.

---

## 🏴 Attack Demo (Step 13)

With the app running in both modes, run:

```bash
python demo_attacks.py
```

| # | Attack | VULNERABLE result | SECURE result |
|---|---|---|---|
| 1 | SQL injection at login (`admin@x.com' --`) | Logs in as admin | Rejected + LOGIN_FAIL logged |
| 2 | Change `/tickets/12` → `/tickets/13` | Shows another student's ticket | 404 |
| 3 | Guess ticket code `3001` at check-in | Accepted | INVALID TICKET + logged |
| 4 | Edit one character of a real code | Accepted | INVALID TICKET + logged |
| 5 | Scan same ticket twice | Accepted both times | ALREADY USED + logged |
| 6 | 6 wrong passwords in a row | Unlimited guesses | Lockout message |
| 7 | Student visits `/admin/audit` | Page loads | 403 + ACCESS_DENIED logged |
| 8 | 15 rapid login POSTs | All processed | 429 after the limit |
| 9 | View `users` table in Supabase | Plaintext passwords | bcrypt hashes |

---

## 📄 Report Notes

**Honest limitations** (must state in report):
- No HTTPS in local demo (cookies need `Secure` flag in production)
- No email verification
- No CSRF tokens (add Flask-WTF as optional extra)
- Rate-limit counters held in memory (reset on restart)
- No MFA

**Optional extras if time allows:**
- CSRF protection with Flask-WTF
- Fernet encryption of attendee data
- HTTPS with a self-signed certificate

---

## 🔎 STRIDE Threat Table

| Asset | STRIDE | Attack | Defence | OWASP |
|---|---|---|---|---|
| Login | Spoofing | Repeated password guessing | Lockout + rate limiting | Authentication Failures |
| Session | Spoofing | Stolen/fixed session cookie | HttpOnly, SameSite, session.clear() on login | Authentication Failures |
| Tickets | Tampering | Edit or guess a ticket code | HMAC-signed codes, server-side verification | Cryptographic Failures |
| Event data | Tampering | SQL injection in form fields | Parameterized queries + validation | Injection |
| Audit log | Repudiation | User denies action | Insert-only log with user, action, time, IP | Logging & Monitoring Failures |
| Attendee data | Information disclosure | Change ticket ID in URL | Ownership check in query | Broken Access Control |
| Passwords | Information disclosure | Database leak | bcrypt hashing | Cryptographic Failures |
| Endpoints | Denial of service | Request flooding | Rate limiting, capacity cap | Insecure Design |
| Admin pages | Elevation of privilege | Student visits admin URL | Role decorators from server session | Broken Access Control |
