"""
app.py  –  SecureEvent main Flask application.

Security features demonstrated:
  Step 3  – bcrypt password hashing        (Cryptographic Failures)
  Step 4  – SQL-injection defence + lockout (Injection, Authentication Failures)
  Step 5  – Role-based access control      (Broken Access Control)
  Step 6  – Event & registration logic     (Insecure Design, Injection)
  Step 7  – HMAC-signed tickets            (Cryptographic Failures)
  Step 8  – One-time check-in              (Insecure Design)
  Step 9  – Object-level ownership check   (Broken Access Control)
  Step 10 – Audit log                      (Logging & Monitoring Failures)
  Step 11 – Rate limiting                  (Authentication Failures)
  Step 12 – Server-side input validation   (Injection)

SECURE_MODE=true  → all defences active
SECURE_MODE=false → intentionally vulnerable branches (demo only)
"""

from datetime import datetime, timedelta

import psycopg2
from flask import (
    Flask, abort, flash, redirect, render_template,
    request, session, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import config
from db import get_db
from security import (
    audit, check_password, hash_password, login_required,
    make_ticket, role_required, validate_event,
    validate_registration, verify_ticket,
)

# ─────────────────────────────────────────────────────────────
#  App factory
# ─────────────────────────────────────────────────────────────

app = Flask(__name__)
app.secret_key = config.SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,       # JS cannot read the cookie
    SESSION_COOKIE_SAMESITE="Lax",      # CSRF mitigation
    # SESSION_COOKIE_SECURE=True,       # enable when serving over HTTPS
    PERMANENT_SESSION_LIFETIME=config.SESSION_LIFETIME,
)

# ─────────────────────────────────────────────────────────────
#  Rate limiter  (Step 11)
# ─────────────────────────────────────────────────────────────

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per hour"],
    storage_uri="memory://",
)


@app.errorhandler(429)
def rate_limit_handler(e):
    audit(session.get("uid"), "RATE_LIMITED", request.path)
    return render_template("429.html"), 429


# ─────────────────────────────────────────────────────────────
#  Home
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "uid" in session:
        return redirect(url_for("events"))
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────────────────
#  Auth – Register  (Step 3)
# ─────────────────────────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", secure=config.SECURE_MODE)

    name  = request.form.get("name",     "").strip()
    email = request.form.get("email",    "").strip().lower()
    pw    = request.form.get("password", "")
    role  = request.form.get("role", "student")

    # --- Server-side validation (Step 12) ---
    err = validate_registration(name, email, pw)
    if err:
        return render_template("register.html", error=err, secure=config.SECURE_MODE)

    if role not in ("student", "organizer"):
        role = "student"

    db  = get_db()
    cur = db.cursor()
    try:
        if config.SECURE_MODE:
            # SECURE: bcrypt hash + parameterized INSERT
            pw_stored = hash_password(pw)
        else:
            # VULNERABLE (demo only): plaintext storage
            pw_stored = pw

        cur.execute(
            "INSERT INTO users (name, email, password_hash, role) VALUES (%s,%s,%s,%s)",
            (name, email, pw_stored, role),
        )
        db.commit()
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        return render_template("register.html",
                               error="Email already registered.",
                               secure=config.SECURE_MODE)
    finally:
        cur.close(); db.close()

    flash("Account created! Please log in.", "success")
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────────────────
#  Auth – Login  (Step 4)
# ─────────────────────────────────────────────────────────────

MAX_ATTEMPTS  = 5
LOCK_MINUTES  = 10


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", secure=config.SECURE_MODE)

    email = request.form.get("email",    "").strip().lower()
    pw    = request.form.get("password", "")

    db  = get_db()
    cur = db.cursor()

    if not config.SECURE_MODE:
        # ── VULNERABLE (demo only): string concatenation → SQL injection ──
        query = f"SELECT * FROM users WHERE email='{email}' AND password_hash='{pw}'"
        cur.execute(query)
        user = cur.fetchone()
        cur.close(); db.close()
        if user:
            session["uid"]  = user["id"]
            session["role"] = user["role"]
            session["name"] = user["name"]
            return redirect(url_for("events"))
        return render_template("login.html", error="Invalid login", secure=False)

    # ── SECURE ──────────────────────────────────────────────────────────────
    cur.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cur.fetchone()

    # Lockout check
    if user and user["locked_until"] and user["locked_until"] > datetime.now():
        audit(user["id"], "LOGIN_BLOCKED", "account locked")
        cur.close(); db.close()
        return render_template("login.html",
                               error="Account temporarily locked. Try again later.",
                               secure=True)

    if user and check_password(pw, user["password_hash"]):
        # Reset counter on success
        cur.execute(
            "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=%s",
            (user["id"],),
        )
        db.commit()
        session.clear()                         # prevents session fixation
        session.permanent = True
        session["uid"]  = user["id"]
        session["role"] = user["role"]
        session["name"] = user["name"]
        audit(user["id"], "LOGIN_OK")
        cur.close(); db.close()
        return redirect(url_for("events"))

    # Failed attempt
    if user:
        attempts = user["failed_attempts"] + 1
        locked   = (datetime.now() + timedelta(minutes=LOCK_MINUTES)
                    if attempts >= MAX_ATTEMPTS else None)
        cur.execute(
            "UPDATE users SET failed_attempts=%s, locked_until=%s WHERE id=%s",
            (attempts, locked, user["id"]),
        )
        db.commit()
        audit(user["id"], "LOGIN_FAIL", f"attempt {attempts}")

    cur.close(); db.close()
    # Same error either way — do not reveal whether the email exists
    return render_template("login.html",
                           error="Invalid email or password.",
                           secure=True)


# ─────────────────────────────────────────────────────────────
#  Auth – Logout
# ─────────────────────────────────────────────────────────────

@app.route("/logout")
def logout():
    uid = session.get("uid")
    session.clear()
    audit(uid, "LOGOUT")
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────────────────
#  Events – List  (Step 6)
# ─────────────────────────────────────────────────────────────

@app.route("/events")
@login_required
def events():
    db  = get_db()
    cur = db.cursor()
    cur.execute("""
        SELECT e.*,
               u.name AS organizer_name,
               (SELECT COUNT(*) FROM registrations r
                WHERE r.event_id=e.id AND r.status='active') AS registered_count
        FROM events e
        JOIN users u ON u.id = e.organizer_id
        WHERE e.event_date > NOW()
        ORDER BY e.event_date ASC
    """)
    event_list = cur.fetchall()
    cur.close(); db.close()
    return render_template("events.html",
                           events=event_list,
                           now=datetime.now(),
                           secure=config.SECURE_MODE)


# ─────────────────────────────────────────────────────────────
#  Events – Create  (Step 6, Step 5)
# ─────────────────────────────────────────────────────────────

@app.route("/organizer/events/new", methods=["GET", "POST"])
@login_required
@role_required("organizer", "admin")
def new_event():
    if request.method == "GET":
        return render_template("new_event.html", secure=config.SECURE_MODE)

    title    = request.form.get("title",    "").strip()
    desc     = request.form.get("description", "").strip()
    capacity = request.form.get("capacity", "")
    ev_date  = request.form.get("event_date", "")
    deadline = request.form.get("reg_deadline", "")

    err = validate_event(title, capacity, ev_date, deadline)
    if err:
        return render_template("new_event.html", error=err, secure=config.SECURE_MODE)

    db  = get_db()
    cur = db.cursor()
    cur.execute(
        """INSERT INTO events (organizer_id, title, description, event_date, capacity, reg_deadline)
           VALUES (%s,%s,%s,%s,%s,%s) RETURNING id""",
        (session["uid"], title, desc, ev_date, int(capacity), deadline),
    )
    new_id = cur.fetchone()["id"]
    db.commit()
    cur.close(); db.close()
    audit(session["uid"], "EVENT_CREATED", f"event {new_id}: {title}")
    flash("Event created successfully!", "success")
    return redirect(url_for("events"))


# ─────────────────────────────────────────────────────────────
#  Registration  (Step 6, 7)
# ─────────────────────────────────────────────────────────────

@app.route("/events/<int:event_id>/register", methods=["POST"])
@login_required
@role_required("student")
@limiter.limit("20 per minute")
def register_event(event_id):
    db  = get_db()
    cur = db.cursor()

    cur.execute("SELECT * FROM events WHERE id=%s", (event_id,))
    ev = cur.fetchone()
    if not ev or ev["reg_deadline"] < datetime.now():
        cur.close(); db.close()
        flash("Registration is closed for this event.", "error")
        return redirect(url_for("events"))

    cur.execute(
        "SELECT COUNT(*) AS n FROM registrations WHERE event_id=%s AND status='active'",
        (event_id,),
    )
    if cur.fetchone()["n"] >= ev["capacity"]:
        cur.close(); db.close()
        flash("Event is full.", "error")
        return redirect(url_for("events"))

    code = make_ticket(event_id, session["uid"])
    try:
        cur.execute(
            "INSERT INTO registrations (event_id, user_id, ticket_code) VALUES (%s,%s,%s)",
            (event_id, session["uid"], code),
        )
        db.commit()
        audit(session["uid"], "REGISTER", f"event {event_id}")
        flash("Registered! Your ticket is ready.", "success")
    except psycopg2.errors.UniqueViolation:
        db.rollback()
        flash("You are already registered for this event.", "info")
    finally:
        cur.close(); db.close()

    return redirect(url_for("my_tickets"))


# ─────────────────────────────────────────────────────────────
#  My Tickets  (Step 9)
# ─────────────────────────────────────────────────────────────

@app.route("/my-tickets")
@login_required
@role_required("student")
def my_tickets():
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        """SELECT r.*, e.title, e.event_date FROM registrations r
           JOIN events e ON e.id = r.event_id
           WHERE r.user_id=%s ORDER BY e.event_date ASC""",
        (session["uid"],),
    )
    tickets = cur.fetchall()
    cur.close(); db.close()
    return render_template("my_tickets.html", tickets=tickets, secure=config.SECURE_MODE)


# ─────────────────────────────────────────────────────────────
#  View single ticket  (Step 9 – ownership check)
# ─────────────────────────────────────────────────────────────

@app.route("/tickets/<int:reg_id>")
@login_required
def view_ticket(reg_id):
    db  = get_db()
    cur = db.cursor()

    if config.SECURE_MODE:
        # SECURE: joins on user_id — only the owner can see their ticket
        cur.execute(
            """SELECT r.*, e.title, e.event_date FROM registrations r
               JOIN events e ON e.id=r.event_id
               WHERE r.id=%s AND r.user_id=%s""",
            (reg_id, session["uid"]),
        )
    else:
        # VULNERABLE (demo only): any authenticated user can view any ticket by ID
        cur.execute(
            """SELECT r.*, e.title, e.event_date FROM registrations r
               JOIN events e ON e.id=r.event_id
               WHERE r.id=%s""",
            (reg_id,),
        )

    reg = cur.fetchone()
    cur.close(); db.close()
    if not reg:
        abort(404)   # 404, not 403, so attackers cannot probe which IDs exist
    return render_template("ticket.html", reg=reg, secure=config.SECURE_MODE)


# ─────────────────────────────────────────────────────────────
#  Cancel registration
# ─────────────────────────────────────────────────────────────

@app.route("/tickets/<int:reg_id>/cancel", methods=["POST"])
@login_required
@role_required("student")
def cancel_ticket(reg_id):
    db  = get_db()
    cur = db.cursor()
    # Ownership check — only owner can cancel
    cur.execute(
        "UPDATE registrations SET status='cancelled' WHERE id=%s AND user_id=%s",
        (reg_id, session["uid"]),
    )
    db.commit()
    if cur.rowcount:
        audit(session["uid"], "CANCEL", f"ticket {reg_id}")
        flash("Registration cancelled.", "info")
    cur.close(); db.close()
    return redirect(url_for("my_tickets"))


# ─────────────────────────────────────────────────────────────
#  Organizer – attendee list  (Step 6)
# ─────────────────────────────────────────────────────────────

@app.route("/organizer/events/<int:event_id>/attendees")
@login_required
@role_required("organizer", "admin")
def attendees(event_id):
    db  = get_db()
    cur = db.cursor()

    cur.execute("SELECT * FROM events WHERE id=%s", (event_id,))
    ev = cur.fetchone()
    if not ev:
        cur.close(); db.close()
        abort(404)
    # Organizer may only view their own events (admin sees all)
    if session["role"] != "admin" and ev["organizer_id"] != session["uid"]:
        cur.close(); db.close()
        abort(403)

    cur.execute(
        """SELECT r.*, u.name, u.email FROM registrations r
           JOIN users u ON u.id=r.user_id
           WHERE r.event_id=%s ORDER BY r.id""",
        (event_id,),
    )
    regs = cur.fetchall()
    cur.close(); db.close()
    return render_template("attendees.html", event=ev, registrations=regs,
                           secure=config.SECURE_MODE)


# ─────────────────────────────────────────────────────────────
#  Check-in  (Step 8)
# ─────────────────────────────────────────────────────────────

@app.route("/organizer/events/<int:event_id>/checkin", methods=["GET", "POST"])
@login_required
@role_required("organizer", "admin")
@limiter.limit("60 per minute")
def checkin(event_id):
    db  = get_db()
    cur = db.cursor()

    cur.execute("SELECT * FROM events WHERE id=%s", (event_id,))
    ev = cur.fetchone()
    if not ev:
        cur.close(); db.close()
        abort(404)
    if session["role"] != "admin" and ev["organizer_id"] != session["uid"]:
        cur.close(); db.close()
        abort(403)

    if request.method == "GET":
        cur.close(); db.close()
        return render_template("checkin.html", event=ev,
                               result=None, secure=config.SECURE_MODE)

    code = request.form.get("code", "").strip()

    cur.execute(
        """SELECT * FROM registrations
           WHERE ticket_code=%s AND event_id=%s AND status='active'""",
        (code, event_id),
    )
    reg = cur.fetchone()

    if not reg or not verify_ticket(code, event_id, reg["user_id"]):
        audit(session["uid"], "CHECKIN_REJECTED",
              f"event {event_id} code={code[:20]}")
        cur.close(); db.close()
        return render_template("checkin.html", event=ev,
                               result="INVALID TICKET", secure=config.SECURE_MODE)

    # Atomic one-time flip: checked_in=false → true
    cur.execute(
        "UPDATE registrations SET checked_in=TRUE, checked_in_at=NOW() "
        "WHERE id=%s AND checked_in=FALSE",
        (reg["id"],),
    )
    db.commit()

    if cur.rowcount == 0:
        audit(session["uid"], "CHECKIN_REUSED", f"ticket {reg['id']}")
        cur.close(); db.close()
        return render_template("checkin.html", event=ev,
                               result="ALREADY USED", secure=config.SECURE_MODE)

    audit(session["uid"], "CHECKIN_OK", f"ticket {reg['id']}")
    cur.close(); db.close()
    return render_template("checkin.html", event=ev,
                           result="WELCOME", secure=config.SECURE_MODE)


# ─────────────────────────────────────────────────────────────
#  Admin – User management
# ─────────────────────────────────────────────────────────────

@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    db  = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, name, email, role, failed_attempts, locked_until FROM users ORDER BY id")
    users = cur.fetchall()
    cur.close(); db.close()
    return render_template("admin_users.html", users=users, secure=config.SECURE_MODE)


@app.route("/admin/users/<int:user_id>/role", methods=["POST"])
@login_required
@role_required("admin")
def change_role(user_id):
    new_role = request.form.get("role", "student")
    if new_role not in ("student", "organizer", "admin"):
        abort(400)
    db  = get_db()
    cur = db.cursor()
    cur.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))
    db.commit()
    cur.close(); db.close()
    audit(session["uid"], "ROLE_CHANGED", f"user {user_id} → {new_role}")
    flash(f"Role updated to {new_role}.", "success")
    return redirect(url_for("admin_users"))


# ─────────────────────────────────────────────────────────────
#  Admin – Audit log  (Step 10)
# ─────────────────────────────────────────────────────────────

@app.route("/admin/audit")
@login_required
@role_required("admin")
def view_audit():
    db  = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT * FROM audit_log ORDER BY ts DESC LIMIT 100"
    )
    rows = cur.fetchall()
    cur.close(); db.close()
    return render_template("audit.html", rows=rows, secure=config.SECURE_MODE)


# ─────────────────────────────────────────────────────────────
#  Error pages
# ─────────────────────────────────────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


# ─────────────────────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # debug=False is essential — debug=True exposes an interactive console
    app.run(debug=False, host="0.0.0.0", port=5000)
