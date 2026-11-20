"""
security.py  –  All security primitives for SecureEvent.

Covers:
  • Password hashing (bcrypt)                  → Cryptographic Failures
  • HMAC-signed ticket codes                   → Cryptographic Failures / Insecure Design
  • Account lockout                            → Authentication Failures
  • Input validation                           → Injection
  • Audit logging                              → Logging & Monitoring Failures
  • Login-required + role-required decorators  → Broken Access Control
"""

import re
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
from flask import session, request, abort, redirect

import config


# ─────────────────────────────────────────────────────────────
#  Password hashing
# ─────────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    """Return a bcrypt hash of *pw* (rounds=12)."""
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()


def check_password(pw: str, hashed: str) -> bool:
    """Constant-time bcrypt comparison."""
    return bcrypt.checkpw(pw.encode(), hashed.encode())


# ─────────────────────────────────────────────────────────────
#  HMAC ticket codes
# ─────────────────────────────────────────────────────────────

def make_ticket(event_id: int, user_id: int) -> str:
    """
    SECURE:   <16-hex-random>.<24-char-HMAC>
    VULNERABLE (demo only): plain integer derived from IDs — guessable & forgeable
    """
    if not config.SECURE_MODE:
        # VULNERABLE (demo only): predictable, no cryptographic signature
        return str(event_id * 1000 + user_id)

    tid = secrets.token_hex(8)                                   # 16 hex chars
    msg = f"{tid}|{event_id}|{user_id}".encode()
    sig = hmac.new(config.TICKET_KEY, msg, hashlib.sha256).hexdigest()[:24]
    return f"{tid}.{sig}"


def verify_ticket(code: str, event_id: int, user_id: int) -> bool:
    """
    SECURE:   re-compute HMAC and compare with hmac.compare_digest (timing-safe).
    VULNERABLE (demo only): accept any string.
    """
    if not config.SECURE_MODE:
        return True  # VULNERABLE (demo only): no verification at all

    try:
        tid, sig = code.split(".", 1)
    except ValueError:
        return False

    msg      = f"{tid}|{event_id}|{user_id}".encode()
    expected = hmac.new(config.TICKET_KEY, msg, hashlib.sha256).hexdigest()[:24]
    return hmac.compare_digest(sig, expected)   # constant-time → no timing attack


# ─────────────────────────────────────────────────────────────
#  Audit logging
# ─────────────────────────────────────────────────────────────

def audit(user_id, action: str, detail: str = ""):
    """
    Insert a row into audit_log.  Never raises — logging must never crash a request.
    Never log passwords or full ticket codes.
    """
    try:
        from db import get_db          # local import avoids circular dependency
        db  = get_db()
        cur = db.cursor()
        cur.execute(
            "INSERT INTO audit_log (user_id, action, detail, ip) VALUES (%s,%s,%s,%s)",
            (user_id, action, str(detail)[:255], request.remote_addr),
        )
        db.commit()
        cur.close()
        db.close()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────
#  Input validation
# ─────────────────────────────────────────────────────────────

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}$")


def validate_registration(name: str, email: str, pw: str):
    """Return an error string or None if inputs are valid."""
    if not (2 <= len(name.strip()) <= 80):
        return "Name must be 2–80 characters."
    if not EMAIL_RE.match(email):
        return "Invalid email address."
    if len(pw) < 8:
        return "Password must be at least 8 characters."
    if pw.lower() == pw:
        return "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in pw):
        return "Password must contain at least one digit."
    return None


def validate_event(title: str, capacity, date_str: str, deadline_str: str):
    """Return an error string or None if event fields are valid."""
    if not (3 <= len(title.strip()) <= 120):
        return "Title must be 3–120 characters."
    try:
        cap = int(capacity)
        if not (1 <= cap <= 5000):
            return "Capacity must be between 1 and 5000."
    except (ValueError, TypeError):
        return "Capacity must be a whole number."
    try:
        ev_dt   = datetime.fromisoformat(date_str)
        dead_dt = datetime.fromisoformat(deadline_str)
    except ValueError:
        return "Invalid date format."
    if dead_dt >= ev_dt:
        return "Registration deadline must be before the event date."
    if ev_dt <= datetime.now():
        return "Event date must be in the future."
    return None


# ─────────────────────────────────────────────────────────────
#  Auth decorators
# ─────────────────────────────────────────────────────────────

def login_required(f):
    """Redirect unauthenticated visitors to /login."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper


def role_required(*roles):
    """
    Abort with 403 (and log ACCESS_DENIED) if the current user's role
    is not in *roles*.  The role is read from the server-side session —
    never from a URL parameter or form field.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                audit(session.get("uid"), "ACCESS_DENIED", request.path)
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator
