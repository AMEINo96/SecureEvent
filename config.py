import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

SECURE_MODE = os.getenv("SECURE_MODE", "true").lower() == "true"
SECRET_KEY  = os.getenv("SECRET_KEY", "change-me")
TICKET_KEY  = os.getenv("TICKET_KEY", "change-me-too").encode()

# Session lifetime
SESSION_LIFETIME = timedelta(minutes=30)
