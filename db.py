import os
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()


def get_db():
    """
    Return a new psycopg2 connection to the Supabase PostgreSQL database.
    Uses environment variables from .env.
    """
    conn = psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 5432)),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        dbname=os.getenv("DB_NAME"),
        sslmode="require",          # Supabase always requires SSL
        cursor_factory=psycopg2.extras.RealDictCursor,
    )
    return conn
