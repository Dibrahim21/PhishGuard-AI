import os
import secrets

import psycopg2
from psycopg2 import IntegrityError
from psycopg2.extras import RealDictCursor

from werkzeug.security import generate_password_hash, check_password_hash


# =============================================================
# DATABASE CONNECTION
# =============================================================

DATABASE_URL = os.getenv("DATABASE_URL")


def get_connection():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL environment variable is not configured."
        )

    return psycopg2.connect(DATABASE_URL)


# =============================================================
# DATABASE INITIALIZATION
# =============================================================

def initialize_database():

    conn = get_connection()

    try:
        cursor = conn.cursor()

        # -----------------------------------------------------
        # USERS
        # -----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # -----------------------------------------------------
        # SESSIONS
        # -----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        # -----------------------------------------------------
        # SCAN HISTORY
        # -----------------------------------------------------

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id SERIAL PRIMARY KEY,
                user_id INTEGER,
                url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score DOUBLE PRECISION NOT NULL,
                phishing_probability DOUBLE PRECISION,
                legitimate_probability DOUBLE PRECISION,
                domain TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)

        # -----------------------------------------------------
        # INDEXES
        # -----------------------------------------------------

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_token
            ON sessions(token)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_user_id
            ON scan_history(user_id)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at
            ON scan_history(scanned_at DESC)
        """)

        conn.commit()

    finally:
        conn.close()


# =============================================================
# USER AUTHENTICATION
# =============================================================

def create_user(email, password):

    email = email.strip().lower()

    if not email or not password:
        raise ValueError(
            "Email and password are required."
        )

    password_hash = generate_password_hash(password)

    conn = get_connection()

    try:
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO users (
                email,
                password_hash
            )
            VALUES (%s, %s)
            RETURNING id
        """, (
            email,
            password_hash
        ))

        user_id = cursor.fetchone()[0]

        conn.commit()

        return user_id

    except IntegrityError:

        conn.rollback()

        raise ValueError(
            "An account with this email already exists."
        )

    finally:
        conn.close()


def authenticate_user(email, password):

    email = email.strip().lower()

    conn = get_connection()

    try:

        cursor = conn.cursor(
            cursor_factory=RealDictCursor
        )

        cursor.execute("""
            SELECT
                id,
                email,
                password_hash
            FROM users
            WHERE email = %s
        """, (email,))

        user = cursor.fetchone()

        if not user:
            return None

        if not check_password_hash(
            user["password_hash"],
            password
        ):
            return None

        return {
            "id": user["id"],
            "email": user["email"],
        }

    finally:
        conn.close()


# =============================================================
# SESSIONS
# =============================================================

def create_session(user_id):

    token = secrets.token_urlsafe(48)

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO sessions (
                user_id,
                token
            )
            VALUES (%s, %s)
        """, (
            user_id,
            token
        ))

        conn.commit()

        return token

    finally:
        conn.close()


def get_user_from_token(token):

    if not token:
        return None

    conn = get_connection()

    try:

        cursor = conn.cursor(
            cursor_factory=RealDictCursor
        )

        cursor.execute("""
            SELECT
                users.id,
                users.email
            FROM sessions
            INNER JOIN users
                ON users.id = sessions.user_id
            WHERE sessions.token = %s
        """, (token,))

        user = cursor.fetchone()

        if not user:
            return None

        return {
            "id": user["id"],
            "email": user["email"],
        }

    finally:
        conn.close()


def delete_session(token):

    if not token:
        return

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM sessions
            WHERE token = %s
        """, (token,))

        conn.commit()

    finally:
        conn.close()


# =============================================================
# SCAN HISTORY
# =============================================================

def save_scan(
    user_id,
    url,
    verdict,
    risk_score,
    phishing_probability=None,
    legitimate_probability=None,
    domain=None
):

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scan_history (
                user_id,
                url,
                verdict,
                risk_score,
                phishing_probability,
                legitimate_probability,
                domain
            )
            VALUES (
                %s,
                %s,
                %s,
                %s,
                %s,
                %s,
                %s
            )
            RETURNING id
        """, (
            user_id,
            url,
            verdict,
            risk_score,
            phishing_probability,
            legitimate_probability,
            domain
        ))

        scan_id = cursor.fetchone()[0]

        conn.commit()

        return scan_id

    finally:
        conn.close()


def get_scan_history(user_id, limit=100):

    conn = get_connection()

    try:

        cursor = conn.cursor(
            cursor_factory=RealDictCursor
        )

        cursor.execute("""
            SELECT
                id,
                url,
                verdict,
                risk_score,
                phishing_probability,
                legitimate_probability,
                domain,
                scanned_at
            FROM scan_history
            WHERE user_id = %s
            ORDER BY id DESC
            LIMIT %s
        """, (
            user_id,
            limit
        ))

        rows = cursor.fetchall()

        result = []

        for row in rows:

            item = dict(row)

            if item.get("scanned_at"):
                item["scanned_at"] = (
                    item["scanned_at"].isoformat()
                )

            result.append(item)

        return result

    finally:
        conn.close()


def delete_scan(user_id, scan_id):

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM scan_history
            WHERE id = %s
            AND user_id = %s
        """, (
            scan_id,
            user_id
        ))

        deleted = cursor.rowcount > 0

        conn.commit()

        return deleted

    finally:
        conn.close()


def clear_scan_history(user_id):

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute("""
            DELETE FROM scan_history
            WHERE user_id = %s
        """, (user_id,))

        deleted_count = cursor.rowcount

        conn.commit()

        return deleted_count

    finally:
        conn.close()