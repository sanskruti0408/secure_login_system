import sqlite3
from flask import Flask, render_template, request, redirect, url_for
from db import get_db, init_db
from security import hash_password
from validators import validate_registration
from datetime import datetime, timedelta, timezone
from flask import make_response
from security import (hash_password, verify_password, new_session_token,
                      hash_token, session_expiry, SESSION_LIFETIME)

MAX_ATTEMPTS = 5
LOCK_TIME = timedelta(minutes = 15)
DUMMY_HASH = hash_password("not-a-real-password")
GENERIC_ERROR = "Invalid username or password."


app = Flask(__name__)
init_db()

@app.route("/register", methods=["GET", "POST"])

def register():
    if request.method == "GET":
        return render_template("register.html", errors=[], username="", email="")

    username = request.form.get("username", "").strip().lower()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    errors = validate_registration(username, email, password)
    if errors:
        return render_template("register.html", errors=errors, username=username,
                               email=email), 400

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, hash_password(password)),
                )

    except sqlite3.IntegrityError:
        errors.append("Above username or email is already registered.")
        return render_template("register.html", errors=errors, username=username,
                               email=email), 409
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", error=None)

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None:
            verify_password(DUMMY_HASH, password) 
            return render_template("login.html", error=GENERIC_ERROR), 401

        now = datetime.now(timezone.utc)
        if user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > now:
            return render_template(
                "login.html",
                error="Too many failed attempts. Try again later."), 429

        if not verify_password(user["password_hash"], password):
            attempts = user["failed_attempts"] + 1
            locked_until = None
            if attempts >= MAX_ATTEMPTS:
                locked_until = (now + LOCK_TIME).isoformat()
                attempts = 0
            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]))
            return render_template("login.html", error=GENERIC_ERROR), 401

        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],))
        token = new_session_token()
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (hash_token(token), user["id"], session_expiry()))

    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("session", token, httponly=True, samesite="Lax",
                    max_age=int(SESSION_LIFETIME.total_seconds()))
    return resp

def get_current_user(conn):
    token = request.cookies.get("session")
    if not token:
        return None
    token_hash = hash_token(token)
    row = conn.execute(
        """
        SELECT users.id, users.username, sessions.expires_at
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ?
        """,
        (token_hash,)).fetchone()

    if row is None:
        return None
    if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return None
    return row

@app.route("/dashboard")

def dashboard():
    with get_db() as conn:
        user = get_current_user(conn)
    if user is None:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=user["username"])

@app.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get("session")
    if token:
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash = ?",
                         (hash_token(token),))
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie("session")
    return resp

if __name__ == "__main__":
    app.run(debug=True)
