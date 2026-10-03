# 🔐 SecureAuth: Secure Login System

A secure login web application built with Flask and SQLite, featuring Argon2id password hashing, input validation, SQL injection protection, and server-side session management, built as Task 4 of a Cyber Security Internship.

## 🎯 Project Objective

The goal is to build a login system that applies the core defenses against common authentication attacks, with each protection implemented and tested directly rather than hidden behind a framework: hashed passwords, validated input, parameterized queries, sessions that can truly be invalidated, and protection against brute-force and cross-site request forgery.

## 🛡️ Features

- 🔑 Registration and login with **Argon2id** password hashing (unique random salt per password)
- ✅ Server-side input validation (username allowlist, password length and complexity rules)
- 💉 **SQL injection protection** using parameterized queries only
- 🍪 **Server-side session management**: random 256-bit session tokens, stored only as SHA-256 hashes, with 30-minute expiry
- 🚪 **Logout** that deletes the session on the server, so a copied cookie stops working
- 🔒 **Account lockout**: 5 failed attempts locks the account for 15 minutes
- 🧾 **CSRF protection** on logout using a per-session token and constant-time comparison
- 👁️ Responsive dark UI with a show/hide password toggle, with no external libraries or CDNs

## 🔍 Security Design

| Threat | Defense |
|---|---|
| Stolen password database | Argon2id with a unique random salt per password |
| SQL injection | Parameterized queries everywhere; strict validation as a second layer |
| Brute-force guessing | Account locked for 15 minutes after 5 failed attempts |
| Username enumeration at login | Identical error message for wrong username and wrong password, with response timing equalised using a dummy hash |
| Session theft from the database | Only the SHA-256 hash of each session token is stored |
| Cookie theft by scripts | `HttpOnly` and `SameSite=Lax` cookie flags |
| Session replay after logout | Session row is deleted on the server |
| Idle or stolen sessions | Sessions expire after 30 minutes |
| Cross-site request forgery | Per-session CSRF token checked on logout |
| XSS through echoed input | Jinja2 auto-escaping left enabled |
| Oversized password input | Passwords capped at 128 characters before hashing, so hashing cannot be abused to exhaust the server |

## 📁 Project Structure

```
secure_login_system/
│
├── app.py            # Flask app and routes
├── db.py             # Database connection and schema
├── security.py       # Argon2 hashing, session token helpers
├── validators.py     # Input validation rules
├── run.bat           # Optional Windows launcher
├── requirements.txt
├── static/
│   └── style.css
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   └── dashboard.html
└── app.db            # created automatically on first run (not in Git)
```

## ⚙️ Technologies Used

- Python
- Flask (routing, templating with Jinja2)
- SQLite (via the built-in `sqlite3` module)
- argon2-cffi (Argon2id password hashing)
- `secrets` and `hashlib` (session tokens and SHA-256)
- HTML and CSS

## 🚀 How to Run

### 1. Install dependencies

```
pip install -r requirements.txt
```

### 2. Start the app

```
python app.py
```

The app opens the login page in your browser automatically at `http://127.0.0.1:5000`. On Windows you can also double-click `run.bat`. The database is created on first run.

## 🔄 How It Works

1. **Register:** input is validated, the password is hashed with Argon2id, and the user is stored with a parameterized query.
2. **Login:** the password is verified against the stored hash. On success, a random session token is set as an `HttpOnly` cookie and only its SHA-256 hash is stored in the database.
3. **Protected pages:** each request hashes the incoming cookie, looks it up in the `sessions` table, and checks that it has not expired.
4. **Logout:** a POST request with a valid CSRF token deletes the session row and clears the cookie.

## 🧪 Testing Performed

- Registered users and confirmed the database stores only Argon2id hashes, with a different salt for each user
- Duplicate username or email is rejected, and usernames are case-normalised
- An injection-style username (`x' OR '1'='1`) is rejected by the validator
- Wrong password and unknown username return the identical error message
- 5 failed logins lock the account, and the correct password is refused while locked
- Logging in and out works, and visiting the dashboard while logged out redirects to login
- After logout, replaying the old session cookie is rejected
- Tampering with the CSRF token returns `403 Invalid CSRF token`

## 🔧 Design Decisions

- **Server-side sessions instead of Flask's default signed cookie.** With a client-side cookie, logout only clears the browser's copy and a stolen cookie stays valid until it expires. Storing sessions in the database makes logout a real invalidation.
- **Timing equalisation at login.** Without it, a nonexistent username returns instantly while an existing one takes the time of an Argon2 verification, which lets an attacker enumerate usernames by measuring response time. Verifying against a dummy hash makes both paths cost the same.
- **CSRF protection added after the core was working,** once a review showed that logout, a state-changing action, was still open to cross-site requests.
- **No framework authentication library.** Each protection is written out so the security logic is visible and explainable.

## ⚠️ Known Limitations

- Runs over plain HTTP in development, so the cookie `Secure` flag is off. A real deployment needs HTTPS with `Secure` enabled.
- `debug=True` is for development only. Production should use a WSGI server with debug off.
- The lockout can be abused to deliberately lock another user out of their account.
- Registration reveals whether a username or email is already taken.
- CSRF protection covers logout only, because the login and registration forms have no session to bind a token to.
- No email verification, password reset, or two-factor authentication.

## 🔒 Ethical Use

This project is intended for educational and defensive cybersecurity purposes, to understand how a secure authentication system is built.

## 🎓 Internship Project

- **Project:** Secure Login System
- **Domain:** Cyber Security & Ethical Hacking
- **Role:** Cyber Security Intern

This project was developed as part of a cybersecurity internship to demonstrate practical understanding of secure authentication: password hashing, input validation, injection defense, session management, and common web attack mitigations.

## 👩‍💻 Author

**Sanskruti Vharamble**

Diploma in Computer Engineering  
Cyber Security & Ethical Hacking
