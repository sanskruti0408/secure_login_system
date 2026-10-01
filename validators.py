import re

USERNAME_RE = re.compile(r"[A-Za-z0-9_]{3,20}")
EMAIL_RE = re.compile("r[^@\s]+@[^@\s]+\.[^@\s]+")

def validate_registration(username: str, email: str, password: str) -> list[str]:
    errors =[]

    if not USERNAME_RE.fullmatch(username):
        errors.append("Username must be 3-20 characters: letters, digits, underscore only")

    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        errors.append("Enter a valid email address.")

    if len(password) <8:
        errors.append("Password must be at least 8 characters.")
    elif len(password) > 128:
        errors.append("Password must be at most 128 characters.")
    elif not(any(c.isalpha() for c in password) and any(c.isdigit() for c in password)):
        errors.append("Password must contain at least one letter and one digit.")

    return errors
