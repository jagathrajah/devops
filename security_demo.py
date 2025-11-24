"""
Intentionally insecure Python code for SonarQube pipeline learning.
(This version fixes ONLY the SQL injection issue as requested.)
"""

import os
import hashlib
from flask import Flask, request
import sqlite3

app = Flask(__name__)

# ❌ Hardcoded secret (still intentionally insecure for learning)
SECRET_KEY = "SuperSecretKey123"

# ❌ Weak hashing (kept intentionally)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


# ✅ FIXED: No longer constructs SQL directly using f‑string
# Parameterized query prevents SQL injection
def get_user(username):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()

    # FIX: parameterized query instead of f-string
    query = "SELECT * FROM users WHERE username = ?;"
    cur.execute(query, (username,))

    result = cur.fetchone()
    conn.close()
    return result


# ❌ Still intentionally insecure (no rate limiting), but works for testing
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    hashed = hash_password(password)
    user = get_user(username)

    if user and user[1] == hashed:
        return "Login successful"
    return "Login failed"


# ❌ Debug disabled now for safety
if __name__ == "__main__":
    app.run(debug=False)
