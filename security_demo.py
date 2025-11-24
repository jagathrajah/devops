"""
Intentionally insecure Python code for SonarQube pipeline learning.
"""

import os
import hashlib
from flask import Flask, request
import sqlite3

app = Flask(__name__)

# ❌ Hardcoded secret (SonarQube flags)
SECRET_KEY = "SuperSecretKey123"

# ❌ Weak hashing (SonarQube flags)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# ❌ No input validation + SQL injection (SonarQube flags)
def get_user(username):
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}';"
    cur.execute(query)
    result = cur.fetchone()
    conn.close()
    return result

# ❌ No rate limiting + debug mode (security issue)
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    hashed = hash_password(password)
    user = get_user(username)

    if user and user[1] == hashed:
        return "Login successful"
    return "Login failed"

# ❌ Debug mode exposes internals (SonarQube flags)
if __name__ == "__main__":
    app.run(debug=False)
