"""
Intentionally insecure code for cybersecurity learning with SonarQube.
DO NOT use in real applications.
"""

import hashlib
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# ❌ Hardcoded credentials (SonarQube should flag this)
ADMIN_PASSWORD = "P@ssword123"

# ❌ Insecure database setup (no parameterization)
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}';"
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result

# ❌ Insecure hashing (MD5 is obsolete and weak)
def insecure_hash(password):
    return hashlib.md5(password.encode()).hexdigest()

# ❌ No rate limiting, brute-force vulnerable
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    hashed = insecure_hash(password)

    user = get_user(username)

    if user and user[1] == hashed:
        return "Login successful"
    else:
        return "Invalid login"

# ❌ Debug mode exposes server info
app.run(debug=True)
