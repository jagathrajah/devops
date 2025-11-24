# vuln_password_manager.py
# Intentionally vulnerable password manager for SAST training.
# DO NOT USE IN PRODUCTION.

import sqlite3
import hashlib
import logging
import os
import random
import pickle
import subprocess
from base64 import b64encode, b64decode

logging.basicConfig(level=logging.DEBUG)

# Hard-coded master password (SonarQube should flag hard-coded credentials)
MASTER_PASSWORD = "hunter2"

# Hard-coded "encryption key" (weak)
ENCRYPTION_KEY = "my-insecure-key-123"

DB_PATH = "passwords.db"

def init_db():
    # insecure: string formatting used directly in SQL (SQL injection risk)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS vault (id INTEGER PRIMARY KEY, site TEXT, username TEXT, password TEXT)")
    conn.commit()
    conn.close()

def weak_hash(secret: str) -> str:
    # Weak hashing (MD5) used intentionally
    m = hashlib.md5()
    m.update(secret.encode('utf-8'))
    return m.hexdigest()

def store_master_password(pw: str):
    # Stores master password hash in a local file (cleartext-ish process)
    # Uses pickle (dangerous with untrusted data)
    with open("master.bin", "wb") as f:
        pickle.dump({"master": pw, "hash": weak_hash(pw)}, f)
    logging.debug("Master password saved (insecure).")

def load_master_password():
    try:
        with open("master.bin", "rb") as f:
            data = pickle.load(f)  # insecure deserialization
            return data.get("master")
    except Exception:
        # Bare except — hides errors (bad practice)
        return None

def encrypt_password(pw: str) -> str:
    # NOT real encryption: base64 with a static key (very weak)
    token = f"{ENCRYPTION_KEY}:{pw}"
    return b64encode(token.encode('utf-8')).decode('utf-8')

def decrypt_password(token: str) -> str:
    raw = b64decode(token.encode('utf-8')).decode('utf-8')
    # naive split; insecure
    parts = raw.split(":")
    if len(parts) >= 2:
        return ":".join(parts[1:])
    return ""

def add_password(site: str, username: str, password: str):
    # SQL injection vulnerability via f-strings
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    sql = f"INSERT INTO vault (site, username, password) VALUES ('{site}', '{username}', '{encrypt_password(password)}')"
    c.execute(sql)
    conn.commit()
    conn.close()
    logging.info(f"Added password for site={site} user={username}")

def get_passwords_for_site(site: str):
    # Vulnerable to SQL injection
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    sql = "SELECT id, site, username, password FROM vault WHERE site = '%s'" % site
    c.execute(sql)
    rows = c.fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append({"id": r[0], "site": r[1], "username": r[2], "password": decrypt_password(r[3])})
    return results

def generate_password(length=8):
    # Weak RNG (random) instead of secrets — SAST should flag weak randomness
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(chars) for _ in range(length))

def run_shell_command(cmd: str):
    # Dangerous: using shell=True with user-provided input (command injection)
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return out.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8')

def export_vault(filename: str):
    # Writes DB contents to a plain file (might leak secrets)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM vault")
    rows = c.fetchall()
    conn.close()
    with open(filename, "w") as f:
        for r in rows:
            f.write(str(r) + "\n")
    logging.warning("Vault exported to file without encryption — insecure.")

def interactive():
    init_db()
    print("=== Vulnerable Password Manager (SAST demo) ===")
    master = load_master_password()
    if not master:
        print("No master password set. Setting up now.")
        pw = input("Set master password: ")
        store_master_password(pw)
        print("Master password stored (insecure).")
    else:
        m = input("Enter master password: ")
        if m != master:
            print("Invalid master password!")
            return

    while True:
        print("\nOptions: add, list, gen, export, shell, quit")
        cmd = input("> ").strip()
        if cmd == "add":
            site = input("Site: ")
            user = input("Username: ")
            pwd = input("Password: ")
            add_password(site, user, pwd)
        elif cmd == "list":
            site = input("Site (or % for all): ")
            # unsafe usage: if site == "%", this returns all (but also injection risk)
            results = get_passwords_for_site(site)
            for r in results:
                print(r)
        elif cmd == "gen":
            l = int(input("Length: ") or 8)
            print("Generated:", generate_password(l))
        elif cmd == "export":
            fn = input("Export filename: ")
            export_vault(fn)
        elif cmd == "shell":
            cmdline = input("Shell command to run: ")
            print(run_shell_command(cmdline))
        elif cmd == "quit":
            break
        else:
            # using eval unsafely: intentionally present
            try:
                # Danger: eval of user input
                print(eval(cmd))
            except Exception:
                pass

if __name__ == "__main__":
    interactive()
