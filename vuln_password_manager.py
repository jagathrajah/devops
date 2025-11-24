# password_manager_safe.py
# Secure password manager example (for demonstration). Suitable for small local use.
# Requires: pip install cryptography

import sqlite3
import hashlib
import json
import logging
import os
import secrets
import subprocess
import shlex
from typing import Optional
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO)

DB_PATH = "passwords_safe.db"
MASTER_FILE = "master.json"
# Encryption key file (generated once)
FERNET_KEY_FILE = "fernet.key"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "CREATE TABLE IF NOT EXISTS vault (id INTEGER PRIMARY KEY, site TEXT, username TEXT, password TEXT)"
    )
    conn.commit()
    conn.close()


def _derive_master_hash(password: str, salt: bytes, iterations: int = 200_000) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return urlsafe_b64encode(dk).decode("utf-8")


def store_master_password(password: str):
    """Store master password as PBKDF2 hash with salt in JSON (no pickle)."""
    salt = secrets.token_bytes(16)
    hashed = _derive_master_hash(password, salt)
    payload = {"salt": urlsafe_b64encode(salt).decode("utf-8"), "hash": hashed, "iterations": 200_000}
    with open(MASTER_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    logging.info("Master password set.")


def verify_master_password(password: str) -> bool:
    if not os.path.exists(MASTER_FILE):
        return False
    with open(MASTER_FILE, "r", encoding="utf-8") as f:
        payload = json.load(f)
    salt = urlsafe_b64decode(payload["salt"].encode("utf-8"))
    expected = payload["hash"]
    got = _derive_master_hash(password, salt, payload.get("iterations", 200_000))
    return secrets.compare_digest(got, expected)


def _ensure_fernet_key() -> bytes:
    if os.path.exists(FERNET_KEY_FILE):
        with open(FERNET_KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(FERNET_KEY_FILE, "wb") as f:
        f.write(key)
    # restrict file permissions if possible
    try:
        os.chmod(FERNET_KEY_FILE, 0o600)
    except Exception:
        pass
    return key


FERNET_KEY = _ensure_fernet_key()
FERNET = Fernet(FERNET_KEY)


def encrypt_password(plain: str) -> str:
    token = FERNET.encrypt(plain.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_password(token: str) -> str:
    return FERNET.decrypt(token.encode("utf-8")).decode("utf-8")


def add_password(site: str, username: str, password: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    enc = encrypt_password(password)
    c.execute("INSERT INTO vault (site, username, password) VALUES (?, ?, ?)", (site, username, enc))
    conn.commit()
    conn.close()
    logging.info("Password stored for site (redacted).")


def get_passwords_for_site(site: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # safe parameterized query
    c.execute("SELECT id, site, username, password FROM vault WHERE site = ?", (site,))
    rows = c.fetchall()
    conn.close()
    results = []
    for r in rows:
        results.append({"id": r[0], "site": r[1], "username": r[2], "password": decrypt_password(r[3])})
    return results


def generate_password(length: int = 16):
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._"
    return "".join(secrets.choice(alphabet) for _ in range(max(8, length)))


def run_shell_command(args: list):
    """Run commands without using a shell; args must be a list (safer)."""
    try:
        res = subprocess.run(args, capture_output=True, text=True, check=True)
        return res.stdout
    except subprocess.CalledProcessError as e:
        return e.stdout + e.stderr


def export_vault(filename: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, site, username, password FROM vault")
    rows = c.fetchall()
    conn.close()
    # write encrypted values so exported file doesn't leak plaintext secrets
    with open(filename, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps({"id": r[0], "site": r[1], "username": r[2], "password": r[3]}) + "\n")
    logging.info("Vault exported (passwords remain encrypted in export).")


def interactive_safe():
    init_db()
    print("=== Secure Password Manager (demo) ===")

    if not os.path.exists(MASTER_FILE):
        print("No master password found. Create one now.")
        pw = input("Set master password: ")
        if not pw:
            print("Master password cannot be empty.")
            return
        store_master_password(pw)
        print("Master password saved.")

    # authenticate
    attempts = 3
    while attempts > 0:
        m = input("Enter master password: ")
        if verify_master_password(m):
            break
        attempts -= 1
        print(f"Invalid master password. Attempts left: {attempts}")
    else:
        print("Authentication failed.")
        return

    while True:
        print("\nOptions: add, list, gen, export, shell, quit")
        cmd = input("> ").strip().lower()
        if cmd == "add":
            site = input("Site: ").strip()
            user = input("Username: ").strip()
            pwd = input("Password (leave empty to generate): ").strip()
            if not pwd:
                pwd = generate_password()
            add_password(site, user, pwd)
            print("Added.")
        elif cmd == "list":
            site = input("Site: ").strip()
            results = get_passwords_for_site(site)
            for r in results:
                print(r)
        elif cmd == "gen":
            try:
                l = int(input("Length: ").strip() or "16")
            except ValueError:
                l = 16
            print("Generated:", generate_password(l))
        elif cmd == "export":
            fn = input("Export filename: ").strip()
            export_vault(fn)
            print("Exported.")
        elif cmd == "shell":
            cmdline = input("Command (space-separated, e.g. ls -la): ").strip()
            if not cmdline:
                continue
            args = shlex.split(cmdline)
            out = run_shell_command(args)
            print(out)
        elif cmd == "quit":
            break
        else:
            print("Unknown command.")
