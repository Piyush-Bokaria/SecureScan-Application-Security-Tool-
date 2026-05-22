"""
vulnerable_app.py — Intentionally vulnerable Python code for testing SecureScan.

DO NOT use this code in production! Each function demonstrates a specific
vulnerability category that Bandit should detect and SecureScan should map
to the corresponding OWASP Top 10:2021 category.
"""

import hashlib
import os
import pickle
import random
import subprocess
import tempfile


# ── A03:2021 — Injection ──────────────────────────────────────────────

def execute_user_command(user_input):
    """OS Command Injection via subprocess with shell=True (B602, CWE-78)."""
    result = subprocess.call(user_input, shell=True)
    return result


def execute_with_os_system(command):
    """OS Command Injection via os.system (B605, CWE-78)."""
    os.system(command)


def unsafe_eval(expression):
    """Code Injection via eval() (B307, CWE-94)."""
    return eval(expression)


def unsafe_exec(code_string):
    """Code Injection via exec() (B102, CWE-78)."""
    exec(code_string)


# ── A07:2021 — Identification and Authentication Failures ─────────────

def connect_to_database():
    """Hardcoded password in source code (B105, CWE-259)."""
    password = "SuperSecret123!"
    db_config = {
        "host": "localhost",
        "port": 5432,
        "user": "admin",
        "password": password,
    }
    return db_config


# ── A02:2021 — Cryptographic Failures ─────────────────────────────────

def hash_password_insecure(password):
    """Use of weak MD5 hash (B303, CWE-328)."""
    return hashlib.md5(password.encode()).hexdigest()


def generate_token():
    """Use of non-cryptographic random for security (B311, CWE-330)."""
    token = random.randint(100000, 999999)
    return str(token)


def hash_with_sha1(data):
    """Use of weak SHA1 hash (B303, CWE-328)."""
    return hashlib.sha1(data.encode()).hexdigest()


# ── A08:2021 — Software and Data Integrity Failures ──────────────────

def load_untrusted_data(data_bytes):
    """Insecure deserialization with pickle (B301, CWE-502)."""
    return pickle.loads(data_bytes)


# ── A05:2021 — Security Misconfiguration ─────────────────────────────

def validate_input(user_input):
    """Using assert for validation — stripped in optimized mode (B101, CWE-703)."""
    assert user_input is not None, "Input cannot be None"
    assert len(user_input) > 0, "Input cannot be empty"
    return user_input


def create_temp_file():
    """Insecure temp file creation with mktemp (B306, CWE-377)."""
    tmp = tempfile.mktemp()
    with open(tmp, "w") as f:
        f.write("sensitive data")
    return tmp


# ── A01:2021 — Broken Access Control ─────────────────────────────────

def set_world_writable(filepath):
    """Overly permissive file permissions (B103, CWE-276)."""
    os.chmod(filepath, 0o777)


# ── Main (for manual testing) ────────────────────────────────────────

if __name__ == "__main__":
    print("This file is intentionally vulnerable for testing purposes.")
    print(f"MD5 of 'test': {hash_password_insecure('test')}")
    print(f"Random token: {generate_token()}")
