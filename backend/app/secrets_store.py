"""Encryption for integration credentials at rest.

API keys are encrypted with Fernet (AES-128-CBC + HMAC-SHA256). The key comes
from the DASHBOARD_SECRET_KEY environment variable, or is generated once into a
local file with owner-only permissions. Decrypted secrets are only ever used
server-side to call the vendor API; they are never returned to the browser.
"""
import os

from cryptography.fernet import Fernet, InvalidToken

from .db import DATA_DIR

KEY_FILE = DATA_DIR / ".secret.key"


def _fernet() -> Fernet:
    key = os.environ.get("DASHBOARD_SECRET_KEY")
    if not key:
        if not KEY_FILE.exists():
            KEY_FILE.write_bytes(Fernet.generate_key())
            KEY_FILE.chmod(0o600)
        key = KEY_FILE.read_bytes().strip()
    return Fernet(key)


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str | None) -> str | None:
    if not token:
        return None
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken:
        return None
