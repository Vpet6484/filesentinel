# modules/watermark.py

import json
import uuid
import hashlib
from datetime import datetime

from cryptography.fernet import Fernet


# =====================================================
# IMPORTANT: KEEP THIS KEY SECRET (DO NOT CHANGE LATER)
# =====================================================
# Generate once using:
# >>> from cryptography.fernet import Fernet
# >>> Fernet.generate_key()

SECRET_KEY = b'aV3uHQeRAhvsvOp1Dv-zxCDKx6DvVKP6YFJSBBj6YWI='

fernet = Fernet(SECRET_KEY)


# =====================================================
# CREATE WATERMARK TOKEN
# =====================================================

def generate_watermark(file_id, user_id, session_id):
    """
    Creates encrypted watermark token
    """

    payload = {
        "file_id": file_id,
        "user_id": user_id,
        "session_id": session_id,
        "timestamp": datetime.utcnow().isoformat(),
        "nonce": uuid.uuid4().hex
    }

    raw = json.dumps(payload)

    token = fernet.encrypt(raw.encode())

    return token.decode()


# =====================================================
# DECODE WATERMARK TOKEN
# =====================================================

def decode_watermark(token):
    """
    Decrypt watermark token
    """

    data = fernet.decrypt(token.encode())

    return json.loads(data.decode())


# =====================================================
# HASH WATERMARK (STORE IN DB)
# =====================================================

def hash_watermark(token):
    """
    Creates irreversible fingerprint for DB
    """

    return hashlib.sha256(token.encode()).hexdigest()
