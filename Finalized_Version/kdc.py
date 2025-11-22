"""
AS/TGS for a minimal Kerberos-style demo (with MFA + SIEM logging + password check).
- AS authenticates user using PASSWORD + MFA (something you know + something you have).
- TGS validates TGT + authenticator and issues a Service Ticket.
- All events logged via siem_logger.
"""

from __future__ import annotations
import base64
import hashlib
import json
import random
import time
from typing import Dict, Tuple, Optional

from cryptography.fernet import Fernet
import siem_logger


# =========================
# Password → Fernet Key
# =========================

def derived_key(password: str) -> bytes:
    """Derive Fernet key from password using SHA-256 (demo-only)."""
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)


# =========================
# User Credentials (Derived Keys)
# =========================

CREDENTIALS: Dict[str, bytes] = {
    "bob":   derived_key("123"),
    "Alice": derived_key("helloWorl$"),
    "Smey":  derived_key("iLxvM0n3y"),
    "Pich":  derived_key("Blu3T3@m_Ismyf4v"),
}


# =========================
# TGS & Service Keys
# =========================

TGS_KEY: bytes = b'0H1mYxCLl3mP4o2rjQ6vK4cP0pC3C0yDsn7pKQ6reWQ='

SERVICE_KEYS: Dict[str, bytes] = {
    "1": b'tvvN_CgyYJ-ulmJaMnBTLV2mP2lEnzHUUAnyy3wS444=',
    "2": b'dVhoWgGGmhs4Ba9fElaiMXAhHmre0foIZC6ve9pxf6w=',
    "3": b'-XnUYdt9YC8Y9ouuc4k8zSDPw7izkBqbLu8JixBgwW8=',
    "4": b'7Qq8wK6kB7n9b7q1l0MZ1Nf9m2Ew7l0f7fJ4mDk0c6Q=',
    "5": b'3P0lKM2s1yRkE6Hc6S2oZ8l7b2j6fM3q8X1tC5R9hWk=',
}


# =========================
# AUTHENTICATION SERVER (AS)
# =========================

def authentication_server(
    username: str,
    password: str,
    client_ip: str
) -> Optional[Tuple[bytes, bytes]]:
    """
    Returns:
      (AS_message_to_user [encrypted with user's key],
       TGT [encrypted with TGS_KEY])
    or None on failure.
    """

    # 1️⃣ Username check
    if username not in CREDENTIALS:
        print("[AS] ❌ Unknown user.")
        siem_logger.log_event("AS", username, "authentication", "fail", client_ip, "Unknown username")
        return None

    # 2️⃣ Password verification (string must match exactly)
    entered_key = derived_key(password)
    stored_key = CREDENTIALS[username]

    if entered_key != stored_key:
        print("[AS] ❌ Invalid password.")
        siem_logger.log_event("AS", username, "authentication", "fail", client_ip, "Wrong password")
        return None

    print("[AS] ✅ Password verified.")
    siem_logger.log_event("AS", username, "authentication", "success", client_ip, "Password verified")

    # 3️⃣ MFA Verification
    mfa_code = str(random.randint(100000, 999999))
    print(f"[AS] Sending MFA code to {username}'s trusted device...")
    time.sleep(1)
    print(f"[AS] (simulated) MFA code for {username}: {mfa_code}")

    entered = input("[AS] Enter MFA code: ").strip()
    if entered != mfa_code:
        print("[AS] ❌ MFA verification failed.")
        siem_logger.log_event("AS", username, "mfa_verification", "fail", client_ip, "Incorrect MFA")
        return None

    print("[AS] ✅ MFA verification successful.")
    siem_logger.log_event("AS", username, "mfa_verification", "success", client_ip)

    # 4️⃣ Issue TGT + TGS Session Key
    user_key = entered_key
    f_user = Fernet(user_key)

    tgt_id = "TGT-69"
    tgs_session_key = Fernet.generate_key()

    # Message to user (encrypted with password-derived key)
    as_msg_to_user = f_user.encrypt((tgt_id + "||").encode() + tgs_session_key)

    # TGT contents (encrypted with TGS key)
    tgt_payload = {
        "client_name": username,
        "tgt_id": tgt_id,
        "client_ip": client_ip,
        "tgs_session_key": tgs_session_key.decode(),
        "issued_at": int(time.time())
    }

    f_tgs = Fernet(TGS_KEY)
    tgt_encrypted = f_tgs.encrypt(json.dumps(tgt_payload).encode())

    print(f"[AS] (debug) Issued TGT for {username}.")
    siem_logger.log_event("AS", username, "tgt_issued", "success", client_ip)

    return as_msg_to_user, tgt_encrypted


# =========================
# Freshness Check
# =========================

def _fresh(timestamp: int, window_sec: int = 60) -> bool:
    """Basic freshness check for authenticators to stop replay attacks."""
    now = int(time.time())
    return abs(now - timestamp) <= window_sec


# =========================
# TICKET GRANTING SERVER (TGS)
# =========================

def ticket_granting_server(
    service_id: str,
    username: str,
    encrypted_user_authenticator: bytes,
    encrypted_tgt: bytes,
    client_ip: str
) -> Optional[Tuple[bytes, bytes]]:
    """
    Validate TGT + Authenticator and issue a Service Ticket (ST).
    Returns:
      (message_to_user [encrypted with TGS session key],
       service_ticket [encrypted with service key])
    or None on failure.
    """

    # 1️⃣ Service validation
    if service_id not in SERVICE_KEYS:
        print("[TGS] ❌ Invalid service_id.")
        siem_logger.log_event("TGS", username, "service_request", "fail", client_ip, "Invalid service ID")
        return None

    # 2️⃣ Decrypt TGT
    try:
        f_tgs = Fernet(TGS_KEY)
        tgt_plain = f_tgs.decrypt(encrypted_tgt)
        tgt = json.loads(tgt_plain.decode())
    except Exception as e:
        print("[TGS] ❌ TGT decrypt error:", e)
        siem_logger.log_event("TGS", username, "tgt_decrypt", "fail", client_ip, str(e))
        return None

    tgs_session_key_b = tgt.get("tgs_session_key", "").encode()
    tgt_user = tgt.get("client_name")
    tgt_ip = tgt.get("client_ip")

    # 3️⃣ Decrypt client authenticator
    try:
        f_sess = Fernet(tgs_session_key_b)
        auth_plain = f_sess.decrypt(encrypted_user_authenticator).decode()
        auth_user, auth_ts_s = auth_plain.split("||", 1)
        auth_ts = int(auth_ts_s)
    except Exception as e:
        print("[TGS] ❌ Authenticator decrypt error:", e)
        siem_logger.log_event("TGS", username, "authenticator", "fail", client_ip, str(e))
        return None

    # 4️⃣ Checks: freshness, username, IP
    if not _fresh(auth_ts):
        print("[TGS] ❌ Replay detected (stale authenticator).")
        siem_logger.log_event("TGS", username, "authenticator", "fail", client_ip, "Replay detected")
        return None

    if auth_user != username or tgt_user != username:
        print("[TGS] ❌ Username mismatch.")
        siem_logger.log_event("TGS", username, "authenticator", "fail", client_ip, "Username mismatch")
        return None

    if tgt_ip != client_ip:
        print("[TGS] ❌ Client IP mismatch.")
        siem_logger.log_event("TGS", username, "authenticator", "fail", client_ip, "IP mismatch")
        return None

    # 5️⃣ Issue Service Ticket
    st_session_key = Fernet.generate_key()
    to_user = f_sess.encrypt(service_id.encode() + b"||" + st_session_key)

    st_payload = {
        "client_name": username,
        "service_id": service_id,
        "client_ip": client_ip,
        "st_session_key": st_session_key.decode(),
        "issued_at": int(time.time())
    }

    f_service = Fernet(SERVICE_KEYS[service_id])
    service_ticket = f_service.encrypt(json.dumps(st_payload).encode())

    print(f"[TGS] ✅ Issued ST for {username} to access service {service_id}.")
    siem_logger.log_event("TGS", username, "ticket_granted", "success", client_ip, f"Service {service_id}")

    return to_user, service_ticket


# =========================
# Expose service keys to Service Server
# =========================

def services_storage() -> Dict[str, bytes]:
    """Expose service keys to the service server."""
    return dict(SERVICE_KEYS)
