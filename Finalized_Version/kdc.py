"""
AS/TGS for a minimal Kerberos-style demo (with MFA + SIEM logging).
- AS authenticates user with password + MFA (something you know + something you have).
- TGS validates the TGT + user authenticator and issues a Service Ticket.
- All events (success/fail) are logged to security_log.json via siem_logger.
"""

from __future__ import annotations
import base64, hashlib, json, time, random
from typing import Dict, Tuple, Optional
from cryptography.fernet import Fernet, InvalidToken
import siem_logger  # import SIEM logging module

# =========================
# Demo constants / storage
# =========================

TGS_KEY: bytes = b'0H1mYxCLl3mP4o2rjQ6vK4cP0pC3C0yDsn7pKQ6reWQ='  # demo key
SERVICE_KEYS: Dict[str, bytes] = {
    "1": b'tvvN_CgyYJ-ulmJaMnBTLV2mP2lEnzHUUAnyy3wS444=',
    "2": b'dVhoWgGGmhs4Ba9fElaiMXAhHmre0foIZC6ve9pxf6w=',
    "3": b'-XnUYdt9YC8Y9ouuc4k8zSDPw7izkBqbLu8JixBgwW8=',
    "4": b'7Qq8wK6kB7n9b7q1l0MZ1Nf9m2Ew7l0f7fJ4mDk0c6Q=',
    "5": b'3P0lKM2s1yRkE6Hc6S2oZ8l7b2j6fM3q8X1tC5R9hWk=',
}


# =========================
# User Credentials
# =========================

def derived_key(password: str) -> bytes:
    """Derive Fernet key from password using SHA-256 (for demo)."""
    digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(digest)


CREDENTIALS: Dict[str, bytes] = {
    "bob":   derived_key("123"),
    "Alice": derived_key("helloWorl$"),
    "Smey":  derived_key("iLxvM0n3y"),
    "Pich":  derived_key("Blu3T3@m_Ismyf4v"),
}


# =========================
# AS (Authentication Server)
# =========================

def authentication_server(username: str, client_ip: str) -> Optional[Tuple[bytes, bytes]]:
    """
    Returns:
      (AS_msg_to_user [encrypted with user's key],
       TicketGrantingTicket [encrypted with TGS_KEY])
    or None if user not found or MFA fails.
    """
    if username not in CREDENTIALS:
        print("[AS] Unknown user.")
        siem_logger.log_event("AS", username, "authentication", "fail", client_ip, "Unknown username")
        return None

    # =========================
    # MFA Verification
    # =========================
    mfa_code = str(random.randint(100000, 999999))
    print(f"[AS] Sending MFA code to {username}'s trusted device...")
    time.sleep(1.5)
    print(f"[AS] (simulated) MFA code for {username}: {mfa_code}")

    entered = input("[AS] Enter MFA code: ").strip()
    if entered != mfa_code:
        print("[AS] MFA verification failed.")
        siem_logger.log_event("AS", username, "mfa_verification", "fail", client_ip, "Incorrect MFA code")
        return None

    print("[AS] MFA verification successful.")
    siem_logger.log_event("AS", username, "mfa_verification", "success", client_ip)

    # =========================
    # Normal AS Ticket Flow
    # =========================
    user_key = CREDENTIALS[username]
    f_user = Fernet(user_key)

    tgt_id = "TGT-69"
    tgs_session_key = Fernet.generate_key()

    # Encrypt data for user (using password key)
    as_msg_to_user = f_user.encrypt((tgt_id + "||").encode() + tgs_session_key)

    # Ticket Granting Ticket (for TGS)
    tgt_payload = {
        "client_name": username,
        "tgt_id": tgt_id,
        "client_ip": client_ip,
        "tgs_session_key": tgs_session_key.decode(),
        "issued_at": int(time.time())
    }

    f_tgs = Fernet(TGS_KEY)
    tgt_encrypted = f_tgs.encrypt(json.dumps(tgt_payload).encode())

    print(f"[AS] (debug) Issued TGT for {username}: {tgt_payload}")
    siem_logger.log_event("AS", username, "tgt_issued", "success", client_ip)

    return as_msg_to_user, tgt_encrypted


# =========================
# TGS (Ticket Granting Server)
# =========================

def _fresh(ts: int, window_sec: int = 60) -> bool:
    """Basic freshness check to prevent replay attacks."""
    now = int(time.time())
    return abs(now - ts) <= window_sec


def ticket_granting_server(
    service_id: str,
    username: str,
    encrypted_user_authenticator: bytes,
    encrypted_tgt: bytes,
    client_ip: str
) -> Optional[Tuple[bytes, bytes]]:
    """Validate TGT + Authenticator and issue Service Ticket (ST)."""
    # 1️. Validate service ID
    if service_id not in SERVICE_KEYS:
        print("[TGS] Invalid service_id.")
        siem_logger.log_event("TGS", username, "service_request", "fail", client_ip, "Invalid service ID")
        return None

    # 2️. Decrypt TGT with TGS key
    try:
        f_tgs = Fernet(TGS_KEY)
        tgt_plain = f_tgs.decrypt(encrypted_tgt)
        tgt = json.loads(tgt_plain.decode())
    except (InvalidToken, ValueError) as e:
        print(f"[TGS] TGT decrypt error: {e}")
        siem_logger.log_event("TGS", username, "tgt_decrypt", "fail", client_ip, str(e))
        return None

    print("[TGS] (debug) Decrypted TGT:", tgt)
    tgs_session_key_b = tgt.get("tgs_session_key", "").encode()
    tgt_user = tgt.get("client_name")
    tgt_ip = tgt.get("client_ip")

    if not tgs_session_key_b or not tgt_user or not tgt_ip:
        print("[TGS] TGT missing fields.")
        siem_logger.log_event("TGS", username, "tgt_validation", "fail", client_ip, "Missing fields")
        return None

    # 3️. Decrypt client authenticator
    try:
        f_sess = Fernet(tgs_session_key_b)
        auth_plain = f_sess.decrypt(encrypted_user_authenticator).decode()
        auth_user, auth_ts_s = auth_plain.split("||", 1)
        auth_ts = int(auth_ts_s)
    except Exception as e:
        print(f"[TGS] Authenticator decrypt error: {e}")
        siem_logger.log_event("TGS", username, "authenticator", "fail", client_ip, str(e))
        return None

    if not _fresh(auth_ts):
        print("[TGS] Stale authenticator (possible replay).")
        siem_logger.log_event("TGS", username, "authenticator", "fail", client_ip, "Replay detected")
        return None

    if auth_user != username or tgt_user != username:
        print("[TGS] Username mismatch.")
        siem_logger.log_event("TGS", username, "authenticator", "fail", client_ip, "Username mismatch")
        return None

    if tgt_ip != client_ip:
        print("[TGS] Client IP mismatch.")
        siem_logger.log_event("TGS", username, "authenticator", "fail", client_ip, "IP mismatch")
        return None

    # 4️. Issue Service Ticket
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

    print(f"[TGS] Issued ST for {username} to access service {service_id}")
    siem_logger.log_event("TGS", username, "ticket_granted", "success", client_ip, f"Service {service_id}")

    return to_user, service_ticket


def services_storage() -> Dict[str, bytes]:
    """Expose service keys to service server."""
    return dict(SERVICE_KEYS)
