"""
Service Server (with SIEM logging):
- Decrypts the Service Ticket (ST) using its long-term key.
- Validates the user authenticator (timestamp + username).
- Sends back a service authenticator (echo of service_id).
- Logs every event (success/failure) to security_log.json via siem_logger.
"""

from __future__ import annotations
import json, time
from typing import Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken
import kdc  # to read service keys
import siem_logger  # for centralized logging

SERVICE_KEYS = kdc.services_storage()

# Demo contents by service_id
SERVICE_CONTENTS = {
    "1": "[From: mjeat] Hello there. This is a Congratulation MESSAGE!!!",
    "2": "Welcome to Facebook. This is your home page... Buzz buzz",
    "3": "[From: mjeat] Hello, there. Congratulations!!! ...again... Texting from Telegram",
    "4": "Kerberos Guides — Step 1: ... (demo placeholder)",
    "5": "BreadCTF\\{th1s_1s_4_fl4g_9uy2\\}",
}


def service_handle(
    username: str,
    service_id: str,
    encrypted_user_authenticator: bytes,
    encrypted_st: bytes
) -> Optional[bytes]:
    """
    Validates ST + authenticator and returns encrypted server authenticator (service_id),
    or None on failure.
    """
    # 1️. Validate service ID
    if service_id not in SERVICE_KEYS:
        print("[SERVICE] Invalid service_id.")
        siem_logger.log_event("SERVICE", username, "service_access", "fail", "-", f"Invalid service ID: {service_id}")
        return None
    svc_key = SERVICE_KEYS[service_id]

    # 2️. Decrypt Service Ticket (ST)
    try:
        f_st = Fernet(svc_key)
        st_plain = f_st.decrypt(encrypted_st)
        st = json.loads(st_plain.decode())
    except (InvalidToken, ValueError) as e:
        print(f"[SERVICE] ST decrypt error: {e}")
        siem_logger.log_event("SERVICE", username, "st_decrypt", "fail", "-", str(e))
        return None

    print("[SERVICE] (debug) ST content:", st)
    st_user = st.get("client_name")
    st_sess_key_b = st.get("st_session_key", "").encode()

    if not st_user or not st_sess_key_b:
        print("[SERVICE] ST missing fields.")
        siem_logger.log_event("SERVICE", username, "st_validation", "fail", "-", "Missing fields in ST")
        return None

    # 3️. Decrypt user authenticator (client → service)
    try:
        f_sess = Fernet(st_sess_key_b)
        auth_plain = f_sess.decrypt(encrypted_user_authenticator).decode()
        auth_user, auth_ts_s = auth_plain.split("||", 1)
        auth_ts = int(auth_ts_s)
    except Exception as e:
        print(f"[SERVICE] ❌ Authenticator decrypt error: {e}")
        siem_logger.log_event("SERVICE", username, "authenticator", "fail", "-", str(e))
        return None

    # 4️. Freshness check
    if abs(int(time.time()) - auth_ts) > 60:
        print("[SERVICE] Stale authenticator (possible replay attack).")
        siem_logger.log_event("SERVICE", username, "replay_protection", "fail", "-", "Stale authenticator")
        return None

    # 5️. Username check
    if auth_user != username or st_user != username:
        print("[SERVICE] Username mismatch.")
        siem_logger.log_event("SERVICE", username, "username_check", "fail", "-", "Username mismatch")
        return None

    # If all checks pass
    encrypted_server_auth = f_sess.encrypt(service_id.encode())
    print("[SERVICE] returning encrypted server authenticator.")
    siem_logger.log_event("SERVICE", username, "service_access", "success", "-", f"Access granted to Service {service_id}")
    return encrypted_server_auth


def file_server(service_id: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (service_id, content) or (None, None) if not found."""
    if service_id in SERVICE_CONTENTS:
        siem_logger.log_event("SERVICE", "N/A", "file_access", "success", "-", f"Service {service_id} content retrieved")
        return service_id, SERVICE_CONTENTS[service_id]

    print(f"[SERVICE] Unknown service_id: {service_id}")
    siem_logger.log_event("SERVICE", "N/A", "file_access", "fail", "-", f"Unknown service_id {service_id}")
    return None, None
