"""
Client for the Kerberos-style demo (with MFA + SIEM logging).
- Logs in to AS with username/password (+ MFA).
- Contacts TGS with TGT + authenticator.
- Contacts Service with ST + authenticator.
- Logs every success/failure to security_log.json via siem_logger.
"""

from __future__ import annotations
import sys, time
from typing import Optional, Tuple
from cryptography.fernet import Fernet, InvalidToken
import kdc
import serviceServer
import siem_logger  # Central logging module

CLIENT_STATIC_IP = "192.168.1.20"
MANUAL_FLOW = False  # Optional teaching mode

# Session storage
TGS_SESSION_KEY: Optional[bytes] = None
ST_SESSION_KEY: Optional[bytes] = None
ENCRYPTED_TGT: Optional[bytes] = None
ENCRYPTED_ST: Optional[bytes] = None


def prompt_nonempty(label: str) -> str:
    s = input(label).strip()
    while not s:
        print("[CLIENT] Value must not be empty.")
        s = input(label).strip()
    return s


def client_as(username: str, password: str) -> bool:
    """Contact AS (with MFA), decrypt message with password, store TGS key + TGT."""
    global TGS_SESSION_KEY, ENCRYPTED_TGT

    print("\n[CLIENT] Starting Authentication Phase...")
    print("[CLIENT] Sending username and requesting MFA challenge...")

    out = kdc.authentication_server(username, CLIENT_STATIC_IP)
    if out is None:
        print("[CLIENT] Authentication failed (invalid user, password, or MFA).")
        siem_logger.log_event("CLIENT", username, "authentication", "fail", CLIENT_STATIC_IP, "AS authentication failed")
        return False

    as_msg_to_user, tgt = out

    # derive user key from password
    user_key = kdc.derived_key(password)
    f_user = Fernet(user_key)

    try:
        plain = f_user.decrypt(as_msg_to_user)
    except InvalidToken:
        print("[CLIENT] Wrong password (decrypt failed).")
        siem_logger.log_event("CLIENT", username, "password_verification", "fail", CLIENT_STATIC_IP, "Invalid password")
        return False

    tgt_id_b, tgs_key_b = plain.split(b"||", 1)
    TGS_SESSION_KEY = tgs_key_b
    ENCRYPTED_TGT = tgt

    print("\n=== Client: Received from AS (after MFA success) ===")
    print("Encrypted-to-user message:", as_msg_to_user.decode())
    print("Encrypted TGT:", tgt.decode())
    print("Decrypted:")
    print("  TGT ID:", tgt_id_b.decode())
    print("  TGS Session Key:", tgs_key_b.decode())
    print()

    siem_logger.log_event("CLIENT", username, "authentication", "success", CLIENT_STATIC_IP, "MFA + password passed")

    if MANUAL_FLOW:
        input("(manual) Press Enter after you've pasted TGT to the 'TGS step'...")
    return True


def client_tgs(username: str, service_id: str) -> bool:
    """Build authenticator, send TGT + auth to TGS, store ST session key + ST."""
    global ST_SESSION_KEY, ENCRYPTED_ST

    if TGS_SESSION_KEY is None or ENCRYPTED_TGT is None:
        print("[CLIENT] Missing TGS key or TGT.")
        siem_logger.log_event("CLIENT", username, "tgs_request", "fail", CLIENT_STATIC_IP, "No TGS key/TGT available")
        return False

    f_tgs = Fernet(TGS_SESSION_KEY)
    auth = f"{username}||{int(time.time())}".encode()
    encrypted_auth = f_tgs.encrypt(auth)

    out = kdc.ticket_granting_server(service_id, username, encrypted_auth, ENCRYPTED_TGT, CLIENT_STATIC_IP)
    if out is None:
        print("[CLIENT] TGS rejected the request.")
        siem_logger.log_event("CLIENT", username, "tgs_request", "fail", CLIENT_STATIC_IP, f"TGS rejected service {service_id}")
        return False

    tgs_msg_to_user, service_ticket = out

    # decrypt message to get service session key
    try:
        plain = f_tgs.decrypt(tgs_msg_to_user)
        sid_b, st_key_b = plain.split(b"||", 1)
    except InvalidToken:
        print("[CLIENT] Decrypt from TGS failed.")
        siem_logger.log_event("CLIENT", username, "tgs_decrypt", "fail", CLIENT_STATIC_IP, "Failed to decrypt TGS response")
        return False

    ST_SESSION_KEY = st_key_b
    ENCRYPTED_ST = service_ticket

    print("=== Client: Received from TGS ===")
    print("Encrypted-to-user message:", tgs_msg_to_user.decode())
    print("Encrypted Service Ticket:", service_ticket.decode())
    print("Decrypted:")
    print("  Service ID:", sid_b.decode())
    print("  Service Session Key:", st_key_b.decode())
    print()

    siem_logger.log_event("CLIENT", username, "tgs_request", "success", CLIENT_STATIC_IP, f"Service {sid_b.decode()} ticket granted")

    if MANUAL_FLOW:
        input("(manual) Press Enter after you've pasted ST to the 'Service step'...")
    return True


def client_service(username: str, service_id: str) -> bool:
    """Build authenticator, send ST + auth to Service, verify reply, fetch content."""
    if ST_SESSION_KEY is None or ENCRYPTED_ST is None:
        print("[CLIENT] Missing ST key or ST.")
        siem_logger.log_event("CLIENT", username, "service_request", "fail", CLIENT_STATIC_IP, "Missing ST key or ticket")
        return False

    f_st = Fernet(ST_SESSION_KEY)
    auth = f"{username}||{int(time.time())}".encode()
    encrypted_auth = f_st.encrypt(auth)

    server_reply = serviceServer.service_handle(username, service_id, encrypted_auth, ENCRYPTED_ST)
    if server_reply is None:
        print("[CLIENT] Service rejected the request.")
        siem_logger.log_event("CLIENT", username, "service_request", "fail", CLIENT_STATIC_IP, f"Service {service_id} rejected")
        return False

    try:
        echoed_sid = f_st.decrypt(server_reply).decode()
    except InvalidToken:
        print("[CLIENT] Could not decrypt server authenticator.")
        siem_logger.log_event("CLIENT", username, "service_response", "fail", CLIENT_STATIC_IP, "Server authenticator decrypt failed")
        return False

    print("=== Client: Received from Service ===")
    print("Encrypted server authenticator:", server_reply.decode())
    print("Decrypted:")
    print("  Echoed Service ID:", echoed_sid)
    print()

    confirm = input("[Client] Confirm service ID (y/n): ").strip().lower()
    if confirm != "y":
        print("[CLIENT] Cancelled by user.")
        siem_logger.log_event("CLIENT", username, "service_confirmation", "fail", CLIENT_STATIC_IP, "User cancelled service access")
        return False

    sid, content = serviceServer.file_server(service_id)
    if sid is None:
        print("[CLIENT] Invalid service selected.")
        siem_logger.log_event("CLIENT", username, "file_access", "fail", CLIENT_STATIC_IP, "Invalid service ID")
        return False

    print("=== Content ===")
    print("Service ID:", sid)
    print("Content:\n" + content)
    siem_logger.log_event("CLIENT", username, "service_request", "success", CLIENT_STATIC_IP, f"Accessed service {service_id}")
    return True


def main() -> None:
    print("==== Mini Kerberos Demo (with MFA + SIEM) ====")
    username = prompt_nonempty("Username: ")
    password = prompt_nonempty("Password: ")

    if not client_as(username, password):
        sys.exit(0)

    while True:
        print("\nChoose a service:")
        print("1 - Message")
        print("2 - Facebook")
        print("3 - Telegram")
        print("4 - Kerberos Guides")
        print("5 - flag.txt")
        print("e - exit")
        choice = input("> ").strip().lower()

        if choice == "e":
            print("[SYSTEM] Goodbye.")
            siem_logger.log_event("CLIENT", username, "session", "end", CLIENT_STATIC_IP, "User exited session")
            sys.exit(0)

        if choice not in {"1", "2", "3", "4", "5"}:
            print("[CLIENT] Invalid choice. Pick 1-5 or e.")
            siem_logger.log_event("CLIENT", username, "menu_selection", "fail", CLIENT_STATIC_IP, f"Invalid choice: {choice}")
            continue

        if not client_tgs(username, choice):
            continue

        client_service(username, choice)
        # loop allows reuse of TGT


if __name__ == "__main__":
    main()
