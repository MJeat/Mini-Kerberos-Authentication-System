
# This is the key distribution center or KDC. KDC has AS and TGS
# We may not have the lifetime of each of the message send back and forth. That's because this is a mini version or the simplified version of Kerberos Authentication 
# We are using symmetric key as a communication encryption key
# The KDC stores the client secret key, encrypts the message with that key according to the username, and sends back to the client
# The client, if has the correct secret key, decrypts the message

import json
import base64
import hashlib
from cryptography.fernet import Fernet

# Secret keys
tgs_key  = Fernet.generate_key()   # Ticket Granting Server secret key

def services_storage():
    # service ID and its service secret key - Preferrably should be static. Dynamic here 
    st_key1 = b'tvvN_CgyYJ-ulmJaMnBTLV2mP2lEnzHUUAnyy3wS444='   # Static Service secret key for service ID 1
    st_key2 = b'dVhoWgGGmhs4Ba9fElaiMXAhHmre0foIZC6ve9pxf6w=' # Static Service secret key for service ID 2  
    st_key3 = b'-XnUYdt9YC8Y9ouuc4k8zSDPw7izkBqbLu8JixBgwW8='  # Static Service secret key for service ID 3
    st_key4 = Fernet.generate_key()   # Dynamic Service secret key for service ID 4
    st_key5 = Fernet.generate_key()   # Dynamic SService secret key for service ID 5

    service_storage = {
        "1": st_key1,
        "2": st_key2,
        "3": st_key3,
        "4": st_key4,
        "5": st_key5
    }
    return service_storage

service_storage = services_storage() 

# Encrypted password between AS and client
def derieved_key(password):
    hash_pwd = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hash_pwd)  

credential_storage = {"bob":derieved_key("123"),
               "Alice":derieved_key("helloWorl$"),
               "Smey": derieved_key("iLxvM0n3y"),
               "Pich":derieved_key("Blu3T3@m_Ismyf4v")}

def authenticationServer(usrname, ip_addr):
    if usrname not in credential_storage:
        return None
    
# === This chunk is encrypted with Client Secret Key === 
    # (Attributes: TGT Name/ID + TGS Session Key)
    stored_key = credential_storage[usrname]
    f = Fernet(stored_key)

    TicketGrantingTicket_ID = b"TGT-69" # Static TGT ID
    TGS_session_key = Fernet.generate_key()  # key between client and TGS
    AS_msg_to_usr = f.encrypt(TicketGrantingTicket_ID + b"||" + TGS_session_key)
    # === End of AS Message #1 (Encrypted Authentication) is Sent from AS -> Client ===

# === This chunk is TGT and is encrypted with TGS Secret Key ===
    # (Attributes: Client Name/ID + TGT Name/ID + Client's Static IP + TGS Session Key)
    tgt_data = {
        "client_name": usrname,
        "tgt_id": TicketGrantingTicket_ID.decode(),
        "client_ip": ip_addr,
        "tgs_session_key": TGS_session_key.decode()
    }

    f_tgs = Fernet(tgs_key)     # Encrypt with TGS secret key
    TicketGrantingTicket = f_tgs.encrypt(json.dumps(tgt_data).encode())
    
    # For demonstration, let's show what's inside the TGT
    print("==========================================================================================================================================================")
    print("[AS] WARNING: The Content Below Should Not Be Seen. The Client Is Only Allowed to See the \"Client: Received from AS\" Content. This Is Only a Demo")
    print("[AS] TGT CONTENTS (Before Encryption)")
    print(f"[AS] Client ID: {tgt_data['client_name']}")
    print(f"[AS] TGT ID: {tgt_data['tgt_id']}")
    print(f"[AS] Client IP: {tgt_data['client_ip']}")
    print(f"[AS] TGS Session Key: {tgt_data['tgs_session_key']}")
    print("==========================================================================================================================================================\n")
    return AS_msg_to_usr, TicketGrantingTicket
    # === End of AS Message #2 (Authentication). Message is Sent From AS -> Client ===

def ticketGrantingServer(service_id: str, usrname: str, encrypted_user_authenticator_msg: bytes, encrypted_TGT: bytes, client_ip: str):  # (Contains: User Name/ID, Service ID, and Encrypted TGT (User Name/ID, TGS Name/ID, IP Addr, TGS Session Key))
# === This chunk below is encrypted with TGS Secret Key === (takes tgs_key) 
    # Step 1: Sanity checks service ID
    if service_id not in service_storage:
        print("[TGS] ERROR: Service ID Invalid")
        return None, None 
    # === End of Client Message #1 (Service ID Checking). Message is Sent From Client -> TGS ===
    
    # Step 2: Decrypt, Message #2, the encrypted TGT with TGS secret key or tgs_key
    print("==========================================================================================================================================================")
    print("[TGS] WARNING: The Content Below Should Not Be Seen. The Client Is Only Allowed to See the \"Client: Received from TGS\" Content. This Is Only a Demo")
    try:
        f_tgs = Fernet(tgs_key)
        tgt_plain = f_tgs.decrypt(encrypted_TGT)   # bytes containing json
        tgt_obj = json.loads(tgt_plain.decode())   # turns into dictionary
    except Exception as e:
        print("[TGS] ERROR: Failed to decrypt TGT:", e)
        return None, None
    
    print("[TGS] TGT decrypted successfully.")
    print(f"[TGS] TGT contents: {tgt_obj}")

    # Extract the TGS_session_key from TGT (it's stored as string, convert to bytes)
    tgs_session_key_str = tgt_obj.get("tgs_session_key")
    if not tgs_session_key_str:
        print("[TGS] ERROR: TGS session key not found in TGT.")
        return None, None
    tgs_session_key = tgs_session_key_str.encode()   # bytes
    # === End of Client Message #2 (Encrypted TGT) from Client -> TGS ===

    # Step 3: Decrypt the authenticator using tgs_session_key
    try:
        f_session = Fernet(tgs_session_key) # takes the key above and use it here to decrypt
        auth_plain = f_session.decrypt(encrypted_user_authenticator_msg)   # bytes
        auth_username = auth_plain.decode()
    except Exception as e:
        print("[TGS] ERROR: Failed to decrypt authenticator:", e)
        return None, None
    print("[TGS] Authenticator decrypted:", auth_username)

    # Step 4: Verify username and IP
    tgt_client_name = tgt_obj.get("client_name")
    tgt_client_ip = tgt_obj.get("client_ip")
    if auth_username != usrname:
        print("[TGS] ERROR: Authenticator username does not match claimed username.")
        return None, None
    if tgt_client_name != usrname:
        print("[TGS] ERROR: Username mismatch between authenticator and TGT.")
        return None, None
    if tgt_client_ip != client_ip:
        print("[TGS] WARNING: Client IP in TGT does not match claimed IP.")
        print("[TGS] Rejecting due to IP mismatch.")   # This applies for the static IP addr only. 
        return None, None
    print("[TGS] Username and IP verified successfully.")
    # === End of Client Message #3 (Encrypted User Authenticator) from Client -> TGS ===

# === This chunk is Service Ticket and is encrypted with Services Secret Key ===
    # Step 1: Create Service session key (ST_session_key) for client <-> service
    ST_session_key = Fernet.generate_key()

    # Step 2: TGS_msg1_to_user: encrypted contains service_id and ST_session_key with tgs_session_key
    t = Fernet(tgs_session_key)
    TGS_encrypted_msg = t.encrypt(service_id.encode() + b"||" + ST_session_key)
# === End of TGS Message #1 (Encrypted Message). Message is Sent From TGS -> Client ===

    # Step 3: ServiceTicket: encrypted with service's long-term key (so only service can decrypt)
    service_secret_key = service_storage[service_id]
    st_payload = {
        "client_name": usrname,
        "service_id": service_id,
        "client_ip": client_ip,
        "st_session_key": ST_session_key.decode()
    }
    f_service = Fernet(service_secret_key)
    ServiceTicket = f_service.encrypt(json.dumps(st_payload).encode())

    print("[TGS] Issued ST and TGS message. Returning to client.")
    print("==========================================================================================================================================================\n")
    return TGS_encrypted_msg, ServiceTicket
# === End of TGS Message #2 (Encrypted Service Ticket). Message is Sent From TGS -> Client ===





