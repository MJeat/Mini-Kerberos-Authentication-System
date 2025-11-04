
# This is the key distribution center or KDC. KDC has AS and TGS
# We may not have the lifetime of each of the message send back and forth. That's because this is a mini version or the simplified version of Kerberos Authentication 
# We are using symmetric key as a communication encryption key
# The KDC stores the client secret key, encrypts the message with that key according to the username, and sends back to the client
# The client, if has the correct secret key, decrypts the message

import json
import base64
import hashlib
from cryptography.fernet import Fernet

# client_static_ip_addr = "192.168.1.20"


# Secret key
tgs_key  = Fernet.generate_key()   # Ticket Granting Server key

# Encrypted password between AS and client
def derieved_key(password):
    hash_pwd = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hash_pwd)  

credential_storage = {"bob":derieved_key("123"),
               "Alice":derieved_key("helloWorl$"),
               "Smey": derieved_key("iLxvM0n3y"),
               "Pich":derieved_key("Blu3T3@m_Ismyf4v")}

def AuthenticationServer(usrname, ip_addr):
    if usrname not in credential_storage:
        return None
    
# === This chuck is encrypted with Client Secret Key === 
    # (Attributes: TGT Name/ID + TGS Session Key)
    stored_key = credential_storage[usrname]
    f = Fernet(stored_key)

    TicketGrantingTicket_ID = b"TGT-69" # Static TGT ID
    TGS_session_key = Fernet.generate_key()  # key between client and TGS
    msg_to_usr = f.encrypt(TicketGrantingTicket_ID + b"||" + TGS_session_key)
    # === End of Message #1 from AS -> Client ===

# === This chuck is TGT and is encrypted with TGS Secret Key ===
    # (Attributes: Client Name/ID + TGT Name/ID + Client's Static IP + TGS Session Key)
    tgt_data = {
        "client_id": usrname,
        "tgt_id": TicketGrantingTicket_ID.decode(),
        "client_ip": ip_addr,
        "tgs_session_key": TGS_session_key.decode()
    }
    
    # Encrypt with TGS secret key
    f_tgs = Fernet(tgs_key)
    TicketGrantingTicket = f_tgs.encrypt(json.dumps(tgt_data).encode())
    
    # # For demonstration, let's show what's inside the TGT
    # print("=== TGT CONTENTS (Before Encryption) ===")
    # print(f"Client ID: {tgt_data['client_id']}")
    # print(f"TGT ID: {tgt_data['tgt_id']}")
    # print(f"Client IP: {tgt_data['client_ip']}")
    # print(f"TGS Session Key: {tgt_data['tgs_session_key']}")
    # print()

    return msg_to_usr, TicketGrantingTicket
# === End of Message #2 from AS -> Client ===

def TicketGrantingServer():
    pass


