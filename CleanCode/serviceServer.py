# File server returns the needed information for the client. Client has to request information or data from the file server
import kdc
import json
from cryptography.fernet import Fernet

service_storage = kdc.services_storage()
# print(service_storage.items())  # for testing bugs
def service(username, service_id, encrypted_user_authenticator_msg, encrypted_ST):
    
    # Find service secret key, based on the selected service ID
    if service_id not in service_storage:
        print("[SERVICE] ERROR: Service ID Invalid")
        return None
    service_secret_key = service_storage[service_id]
    
    # Step 1: Decrypt the encrypted service ticket with service secret key
    print("\n==========================================================================================================================================================")
    print("[SERVICE] WARNING: The Content Below Should Not Be Seen. The Client Is Only Allowed to See the \"Client: Received from Service Server\" Content. This Is Only a Demo")
    print(f"[SERVICE] Received request for service {service_id}")
    try:
        f_st = Fernet(service_secret_key)
        st_plain = f_st.decrypt(encrypted_ST)
        st_obj = json.loads(st_plain.decode())
        st_obj_usrname = st_obj["client_name"]

        print("[SERVICE] ST decrypted successfully.")
        print(f"[SERVICE] ST contents: {st_obj}") # compare username here
        print(f"[SERVICE] Username from the encrypted ST is: {st_obj_usrname}")
    except Exception as e:
        print(f"[SERVICE] ERROR: Failed to decrypt ST: {e}")
        return None
    # Step 2: Extract the ST_session_key from TGT (it's stored as string, convert to bytes)
    st_session_key_str = st_obj.get("st_session_key")
    if not st_session_key_str:
        print("[SERVICE] ERROR: ST session key not found in Service.")
        return None
    st_session_key = st_session_key_str.encode()  # bytes

    # Step 3: Decrypt the authenticator using st_session_key
    try:
        f_session = Fernet(st_session_key) # takes the key above and use it here to decrypt
        auth_plain = f_session.decrypt(encrypted_user_authenticator_msg)   # bytes
        auth_username = auth_plain.decode() # compare username here
    except Exception as e:
        print(f"[SERVICE] ERROR: Failed to decrypt authenticator: {e}")
        return None
    print(f"[SERVICE] Authenticator decrypted: {auth_username}")

    # Step 4: Verify username and IP
    st_client_name = st_obj.get("client_name")
    if auth_username != username:
        print("[SERVICE] ERROR: Authenticator username does not match claimed username.")
        return None
    if st_client_name != st_obj_usrname:
        print("[SERVICE] ERROR: Username mismatch between authenticator and ST.")
        return None
    print("[SERVICE] Username verified successfully.")

# === This chunk is Service Authenticator and is encrypted with Services Session Key ===
    # Step 1: Create encrytion key to encrypt the server authenticator message
    f_sv = Fernet(st_session_key)
    encrypted_server_authenticator_msg = f_sv.encrypt(service_id.encode())
    print("[SERVICE] Issued Encrypted Server Authenticator Message to Client.")
    print("==========================================================================================================================================================\n")
    return encrypted_server_authenticator_msg

# services for accessing contents based on the authenticated service ID
def file_server(service_number):
    print("=== File Server ===")
    services = {"1":"[From: mjeat] Hello there. This is a Congradulation MESSAGE!!!",
               "2":"Welcome to Facebook. This is your home page...Buzz buzz",
               "3": "[From: mjeat] Hello, there. Congradulation!!!....again...Texting from telegram ofc",
               "4":"Kerberos Guides. Step 1: ... my back hurts...",
               "5":"BreadCTF\\{th1s_1s_4_fl4g_9uy2\\}"}
    
    # Check if the service number exists
    if service_number in services:
        return service_number, services[service_number]
    else:
        print(f"[SERVICE] Invalid service ID: {service_number}")
        return None, None
    

    
    

    

