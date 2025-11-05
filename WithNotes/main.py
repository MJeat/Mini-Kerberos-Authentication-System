import sys   # for existing the system
import kdc
import serviceServer 
from cryptography.fernet import Fernet
from kdc import derieved_key

# Storing session keys
def sessions_store():
    session_store = {
        "TGS Session Key": None,
        "Service Session Key": None
    }
    return session_store
session_store = sessions_store()

store_encrypted_msg = {
    "Encrypted TGT": None,
    "Encrypted ST": None,
    "Encrypted SID": None # SID = Service ID
}

client_static_ip_addr = "192.168.1.20"

def main():
    count_login = 0
    while count_login<3:
        try:
            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            usrname_input = input("Username: ").strip()
            pwd = input("Password: ").strip()

            if not usrname_input and not pwd:
                print("=======================================")
                print("[CLIENT] Username and Password must not be empty")
                print("=======================================\n")
                count_login += 1
                continue

            # Working with Authentication Server - AS
            AS_msg_to_usr, TicketGrantingTicket = kdc.authenticationServer(usrname_input, client_static_ip_addr)
            client_to_AS = client_AS(AS_msg_to_usr, TicketGrantingTicket, pwd)

            if client_to_AS is False:
                print("=======================================")
                print("[CLIENT] Error During Authentication Server or Wrong Username/Password.")
                print("=======================================\n")
                count_login += 1
                continue # restart the while loop
            break
        except:
            print("=======================================================================")
            print(f"[CLIENT] Error Occurred. Please enter username and password correctly.")
            print("=======================================================================\n")
            count_login += 1
    if count_login >= 3:
        print("\n[CLIENT] Too many failed attempts. Exiting...")
        sys.exit(1)

    while True:
        try:
            confirmation = input()
            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            service_id = input("Enter Service ID (e - exit)\n" 
            "ID - Services\n"
            "1 - Message\n" 
            "2 - Facebook\n" 
            "3 - Telegram\n" 
            "4 - Kerberos Guides\n" 
            "5 - flag.txt\n" 
            "> ").strip().lower()
            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

            if service_id == "e":
                print("=======================================")
                print("[SYSTEM] WARNING: System Closing...")
                print("[SYSTEM GOODBYE]")
                print("=======================================\n")
                sys.exit(0)
            if service_id == "":
                print("=======================================")
                print("[CLIENT] Service ID must not be empty")
                print("=======================================\n")
                continue
            elif service_id not in {"1", "2", "3", "4", "5"}:
                print("===================================================")
                print("[CLIENT] Invalid ID. Please choose between 1 to 5")
                print("===================================================\n")
                continue

            client_TGS(service_id, usrname_input)
            break
        except Exception as e:
            print("=========================================")
            print(f"[CLIENT] Error Occurred: {e}")
            print("=========================================\n")

    while True:
        try:
            confirmation = input()
            client_sv(usrname_input, service_id)
            break
        except Exception as e:
            print("=========================================")
            print(f"[CLIENT] Error Occurred: {e}")
            print("=========================================\n")
            

# (Contains: Encrypted message (TGS Session Key and TGS Name/ID), Encrypted TGT (User Name/ID, TGS Name/ID, IP Addr, TGS Session Key))
def client_AS(AS_encrypted_msg, TicketGrantingTicket, pwd): 
    if AS_encrypted_msg is None:
        return False
    
# === This chunk below decrypts the encrypted message from AS that was encrypted with stored Client Secret Key ===
    # (Attributes: TGT Name/ID + TGS Session Key)
    try:
        client_secretKey_decryptor = derieved_key(pwd)
        f = Fernet(client_secretKey_decryptor)

        decrypt_From_AS = f.decrypt(AS_encrypted_msg)
        TGT_id, TGS_session_key = decrypt_From_AS.split(b'||')

        session_store["TGS Session Key"] = TGS_session_key     # saving the TGS session key as global for using in client_TGS() 
        store_encrypted_msg["Encrypted TGT"] = TicketGrantingTicket    # saving the encrypted TGT message as global for using in client_TGS() 

        confirmation = input()
        print("================================================================ Client: Received from AS =================================================================")
        print("=== Before Decryption ===")
        print(f"Message to user before decryption: {AS_encrypted_msg.decode()}\n")
        print(f"Encrypted TGT: {TicketGrantingTicket.decode()}\n")
        print("\n=== After Decryption ===")
        print(f"Ticket-Granting-Ticket ID (TGT ID): {TGT_id.decode()}") # put .decode() to remove the b'...' | Try removing b'...' and see for yourself 
        print(f"Ticket-Granting Server Session Key (TGS Session Key): {TGS_session_key.decode()}")
        # === End of Message #1 from AS -> Client ===

# === This chunk below is TGT and is encrypted with TGS Secret Key ===
        # (Contains: User Name/ID + TGT Name/ID + TGS Session Key)
        print(f"Encrypted TGT (Encrypted Message. Client is unable to read): {TicketGrantingTicket.decode()}")
        print("============================================================================================================================================================\n")
        return True
        # === End of Message #2 from AS -> Client ===
    except:
        return False


# (Contains: User Name/ID, Service ID, and Encrypted TGT (User Name/ID, TGS Name/ID, IP Addr, ST Session Key))
def client_TGS(service_id, username): 
    confirmation = input()
    if service_id is None:
        return False
# === This chunk below is encrypted with TGS Session Key === (take that key from the storage placement above - TGS_Session_Key)
    try:
        user_authenticator_encryptor = session_store["TGS Session Key"]
        f_tgs = Fernet(user_authenticator_encryptor)
        encrypted_user_authenticator_msg = f_tgs.encrypt(username.encode()) # use .encode() to convert strings or other data types to bytes
        # print(usr_authenticator_to_tgs.decode())  # For testing
        
        encrypted_TGT = store_encrypted_msg["Encrypted TGT"]

        # Sending 5 infos to ticketGrantingServer() in kdc.py
        TGS_encrypted_msg, ServiceTicket = kdc.ticketGrantingServer(service_id, username, encrypted_user_authenticator_msg, encrypted_TGT, client_static_ip_addr)
        if TGS_encrypted_msg is None or ServiceTicket is None:
            print("=========================================")
            print("[CLIENT] TGS rejected the request")
            print("=========================================\n")
            return False
# === End of Client Message #1,2,3 Sent from Client -> TGS ===

# === This chunk below is Service Ticket and is encrypted with Services Secret Key ===
        # (Contains: User Name/ID + TGT Name/ID + TGS Session Key)
        decrypt_from_TGS = f_tgs.decrypt(TGS_encrypted_msg)
        service_id_received, ST_session_key = decrypt_from_TGS.split(b"||")  
        store_encrypted_msg["Encrypted ST"] = ServiceTicket # saving the encrypted ST as global for using in client_fs() 
        session_store["Service Session Key"] = ST_session_key # saving the ST session key as global for using in client_fs() 

        confirmation = input()
        print("============================================================== Client: Received from TGS =================================================================")
        print("=== Before Decryption ===")
        print(f"Message to user before decryption: {TGS_encrypted_msg.decode()}\n")
        print(f"Encrypted Service Ticket: {ServiceTicket.decode()}\n")
        print("\n=== After Decryption ===")
        print(f"Service ID (from TGS): {service_id_received.decode()}")
        print(f"Service Session Key (File Server Session Key): {ST_session_key.decode()}")
        print(f"Encrypted Service Ticket (Encrypted for the Selected Service): {ServiceTicket.decode()}")
        print("===========================================================================================================================================================\n")
        return True
# === End of TGS Message #1, 2 Sent from TGS -> Client ===
    except Exception as e:
        print("=========================================")
        print(f"[CLIENT] Error at client_TGS: {e}")
        print("=========================================\n")
        return False


# (Contains: User Name/ID, Service ID, and Encrypted TGT (User Name/ID, TGS Name/ID, IP Addr, ST Session Key))
def client_sv(username, service_id):
# === This chunk below is encrypted with Service Session Key === (take that key from the storage placement above - Service Session Key)
    try:
        user_authenticator_encryptor = session_store["Service Session Key"]
        f_st = Fernet(user_authenticator_encryptor)
        encrypted_user_authenticator_msg = f_st.encrypt(username.encode())   # Message #1 

        encrypted_ST = store_encrypted_msg["Encrypted ST"]    # Message #2

        service_id_received = serviceServer.service(username, service_id, encrypted_user_authenticator_msg, encrypted_ST)
        if service_id_received is None:
            print("=========================================")
            print("[CLIENT] SERVICE rejected the request. Invalid Username.")
            print("=========================================\n")
            return False
# === End of Client Message #1, 2 (Encrypted ST & Encrypted User Authenticator). Message is Sent From Client -> Service Server ===

        decrypt_from_sv = f_st.decrypt(service_id_received)
        store_encrypted_msg["Encrypted SID"] = service_id_received  # saving encrypted service ID

        confirmation = input()
        print("========================================================== Client: Received from Service Server ============================================================")
        print("=== Before Decryption ===")
        print(f"Encrypted Service Authenticator Message: {service_id_received.decode()}\n")
        print("\n=== After Decryption ===")
        print(f"Service Authenticator Message: {decrypt_from_sv.decode()}")
        print("===========================================================================================================================================================\n")
        choose_service(decrypt_from_sv.decode()) # Client confirms service ID to get the content from that service ID
        return True
# === End of Encrypted Service Message Sent from File Server -> Client ===
    except Exception as e:
        print(f"[CLIENT] Error at client_fs {e}")


# Client confirms service ID to get the content from that service ID
def choose_service(service_num):

    usr_confirmation = input(f"[Client] Please confirm your service ID (y/n): ").strip().lower()
    while usr_confirmation not in ["y","n"]:
        usr_confirmation = input(f"[Client] Please confirm your service ID (y/n): ").strip().lower()
        
    if usr_confirmation == "y":
        print(f"[CLIENT] Service ID {service_num} confirmed.")
        print("[CLIENT] Loading Content ... \n")
    else:
        return main()

    service_number, content = serviceServer.file_server(service_num)
    if service_num is None:
        print("[CLIENT] Invalid service ID received from server.")
        return False

    print(f"Service ID Number: {service_number}")
    print(f"Content: \n{content}")
    return True

if __name__ == "__main__":
    main()



"""

main.py has inputs and i want to check if my username and password already has in database

kdc.py takes the input from main.py and checks if the elements exist in the database and outputs back to main.py
--

How to get the info from kdc.py, store in main() and print by clientToAS()? The goal is to print from one function using anther function from the same file.

"""