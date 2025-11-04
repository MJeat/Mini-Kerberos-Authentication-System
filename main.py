import kdc
import fileServer
from cryptography.fernet import Fernet
from kdc import derieved_key


# Continue watching at 8:15 # https://www.youtube.com/watch?v=5N242XcKAsM


# Storing Session Keys On Client-Side
TGS_Session_Key = ""
Service_Session_Key = ""

def main():
    # service_id = input("Énter Service ID: ").strip()
    client_static_ip_addr = "192.168.1.20"
    usrname_input = input("Username: ").strip()
    pwd = input("Password: ").strip()
    
    # Working with Authentication Server - AS
    msg_to_usr, TicketGrantingTicket = kdc.AuthenticationServer(usrname_input, client_static_ip_addr)
    clientToAS(msg_to_usr, TicketGrantingTicket, pwd, client_static_ip_addr)

    # Working with Ticket Granting Server - TGS
    clientToTGS()


def clientToAS(msg_to_usr, TicketGrantingTicket, password):
    if msg_to_usr is None:
        return None
    # === Before Decryption ===
    # print(f"Message to user before decryption: {msg_to_usr.decode()}")
    # print(f"TGT before decryption: {TicketGrantingTicket.decode()}")

    
# === This chuck below is encrypted with Client Secret Key ===
    # (Contains: TGT Name/ID + TGS Session Key)
    try:
        user_key = derieved_key(password)

        f = Fernet(user_key)

        decrypt_From_AS = f.decrypt(msg_to_usr)
        TGT_id, TGS_session_key = decrypt_From_AS.split(b'||')

        confirmation = input()
        print(" === Login Success! === ")
        print(f" == TGT Name/ID == \n{TGT_id.decode()}") # put .decode() to remove the b'...' | Try removing b'...' and see for yourself 
        print(f" == TGS Session Key == \n{TGS_session_key.decode()}")
        # === End of Message #1 from AS -> Client ===

# === This chuck below is TGT and is encrypted with TGS Secret Key ===
        # (Contains: Client Name/ID + TGT Name/ID + Client's Static IP + TGS Session Key)
        print(f" == TGT (Encrypted Message. Client is unable to read) == \n{TicketGrantingTicket.decode()}")
        print()
        # === End of Message #2 from AS -> Client ===
    except:
        print("Error occurrs")
        return
   
def clientToTGS():
    pass

def clientToFileServer():
    pass




if __name__ == "__main__":
    main()



"""

main.py has inputs and i want to check if my username and password already has in database

kdc.py takes the input from main.py and checks if the elements exist in the database and outputs back to main.py
--

How to get the info from kdc.py, store in main() and print by clientToAS()? The goal is to print from one function using anther function from the same file.

"""