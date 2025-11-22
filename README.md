# _Tips to navigate and use the repository_: 
This is a recommendation:
1. First, read all code from the CleanCode directory and understand how each function needs each others across files
2. After reading the CleanCode directory, go to the WithNotes directory for a more detailed version of noting and documentation.
You may find this directory a little bit difficult to read and navigate, but if you already understand the code and functionality from the CleanCode directory, then the WithNotes directory shouldn't be a problem.
3. Finalized_Version is the final product. 

=============================================
# Mini-Kerberos-Authentication-System

The main objective of the Mini Kerberos Authentication System is to design and demonstrate a secure authentication mechanism that verifies user identities and grants access to network services without exposing passwords. The system aims to implement the core principles of the Kerberos protocol, such as confidentiality, integrity, and mutual authentication through the use of encrypted tickets and session keys.

Specifically, the goal is to:
- Simulate the interaction between the Authentication Server (AS), Ticket Granting Server (TGS), and File Server within a Key Distribution Centre (KDC).
- Ensure that users are authenticated securely before accessing protected resources.
- Prevent unauthorized access and replay attacks by using time-stamped, encrypted tokens.
- Provide an educational model to understand how Kerberos enhances trust and security in distributed systems.

Below is the flowchart: 
<br>
<img width="1174" height="592" alt="Image" src="https://github.com/user-attachments/assets/d0955f52-bc08-42da-b54b-dd4c048768c6" />
<br>

## Description
The Mini Kerberos Authentication System securely verifies users without sending passwords over the network. It operates through a Key Distribution Centre (KDC) containing an Authentication Server (AS) and a Ticket Granting Server (TGS). The AS validates the user’s credentials and issues a Ticket Granting Ticket (TGT). The client uses this TGT to request a service token from the TGS, which allows access to the File Server. The File Server verifies the token using shared encryption keys before granting access. A Mini SIEM tool monitors activities, logs access, and detects errors, enhancing security and accountability.

