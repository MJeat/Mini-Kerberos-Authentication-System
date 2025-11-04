
# File server returns the needed information for the client. Client has to request information or data from the file server

def FileServer():
    print("=== File Server ===")
    print("Here is the data:\n")
    data = {"Bob":"1234",
               "Alice":"helloWorl$",
               "Smey": "iLxvM0n3y",
               "Pich":"Blu3T3@m_Ismyf4v"}
    for i,j in data.items():
        print(f"{i}: {j}")
    print()

def key():
    return "banana"
