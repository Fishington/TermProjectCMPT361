# Server code Term Project CMPT361

import socket
import json
import sys
import os
import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# Helper Functions For Encryption/Decryption

def generateAESKey(client_name):
    # Generate a 256 AES key
    key = os.urandom(32)  # AES-256

    # Create client directory if it doesn't exist
    os.makedirs(f'client/{client_name}', exist_ok=True)
    return key

#def getKey():
#    with open('../key', 'rb') as f:
#        key = f.read()
#    return key


# Saves the pubkey of the client for later use, if doesnt already exist
def saveClientPubKey(client_name, key):
    if not os.path.exists(f'client/{client_name}/{client_name}_public.pem'):
        with open(f'client/{client_name}/{client_name}_public.pem', 'wb') as f:
            f.write(key)

def generateRSAKeys():
    # Checks if keys exist on server machine
    if os.path.exists('server_public.pem') and os.path.exists('server_private.pem'):
        with open('server_public.pem', 'rb') as f:
            public_key = f.read()

        with open('server_private.pem', 'rb') as f:
            private_key = f.read()
        return public_key, private_key
    
    else:
    # Generates RSA key pair and saves to server machine
        key = RSA.generate(2048)
        private_key = key.export_key()
        with open('server_private.pem', 'wb') as f:
            f.write(private_key)

        public_key = key.publickey().export_key()
        with open('server_public.pem', 'wb') as f:
            f.write(public_key)
        return public_key, private_key

# For sending encrypted messages using client pubkey
def encryptMessageRSA(public_key, message):
    pubkey = RSA.import_key(public_key)
    cipher_rsa_en = PKCS1_OAEP.new(pubkey)

    if isinstance(message, str):  
        enc_data = cipher_rsa_en.encrypt(message.encode('ascii'))
    else:
        enc_data = cipher_rsa_en.encrypt(message)
    return enc_data

# For receiving encrypted messages using server privkey
def decryptMessageRSA(private_key, encrypted_message):
    privkey = RSA.import_key(private_key)
    cipher_rsa_dec = PKCS1_OAEP.new(privkey)
    dec_data = cipher_rsa_dec.decrypt(encrypted_message)
    return dec_data

# Encrypting using AES symmetric key
def encryptMessage(key, message):
    cipher = AES.new(key, AES.MODE_ECB)

    # Bytes then padded
    padded_message = pad(message.encode('ascii'), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message

# Decrypting using AES symmetric key
def decryptMessage(key, encrypted_message):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded_message = cipher.decrypt(encrypted_message)
    decrypted_message = unpad(decrypted_padded_message, AES.block_size)
    return decrypted_message.decode('ascii')

def client_handeler(connectionSocket, addr):   
    # This handles the entire exam for a single client connection

    # Load all client names and passwords from file

    # Prior to symkey generation, use RSA to securely exchange username/password
    # Encrypt using client pubkey when sending to client, decrypt using server privkey when receiving from client

    with open('user_pass.json', 'r') as f:
        user_pass_dict = json.load(f)

    client_name = ""
    try:

        #Server sends pubkey to client
        pubkey, privkey = generateRSAKeys()
        connectionSocket.send(pubkey)

        #Server recieves encrypted client pubkey
        client_pubkey = connectionSocket.recv(2048)

        welcome_msg = "Enter your name: "
        encrypted_message = encryptMessageRSA(client_pubkey, welcome_msg)
        connectionSocket.send(encrypted_message)
                
        # Server receives client user name
        encrypted_name = connectionSocket.recv(2048)
        NameStr = decryptMessageRSA(privkey, encrypted_name).decode('ascii').strip()

        # Server asks for password
        password_msg = f"Enter your password: "
        encrypted_password_msg = encryptMessageRSA(client_pubkey, password_msg)
        connectionSocket.send(encrypted_password_msg)

        # Server receives password
        encrypted_password = connectionSocket.recv(2048)
        PasswordStr = decryptMessageRSA(privkey, encrypted_password).decode('ascii').strip()
        
        print(f"Encrypted message recv: {encrypted_name}")
        print(f"encrypted message decrypted: {NameStr}")
        # Authentication for client, ensuring they exist in user_pass.json
        if NameStr in user_pass_dict and user_pass_dict[NameStr] == PasswordStr:
            auth_msg = f"Connection Accepted and Symmetric Key Generated for client: {NameStr}"
            print(auth_msg)
            sym_key = generateAESKey(NameStr)
            saveClientPubKey(NameStr, client_pubkey)
            
            # send symmetric key to client
            encrypted_sym_key = encryptMessageRSA(client_pubkey, sym_key)
            connectionSocket.send(encrypted_sym_key)
        else:
            connectionSocket.send("Invalid username or password")
            auth_msg = f"The received client information: {NameStr} is invalid (Connection Terminated)."

            connectionSocket.send(auth_msg.encode('ascii'))
            connectionSocket.close()    
            
            # Terminate child process
            os._exit(0)

        # Start Menu Loop
        while True:
            menu = (
                "\nPlease Select the operation:\n"
                "1) Create and send an email\n"
                "2) Display the inbox list\n"
                "3) Display the email contents\n"
                "4) Terminate the connection\n"
                "Choice: "
                )

            encrypted_menu = encryptMessage(sym_key, menu)
            connectionSocket.send(encrypted_menu)

            # Wait for client choice
            encrypted_choice = connectionSocket.recv(2048)
            choice = decryptMessage(sym_key, encrypted_choice).strip()

            if choice == '1':
                # Create and send an email

                # The format of the email message is as follows:
                # From: [The source client username who sent the message] \n
                # To: [The list of destination clients’ usernames separated by “;”] \n
                # Time and Date: [The time and date of receiving the message]\n
                # Title: [The title of the sent message with maximum length of 100 characters] \n
                # Content Length: [Number of characters in the content field] \n
                # Content: \n
                # [message contents with a maximum length of 1000000 characters]

                Enter_email_prompt = "Enter emails (separated by ;): "
                encrypted_prompt = encryptMessage(sym_key, Enter_email_prompt)
                connectionSocket.send(encrypted_prompt)

                user_input = connectionSocket.recv(2048)
                email_list = decryptMessage(sym_key, user_input).strip().split(';')
                Enter_title_prompt = "Enter title: "
                encrypted_prompt = encryptMessage(sym_key, Enter_title_prompt)
                connectionSocket.send(encrypted_prompt)

                user_input = connectionSocket.recv(2048)
                email_title = decryptMessage(sym_key, user_input).strip()
                load_content_prompt = "Would you like to load contents from a file? (Y/N): "
                encrypted_prompt = encryptMessage(sym_key, load_content_prompt)
                connectionSocket.send(encrypted_prompt)

                user_input = connectionSocket.recv(2048)
                load_choice = decryptMessage(sym_key, user_input).strip().upper()
                if load_choice == 'Y':
                    file_prompt = "Enter file path: "
                    encrypted_prompt = encryptMessage(sym_key, file_prompt)
                    connectionSocket.send(encrypted_prompt)

                    user_input = connectionSocket.recv(2048)
                    file_path = decryptMessage(sym_key, user_input).strip()
                    try:
                        with open(file_path, 'r') as f:
                            email_content = f.read()
                    except FileNotFoundError:
                        email_content = "File not found. Email content is empty."

                else:
                    Enter_content_prompt = "Enter content:"
                    encrypted_prompt = encryptMessage(sym_key, Enter_content_prompt)
                    connectionSocket.send(encrypted_prompt)

                    user_input = connectionSocket.recv(2048)
                    email_content = decryptMessage(sym_key, user_input).strip()
                # Format full email

                from datetime import datetime
                now = datetime.now()
                dt_string = now.strftime("%Y-%m-%d %H:%M:%S")
                full_email = (
                    f"From: {NameStr}\n"
                    f"To: {';'.join(email_list)}\n"
                    f"Time and Date: {dt_string}\n"
                    f"Title: {email_title}\n"
                    f"Content Length: {len(email_content)}\n"
                    f"Content:\n"
                    f"{email_content}"
                )

                print(full_email)

                # Save as text file in each recipient's folder
                for recipient in email_list:
                    recipient = recipient.strip()
                    if recipient:
                        recipient_dir = f"client/{recipient}"
                        if not os.path.exists(recipient_dir):
                            os.makedirs(recipient_dir)

                        # "[Username of source]_[email title].txt" 
                        # Assuming client will not send duplicate titled emails
                        email_filename = f"{NameStr}_{email_title}.txt"

                        full_path = os.path.join(recipient_dir, email_filename)
                        with open(full_path, 'w') as f:
                            f.write(full_email)
                
                # Send Confirmation Message
                Confirmation_prompt = "The message is sent to the server."
                encrypted_prompt = encryptMessage(sym_key, Confirmation_prompt)
                connectionSocket.send(encrypted_prompt)

                # Client ACK so that menu doesnt send right away
                connectionSocket.recv(2048) 

            elif choice == '2':
                # Display Index, From, Date/Time, Title
                # Reads client directory for emails

                # Format:
                # Index From    DateTime                   Title
                # 1     client2 2022-07-21 19:29:35.768508 Test2
                # 2     client1 2022-07-21 19:29:42.118132 Test

                client_directory = f"client/{NameStr}"
                
                if not os.path.exists(client_directory):
                    full_summary = "Inbox is empty (No directory found)."
                else:
                    email_files = [f for f in os.listdir(client_directory) if os.path.isfile(os.path.join(client_directory, f))]
                    if not email_files:
                        full_summary = "Inbox is empty."
                    else:
                        email_summaries = []
                for index, email_file in enumerate(email_files, start=1):
                    with open(os.path.join(client_directory, email_file), 'r') as f:
                        lines = f.readlines()
                        from_line = lines[0].strip()  # From: ...
                        date_line = lines[2].strip()  # Time and Date: ...
                        title_line = lines[3].strip()  # Title: ...
                        email_summaries.append(f"{index} {from_line[6:]} {date_line[15:]} {title_line[7:]}")
                summary_line =   "----------------------------------------------"
                summary_header = "Index From    DateTime                   Title\n"
                summary_content = "\n".join(email_summaries)
                full_summary = summary_line + summary_header + summary_content
                
                encrypted_summary = encryptMessage(sym_key, full_summary)
                connectionSocket.send(encrypted_summary)

                # Client ACK so that menu doesnt send right away
                connectionSocket.recv(2048) 

            elif choice == '3':
                # Display the email contents
                enter_index_prompt = "Enter the index of the email to display:\n"
                encrypted_prompt = encryptMessage(sym_key, enter_index_prompt)
                connectionSocket.send(encrypted_prompt)

                user_input = connectionSocket.recv(2048)
                email_index = int(decryptMessage(sym_key, user_input).strip())
                client_directory = f"client/{NameStr}"
                email_files = [f for f in os.listdir(client_directory) if os.path.isfile(os.path.join(client_directory, f))]
                if 1 <= email_index <= len(email_files):
                    email_file = email_files[email_index - 1]
                    with open(os.path.join(client_directory, email_file), 'r') as f:
                        email_content = f.read()
                    email_line = "----------------------------------------------"
                    encrypted_email_content = encryptMessage(sym_key, email_line + email_content)
                    connectionSocket.send(encrypted_email_content)
                else:
                    error_msg = "Invalid email index."
                    encrypted_error_msg = encryptMessage(sym_key, error_msg)
                    connectionSocket.send(encrypted_error_msg)

                connectionSocket.recv(2048)

            elif choice == '4':
                # Terminate connection
                goodbye_msg = "Terminated."
                encrypted_goodbye = encryptMessage(sym_key, goodbye_msg)
                connectionSocket.send(encrypted_goodbye)
                break

    except Exception as e:
        print('An error occured while communicating with the client:',e)
    finally:
        print(f"Connection with {addr} ({NameStr}) closed.")
        connectionSocket.close()

        os._exit(0)


def server():
    #Server port
    serverPort = 12001
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    #Associate 12000 port number to the server socket
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
        
    print('The server is ready to accept connections')
    
    # Call pub/priv key creation function here
    #
    generateRSAKeys()

    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)
    
    

    # get symmetric key in client_handler
    # key = getKey()

    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            print(addr,'   ',connectionSocket)
            pid = os.fork()
            
            # If it is a client process
            if  pid== 0:
                
                serverSocket.close() 
                
                client_handeler(connectionSocket, addr)
                
                connectionSocket.close()
                
                return
            
            else:
                #Parent doesn't need this connection
                connectionSocket.close()
            
        except socket.error as e:
            print('An error occured:',e)
            serverSocket.close() 
            sys.exit(1)        
        except:
            print('Goodbye')
            serverSocket.close() 
            sys.exit(0)
            
server()