# Client code Term Project CMPT361
import socket
import sys
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# Helper Functions For Encryption/Decryption

#def getKey():
#    with open('../key', 'rb') as f:
#        key = f.read()
#    return key

def generateRSAKeys(username):
    # Checks if keys exist on client machine
    if os.path.exists(f'../{username}_public.pem') and os.path.exists(f'../{username}_private.pem'):
        with open(f'../{username}_public.pem', 'rb') as f:
            public_key = f.read()

        with open(f'../{username}_private.pem', 'rb') as f:
            private_key = f.read()
        return public_key, private_key
    
    else:
    # Generates RSA key pair and saves to client machine
        key = RSA.generate(2048)
        private_key = key.export_key()
        with open(f'../{username}_private.pem', 'wb') as f:
            f.write(private_key)

        public_key = key.publickey().export_key()
        with open(f'../{username}_public.pem', 'wb') as f:
            f.write(public_key)
        return public_key, private_key

# Saves the server's public key for later use, if doesnt already exist
def saveServerPubKey(key):
    if not os.path.exists(f'../server_public.pem'):
        with open(f'../server_public.pem', 'wb') as f:
            f.write(key)

# For sending encrypted username to server
def encryptMessageRSA(public_key, message):
    pubkey = RSA.import_key(public_key)
    cipher_rsa_en = PKCS1_OAEP.new(pubkey)
    enc_data = cipher_rsa_en.encrypt(message.encode('ascii'))
    return enc_data

# For receiving encrypted messages using privkey from client
def decryptMessageRSA(private_key, encrypted_message):
    privkey = RSA.import_key(private_key)
    cipher_rsa_dec = PKCS1_OAEP.new(privkey)
    dec_data = cipher_rsa_dec.decrypt(encrypted_message)
    return dec_data

# Same as server.py
def encryptMessage(key, message):
    cipher = AES.new(key, AES.MODE_ECB)
    # Bytes then padded
    padded_message = pad(message.encode('ascii'), AES.block_size)
    encryped_message = cipher.encrypt(padded_message)
    return encryped_message

def decryptMessage(key, encrypted_message):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded_message = cipher.decrypt(encrypted_message)
    decrypted_message = unpad(decrypted_padded_message, AES.block_size)
    return decrypted_message.decode('ascii')


def client():
    # Server Information
    # serverName = '127.0.0.1' #'localhost'
    serverPort = 12001
    username = ""
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        # Prior to recieving symkey, use RSA to exchange username/password
        # Encrpyt using server pubkey when sending to server, decrypt using client privkey when receiving from server

        #Client connect with the server
        serverName = input("Enter server IP address or name: ")
        clientSocket.connect((serverName,serverPort))

        # Generate RSA Keys for client
        pubkey, privkey = generateRSAKeys(username)

        # Client receives server's public key
        server_pubkey= clientSocket.recv(2048)
        saveServerPubKey(server_pubkey)

        # Client sends client pubkey to server
        clientSocket.send(pubkey)
    
        # Client receives a message and decrypts it
        encrypted_welcome = clientSocket.recv(2048)
        decrypted_welcome = decryptMessageRSA(privkey, encrypted_welcome).decode('ascii')
        print(decrypted_welcome)

        username = input()

        encrypted_name = encryptMessageRSA(server_pubkey, username)
        clientSocket.send(encrypted_name)

        # Password request from server
        encrypted_pass_msg = clientSocket.recv(2048)
        decrypted_pass_msg = decryptMessageRSA(privkey, encrypted_pass_msg).decode('ascii')
        print(decrypted_pass_msg)

        # Input password and send to server
        password = input()
        encrypted_password = encryptMessageRSA(server_pubkey, password)
        clientSocket.send(encrypted_password)

        # recieve sym_key - after this all communication will use symmetric encryption, not RSA
        encrypted_sym_key = clientSocket.recv(2048)
        sym_key = decryptMessageRSA(privkey, encrypted_sym_key) # No need to decode here as sym_key is bytes as is

        # Start Menu Loop
        while True:
            
            # Receive Menu from server
            encrypted_menu = clientSocket.recv(2048)
            decrypted_menu = decryptMessage(sym_key, encrypted_menu)
            print(decrypted_menu)

            choice = input()

            encrypted_choice = encryptMessage(sym_key, choice)
            clientSocket.send(encrypted_choice)

            if choice == '1': # Create and Send Email

                # Enter Email
                Encrypted_email = clientSocket.recv(2048)
                decrypted_email = decryptMessage(sym_key, Encrypted_email) 
                print(decrypted_email)

                email_input = input()
                email_send = encryptMessage(sym_key, email_input)
                clientSocket.send(email_send)

                # Enter Title
                Encrypted_title = clientSocket.recv(2048)
                decrypted_title = decryptMessage(sym_key, Encrypted_title) 
                print(decrypted_title)

                title_input = input()
                title_send = encryptMessage(sym_key, title_input)
                clientSocket.send(title_send)

                # Load Contents 
                Encrypted_load = clientSocket.recv(2048)
                decrypted_load = decryptMessage(sym_key, Encrypted_load) 
                print(decrypted_load)

                load_input = input()
                load_send = encryptMessage(sym_key, load_input)
                clientSocket.send(load_send)

                if load_input.upper().strip() == 'Y':
                    # Path
                    Encrypted_path = clientSocket.recv(2048)
                    decrypted_path = decryptMessage(sym_key, Encrypted_path) 
                    print(decrypted_path)

                    path_input = input()
                    path_send = encryptMessage(sym_key, path_input)
                    clientSocket.send(path_send)
                
                else:
                    # Enter Content
                    Encrypted_content = clientSocket.recv(2048)
                    decrypted_content = decryptMessage(sym_key, Encrypted_content) 
                    print(decrypted_content)

                    content_input = input()
                    content_send = encryptMessage(sym_key, content_input)
                    clientSocket.send(content_send)

                # Confirmation Message
                Encrypted_conf = clientSocket.recv(2048)
                decrypted_conf = decryptMessage(sym_key, Encrypted_conf)
                print(decrypted_conf)

                # Send ACK So that sever doesnt send menu right away
                ack_msg = "OK"
                encrypted_ack = encryptMessage(sym_key, ack_msg)
                clientSocket.send(encrypted_ack)


            elif choice == '2': # Display inbox list
                encrypted_prompt = clientSocket.recv(4096)
                decrypted_prompt = decryptMessage(sym_key, encrypted_prompt)
                print(decrypted_prompt)

                # Send ACK So that sever doesnt send menu right away
                ack_msg = "OK"
                encrypted_ack = encryptMessage(sym_key, ack_msg)
                clientSocket.send(encrypted_ack)

            elif choice == '3':
                # Display the email contents
                encrypted_prompt = clientSocket.recv(2048)
                decrypted_prompt = decryptMessage(sym_key, encrypted_prompt)
                print(decrypted_prompt)

                user_input = input()

                encrypted_input = encryptMessage(sym_key, user_input)
                clientSocket.send(encrypted_input)

                encrypted_content = clientSocket.recv(2048)
                decrypted_content = decryptMessage(sym_key, encrypted_content)
                print(decrypted_content)

                # Send ACK So that sever doesnt send menu right away
                ack_msg = "OK"
                encrypted_ack = encryptMessage(sym_key, ack_msg)
                clientSocket.send(encrypted_ack)

            elif choice == '4': # Terminate connection
                encrypted_goodbye = clientSocket.recv(2048)
                decrypted_goodbye = decryptMessage(sym_key, encrypted_goodbye)
                print(decrypted_goodbye)
                clientSocket.close()
                break
            else:
                pass
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
