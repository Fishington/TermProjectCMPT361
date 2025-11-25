# Server code Term Project CMPT361

import socket
import sys
import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Helper Functions For Encryption/Decryption

def getKey():
    with open('../key', 'rb') as f:
        key = f.read()
    return key

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

def client_handeler(connectionSocket, addr, key):   
    # This handles the entire exam for a single client connection

    client_name = ""
    try:

        #Server send a message to the client
        welcome_msg = "Enter your name: "
        encryped_message = encryptMessage(key, welcome_msg)
        connectionSocket.send(encryped_message)
                
        # Server receives client user name
        encrypted_name = connectionSocket.recv(2048)
        NameStr = decryptMessage(key, encrypted_name).strip()

        # Server asks for password
        password_msg = f"Enter your password: "
        encrypted_password_msg = encryptMessage(key, password_msg)
        connectionSocket.send(encrypted_password_msg)

        # Server receives password
        encrypted_password = connectionSocket.recv(2048)
        PasswordStr = decryptMessage(key, encrypted_password).strip()
        
        print(f"Encrypted message recv: {encrypted_name}")
        print(f"encrypted message decrypted: {NameStr}")

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

            encrypted_menu = encryptMessage(key, menu)
            connectionSocket.send(encrypted_menu)

            # Wait for client choice
            encrypted_choice = connectionSocket.recv(2048)
            choice = decryptMessage(key, encrypted_choice).strip()

            if choice == '1':
                # Create and send an email
                pass

            elif choice == '2':
                # Display inbox list
                pass

            elif choice == '3':
                # Display the email contents
                pass

            elif choice == '4':
                # Terminate connection
                goodbye_msg = "Terminated."
                encrypted_goodbye = encryptMessage(key, goodbye_msg)
                connectionSocket.send(encrypted_goodbye)
                break

    except Execption as e:
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
        
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)
    
    key = getKey()

    while 1:
        try:
            #Server accepts client connection
            connectionSocket, addr = serverSocket.accept()
            print(addr,'   ',connectionSocket)
            pid = os.fork()
            
            # If it is a client process
            if  pid== 0:
                
                serverSocket.close() 
                
                client_handeler(connectionSocket, addr, key)
                
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
            
        
#-------
server()
