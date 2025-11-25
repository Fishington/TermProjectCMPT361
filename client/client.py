# Client code Term Project CMPT361
import socket
import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Helper Functions For Encryption/Decryption

def getKey():
    with open('../key', 'rb') as f:
        key = f.read()
    return key


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
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    try:
        #Client connect with the server
        serverName = input("Enter server IP address or name: ")
        clientSocket.connect((serverName,serverPort))

        key = getKey()
        
        # Client receives a message and send it to the client
        encrypted_welcome = clientSocket.recv(2048)
        decrypted_welcome = decryptMessage(key, encrypted_welcome)
        print(decrypted_welcome)

        name = input()

        encrypted_name = encryptMessage(key, name)
        clientSocket.send(encrypted_name)

        # Start Menu Loop
        while True:
            
            # Receive Menu from server
            encrypted_menu = clientSocket.recv(2048)
            decrypted_menu = decryptMessage(key, encrypted_menu)
            print(decrypted_menu)

            choice = input()

            encrypted_choice = encryptMessage(key, choice)
            clientSocket.send(encrypted_choice)

            if choice == '1': # Create and Send Email
               
                encrypted_prompt = clientSocket.recv(2048)
                decrypted_prompt = decryptMessage(key, encrypted_prompt)
                print(decrypted_prompt)

                user_input = input()

                encrypted_input = encryptMessage(key, user_input)
                clientSocket.send(encrypted_input)


            elif choice == '2': # Display inbox list
                encrypted_prompt = clientSocket.recv(2048)
                decrypted_prompt = decryptMessage(key, encrypted_prompt)
                print(decrypted_prompt)

                user_input = input()

                encrypted_input = encryptMessage(key, user_input)
                clientSocket.send(encrypted_input)

            elif choice == '3':
                # Display the email contents
                encrypted_prompt = clientSocket.recv(2048)
                decrypted_prompt = decryptMessage(key, encrypted_prompt)
                print(decrypted_prompt)

                user_input = input()

                encrypted_input = encryptMessage(key, user_input)
                clientSocket.send(encrypted_input)

            elif choice == '4': # Terminate connection
                print("Connection Terminated.")
                clientSocket.close()
                break

            else:
                # Invalid choice handling
                encrypted_invalid = clientSocket.recv(2048)
                decrypted_invalid = decryptMessage(key, encrypted_invalid)
                print(decrypted_invalid)
        
    except socket.error as e:
        print('An error occured:',e)
        clientSocket.close()
        sys.exit(1)

#----------
client()
