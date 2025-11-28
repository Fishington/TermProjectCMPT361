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

        # Password
        encrypted_pass_msg = clientSocket.recv(2048)
        decrypted_pass_msg = decryptMessage(key, encrypted_pass_msg)
        print(decrypted_pass_msg)

        password = input()
        encrypted_password = encryptMessage(key, password)
        clientSocket.send(encrypted_password)

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

                # Enter Email
                Encrypted_email = clientSocket.recv(2048)
                decrypted_email = decryptMessage(key, Encrypted_email) 
                print(decrypted_email)

                email_input = input()
                email_send = encryptMessage(key, email_input)
                clientSocket.send(email_send)

                # Enter Title
                Encrypted_title = clientSocket.recv(2048)
                decrypted_title = decryptMessage(key, Encrypted_title) 
                print(decrypted_title)

                title_input = input()
                title_send = encryptMessage(key, title_input)
                clientSocket.send(title_send)

                # Load Contents 
                Encrypted_load = clientSocket.recv(2048)
                decrypted_load = decryptMessage(key, Encrypted_load) 
                print(decrypted_load)

                load_input = input()
                load_send = encryptMessage(key, load_input)
                clientSocket.send(load_send)

                if load_input.upper().strip() == 'Y':
                    # Path
                    Encrypted_path = clientSocket.recv(2048)
                    decrypted_path = decryptMessage(key, Encrypted_path) 
                    print(decrypted_path)

                    path_input = input()
                    path_send = encryptMessage(key, path_input)
                    clientSocket.send(path_send)
                
                else:
                    # Enter Content
                    Encrypted_content = clientSocket.recv(2048)
                    decrypted_content = decryptMessage(key, Encrypted_content) 
                    print(decrypted_content)

                    content_input = input()
                    content_send = encryptMessage(key, content_input)
                    clientSocket.send(content_send)

                # Confirmation Message
                Encrypted_conf = clientSocket.recv(2048)
                decrypted_conf = decryptMessage(key, Encrypted_conf)
                print(decrypted_conf)

                # Send ACK So that sever doesnt send menu right away
                ack_msg = "OK"
                encrypted_ack = encryptMessage(key, ack_msg)
                clientSocket.send(encrypted_ack)


            elif choice == '2': # Display inbox list
                encrypted_prompt = clientSocket.recv(4096)
                decrypted_prompt = decryptMessage(key, encrypted_prompt)
                print(decrypted_prompt)

                # Send ACK So that sever doesnt send menu right away
                ack_msg = "OK"
                encrypted_ack = encryptMessage(key, ack_msg)
                clientSocket.send(encrypted_ack)

            elif choice == '3':
                # Display the email contents
                encrypted_prompt = clientSocket.recv(2048)
                decrypted_prompt = decryptMessage(key, encrypted_prompt)
                print(decrypted_prompt)

                user_input = input()

                encrypted_input = encryptMessage(key, user_input)
                clientSocket.send(encrypted_input)

                encrypted_content = clientSocket.recv(2048)
                decrypted_content = decryptMessage(key, encrypted_content)
                print(decrypted_content)

                # Send ACK So that sever doesnt send menu right away
                ack_msg = "OK"
                encrypted_ack = encryptMessage(key, ack_msg)
                clientSocket.send(encrypted_ack)

            elif choice == '4': # Terminate connection
                encrypted_goodbye = clientSocket.recv(2048)
                decrypted_goodbye = decryptMessage(key, encrypted_goodbye)
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
