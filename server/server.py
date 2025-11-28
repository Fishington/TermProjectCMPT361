# Server code Term Project CMPT361

import socket
import sys
import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Helper Functions For Encryption/Decryption

def generateAESKey(client_name):
    # Generate a 256 AES key
    key = os.urandom(32)  # AES-256
    with open(f'../client/{client_name}/sym_key', 'wb') as f:
        f.write(key)
    return key


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

                # The format of the email message is as follows:
                # From: [The source client username who sent the message] \n
                # To: [The list of destination clients’ usernames separated by “;”] \n
                # Time and Date: [The time and date of receiving the message]\n
                # Title: [The title of the sent message with maximum length of 100 characters] \n
                # Content Length: [Number of characters in the content field] \n
                # Content: \n
                # [message contents with a maximum length of 1000000 characters]

                Enter_email_prompt = "Enter emails (separated by ;): "
                encrypted_prompt = encryptMessage(key, Enter_email_prompt)
                connectionSocket.send(encrypted_prompt)

                user_input = connectionSocket.recv(2048)
                email_list = decryptMessage(key, user_input).strip().split(';')

                Enter_title_prompt = "Enter title: "
                encrypted_prompt = encryptMessage(key, Enter_title_prompt)
                connectionSocket.send(encrypted_prompt)

                user_input = connectionSocket.recv(2048)
                email_title = decryptMessage(key, user_input).strip()

                load_content_prompt = "Would you like to load contents from a file? (Y/N): "
                encrypted_prompt = encryptMessage(key, load_content_prompt)
                connectionSocket.send(encrypted_prompt)

                user_input = connectionSocket.recv(2048)
                load_choice = decryptMessage(key, user_input).strip().upper()

                if load_choice == 'Y':
                    file_prompt = "Enter file path: "
                    encrypted_prompt = encryptMessage(key, file_prompt)
                    connectionSocket.send(encrypted_prompt)

                    user_input = connectionSocket.recv(2048)
                    file_path = decryptMessage(key, user_input).strip()

                    try:
                        with open(file_path, 'r') as f:
                            email_content = f.read()
                    except FileNotFoundError:
                        email_content = "File not found. Email content is empty."

                else:
                    Enter_content_prompt = "Enter content:"
                    encrypted_prompt = encryptMessage(key, Enter_content_prompt)
                    connectionSocket.send(encrypted_prompt)

                    user_input = connectionSocket.recv(2048)
                    email_content = decryptMessage(key, user_input).strip()

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
                        recipient_dir = f"../client/{recipient}"
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
                encrypted_prompt = encryptMessage(key, Confirmation_prompt)
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

                client_directory = f"../client/{NameStr}"
                
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
                
                encrypted_summary = encryptMessage(key, full_summary)
                connectionSocket.send(encrypted_summary)

                # Client ACK so that menu doesnt send right away
                connectionSocket.recv(2048) 

            elif choice == '3':
                # Display the email contents
                enter_index_prompt = "Enter the index of the email to display:\n"
                encrypted_prompt = encryptMessage(key, enter_index_prompt)
                connectionSocket.send(encrypted_prompt)

                user_input = connectionSocket.recv(2048)
                email_index = int(decryptMessage(key, user_input).strip())
                client_directory = f"../client/{NameStr}"
                email_files = [f for f in os.listdir(client_directory) if os.path.isfile(os.path.join(client_directory, f))]
                if 1 <= email_index <= len(email_files):
                    email_file = email_files[email_index - 1]
                    with open(os.path.join(client_directory, email_file), 'r') as f:
                        email_content = f.read()
                    email_line = "----------------------------------------------"
                    encrypted_email_content = encryptMessage(key, email_line + email_content)
                    connectionSocket.send(encrypted_email_content)
                else:
                    error_msg = "Invalid email index."
                    encrypted_error_msg = encryptMessage(key, error_msg)
                    connectionSocket.send(encrypted_error_msg)

                connectionSocket.recv(2048)

            elif choice == '4':
                # Terminate connection
                goodbye_msg = "Terminated."
                encrypted_goodbye = encryptMessage(key, goodbye_msg)
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
        
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(5)
    
    # Need to do SHA Key Here
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
