# Enhanced client with replay protection for CMPT 361 project

import socket
import sys
import os
import json

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256


# Helper Functions For Encryption/Decryption

# Returns pubkey for server or (pubkey, privkey) for client, depending on if username is provided
def getRSAKeys(username=None):
    if username == None:
        with open('server_public.pem', 'rb') as f:
            public_key = f.read()
        return public_key
    elif username != None:
        if not os.path.exists(username):
            print("Username does not exist locally. Generate keys first.")
            sys.exit(1)
        with open(f'{username}/{username}_private.pem', 'rb') as f:
            private_key = f.read()
        with open(f'{username}/{username}_public.pem', 'rb') as f:
            public_key = f.read()
        return public_key, private_key

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


def encryptMessage(key, message):
    
    # Encrypt a plaintext string using AES-256 in ECB mode with PKCS#7 padding.
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode('ascii'), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return encrypted_message


def decryptMessage(key, encrypted_message):
    
    # Decrypt an AES-ECB ciphertext (bytes) and return the plaintext string.
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded_message = cipher.decrypt(encrypted_message)
    decrypted_message = unpad(decrypted_padded_message, AES.block_size)
    return decrypted_message.decode('ascii')



# Enhanced protocol helpers: MAC + sequence numbers

def compute_mac(key, seq, payload_str):
    """
    Compute HMAC-SHA256 over (seq || '||' || payload_str) using the symmetric key.
    key: bytes (same AES key)
    seq: integer sequence number
    payload_str: string payload
    returns: hex string MAC
    """
    h = HMAC.new(key, digestmod=SHA256)
    h.update(str(seq).encode('ascii'))
    h.update(b'||')
    h.update(payload_str.encode('ascii'))
    return h.hexdigest()


def pack_secure_message(key, seq, payload_str):
    """
    Build a secure message object:
        { "seq": seq, "payload": payload_str, "mac": mac }
    Serialize as JSON string and encrypt with AES (encryptMessage).
    """
    mac = compute_mac(key, seq, payload_str)
    msg_obj = {
        "seq": seq,
        "payload": payload_str,
        "mac": mac
    }
    clear_text = json.dumps(msg_obj)
    encrypted = encryptMessage(key, clear_text)
    return encrypted

def pack_secure_messageRSA(key, seq, payload_str):
    """
    Build a secure message object:
        { "seq": seq, "payload": payload_str, "mac": mac }
    Serialize as JSON string and encrypt with RSA (encryptMessageRSA).
    """
    msg_obj = {
        "seq": seq,
        "payload": payload_str
    }
    clear_text = json.dumps(msg_obj)
    encrypted = encryptMessageRSA(key, clear_text)
    return encrypted


def unpack_secure_message(key, encrypted_bytes, expected_seq):
    
    # Decrypt a secure message, verify MAC and expected sequence number.
    # Returns the payload string if valid, otherwise raises ValueError.
    clear_text = decryptMessage(key, encrypted_bytes)
    msg_obj = json.loads(clear_text)

    seq = msg_obj.get("seq")
    payload_str = msg_obj.get("payload")
    mac = msg_obj.get("mac")

    if seq is None or payload_str is None or mac is None:
        raise ValueError("Malformed secure message")

    mac_check = compute_mac(key, seq, payload_str)

    if mac != mac_check:
        raise ValueError("MAC verification failed")

    if seq != expected_seq:
        raise ValueError(f"Unexpected sequence number: got {seq}, expected {expected_seq}")

    return payload_str

def unpack_secure_messageRSA(key, encrypted_bytes, expected_seq):
    
    # Decrypt a RSA secure message, and expected sequence number.
    # Returns the payload string if valid, otherwise raises ValueError.
    clear_text = decryptMessageRSA(key, encrypted_bytes)
    msg_obj = json.loads(clear_text)

    seq = msg_obj.get("seq")
    payload_str = msg_obj.get("payload")

    if seq is None or payload_str is None:
        raise ValueError("Malformed secure message")

    if seq != expected_seq:
        raise ValueError(f"Unexpected sequence number: got {seq}, expected {expected_seq}")

    return payload_str

# Client main logic (enhanced)

def client():
    # Server Information
    # serverName = '127.0.0.1'  # 'localhost'
    serverPort = 13000

    # Create client socket that uses IPv4 and TCP Protocols
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:', e)
        sys.exit(1)

    try:
        # Client connect with the server
        serverName = input("Enter server IP address or name: ")
        clientSocket.connect((serverName, serverPort))

        # Sequence numbers for secure messages
        send_seq = 1  # messages we send to server
        recv_seq = 1  # messages we receive from server

        
        # Login / initial exchange
        

        # Receive welcome message (unsecure)
        welcome_msg = clientSocket.recv(4096).decode('ascii')
        print(welcome_msg)

        # Send username
        name = input()
        pubkey, privkey = getRSAKeys(name)  # Get client keys for this username
        server_pubkey = getRSAKeys()  # Get server public key
        encrypted_name = pack_secure_messageRSA(server_pubkey, send_seq, name)
        clientSocket.send(encrypted_name)
        send_seq += 1

        # Receive password prompt
        encrypted_pass_msg = clientSocket.recv(4096)
        pass_prompt = unpack_secure_messageRSA(privkey, encrypted_pass_msg, recv_seq)
        recv_seq += 1
        print(pass_prompt)

        # Send password
        password = input()
        encrypted_password = pack_secure_messageRSA(server_pubkey, send_seq, password)
        clientSocket.send(encrypted_password)
        send_seq += 1

        # Receive symmetric key
        encryptedSymKey = clientSocket.recv(4096)

        hex_key = unpack_secure_messageRSA(privkey, encryptedSymKey, recv_seq)
        key = bytes.fromhex(hex_key)
        recv_seq += 1
        
        # Start Menu Loop
        
        while True:

            # Receive menu from server (secure)
            encrypted_menu = clientSocket.recv(4096)
            menu_text = unpack_secure_message(key, encrypted_menu, recv_seq)
            recv_seq += 1
            print(menu_text)

            choice = input().strip()

            # Send menu choice (secure)
            encrypted_choice = pack_secure_message(key, send_seq, choice)
            clientSocket.send(encrypted_choice)
            send_seq += 1

            if choice == '1':   # Create and send an email

                # Enter Email (destinations)
                encrypted_email_prompt = clientSocket.recv(4096)
                email_prompt = unpack_secure_message(key, encrypted_email_prompt, recv_seq)
                recv_seq += 1
                print(email_prompt)

                email_input = input()
                encrypted_email_input = pack_secure_message(key, send_seq, email_input)
                clientSocket.send(encrypted_email_input)
                send_seq += 1

                # Enter Title
                encrypted_title_prompt = clientSocket.recv(4096)
                title_prompt = unpack_secure_message(key, encrypted_title_prompt, recv_seq)
                recv_seq += 1
                print(title_prompt)

                title_input = input()
                encrypted_title_input = pack_secure_message(key, send_seq, title_input)
                clientSocket.send(encrypted_title_input)
                send_seq += 1

                # Load Contents 
                encrypted_load_prompt = clientSocket.recv(4096)
                load_prompt = unpack_secure_message(key, encrypted_load_prompt, recv_seq)
                recv_seq += 1
                print(load_prompt)

                load_input = input()
                encrypted_load_input = pack_secure_message(key, send_seq, load_input)
                clientSocket.send(encrypted_load_input)
                send_seq += 1

                if load_input.upper().strip() == 'Y':
                    # Path prompt
                    encrypted_path_prompt = clientSocket.recv(4096)
                    path_prompt = unpack_secure_message(key, encrypted_path_prompt, recv_seq)
                    recv_seq += 1
                    print(path_prompt)

                    path_input = input()
                    encrypted_path_input = pack_secure_message(key, send_seq, path_input)
                    clientSocket.send(encrypted_path_input)
                    send_seq += 1

                else:
                    # Enter content manually
                    encrypted_content_prompt = clientSocket.recv(4096)
                    content_prompt = unpack_secure_message(key, encrypted_content_prompt, recv_seq)
                    recv_seq += 1
                    print(content_prompt)

                    content_input = input()
                    encrypted_content_input = pack_secure_message(key, send_seq, content_input)
                    clientSocket.send(encrypted_content_input)
                    send_seq += 1

                # Confirmation message
                encrypted_conf = clientSocket.recv(4096)
                conf_msg = unpack_secure_message(key, encrypted_conf, recv_seq)
                recv_seq += 1
                print(conf_msg)

                # Send ACK so that server doesn't send menu right away
                ack_msg = "OK"
                encrypted_ack = pack_secure_message(key, send_seq, ack_msg)
                clientSocket.send(encrypted_ack)
                send_seq += 1

            elif choice == '2':  # Display inbox list
                encrypted_prompt = clientSocket.recv(4096)
                inbox_summary = unpack_secure_message(key, encrypted_prompt, recv_seq)
                recv_seq += 1
                print(inbox_summary)

                # Send ACK so that server doesn't send menu right away
                ack_msg = "OK"
                encrypted_ack = pack_secure_message(key, send_seq, ack_msg)
                clientSocket.send(encrypted_ack)
                send_seq += 1

            elif choice == '3':  # Display the email contents
                encrypted_prompt = clientSocket.recv(4096)
                index_prompt = unpack_secure_message(key, encrypted_prompt, recv_seq)
                recv_seq += 1
                print(index_prompt)

                user_input = input()
                encrypted_input = pack_secure_message(key, send_seq, user_input)
                clientSocket.send(encrypted_input)
                send_seq += 1

                encrypted_content = clientSocket.recv(4096)
                email_contents = unpack_secure_message(key, encrypted_content, recv_seq)
                recv_seq += 1
                print(email_contents)

                # Send ACK so that server doesn't send menu right away
                ack_msg = "OK"
                encrypted_ack = pack_secure_message(key, send_seq, ack_msg)
                clientSocket.send(encrypted_ack)
                send_seq += 1

            elif choice == '4':  # Terminate connection
                encrypted_goodbye = clientSocket.recv(4096)
                goodbye_msg = unpack_secure_message(key, encrypted_goodbye, recv_seq)
                recv_seq += 1
                print(goodbye_msg)
                clientSocket.close()
                break

            else:
                # Invalid choice: let server loop and resend menu
                pass

    except ValueError as ve:
        # Catches MAC / sequence failures
        print("[SECURITY] Secure message verification failed:", ve)
        print("[SECURITY] Terminating connection due to possible replay or tampering.")
        try:
            clientSocket.close()
        except Exception:
            pass
        sys.exit(1)

    except socket.error as e:
        print('An error occured:', e)
        try:
            clientSocket.close()
        except Exception:
            pass
        sys.exit(1)


# ----------
if __name__ == "__main__":
    client()
