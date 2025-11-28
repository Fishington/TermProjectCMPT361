# Enhanced server with replay protection for CMPT 361 project

import socket
import sys
import os
import json
import datetime
import glob

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA256


# Helper Functions For Encryption/Decryption

def getKey():
    
    # Read the symmetric AES key from ../key.
    with open('../key', 'rb') as f:
        key = f.read()
    return key


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



# User / Mailbox helpers

def load_user_pass():
    
    # Load username/password pairs from ../user_pass.json.
    # Expected structure: { "client1": "password1", ... }
    with open('../user_pass.json', 'r') as f:
        data = json.load(f)
    return data


def ensure_mailbox_dir(username):
    
    # Ensure the mailbox directory for the given username exists.
    # It is created inside the server/ directory (same dir as this file).
    base_dir = os.path.dirname(os.path.abspath(__file__))
    user_dir = os.path.join(base_dir, username)
    if not os.path.isdir(user_dir):
        os.makedirs(user_dir, exist_ok=True)
    return user_dir


def get_inbox_files(username):
    
    # Return a list of (filepath, datetime_obj, title, from_user) for the given user,
    # sorted by datetime.
    user_dir = ensure_mailbox_dir(username)
    pattern = os.path.join(user_dir, "*.txt")
    files = glob.glob(pattern)

    results = []
    for path in files:
        try:
            with open(path, 'r') as f:
                lines = f.readlines()
            # Expecting:
            # 0: From: ...
            # 1: To: ...
            # 2: Time and Date: ...
            # 3: Title: ...
            from_line = lines[0].strip()
            time_line = lines[2].strip()
            title_line = lines[3].strip()

            from_user = from_line.split(":", 1)[1].strip()
            # "Time and Date: 2022-07-21 19:29:42.118132"
            time_str = time_line.split(":", 1)[1].strip()
            # datetime.fromisoformat should work with str(x) of datetime
            dt = datetime.datetime.fromisoformat(time_str)
            title = title_line.split(":", 1)[1].strip()
            results.append((path, dt, title, from_user))
        except Exception:
            # If parsing fails, skip the file
            continue

    # Sort by datetime (oldest first)
    results.sort(key=lambda x: x[1])
    return results


# Client handler


def handle_client(connectionSocket, clientAddress):
    key = getKey()
    user_pass = load_user_pass()

    send_seq = 1  # messages we send to this client
    recv_seq = 1  # messages we receive from this client

    username = None

    try:
        
        # Login / initial exchange

        welcome_msg = "Enter your username: "
        encrypted_welcome = pack_secure_message(key, send_seq, welcome_msg)
        connectionSocket.send(encrypted_welcome)
        send_seq += 1
        print(f"[INFO] Sent welcome prompt to {clientAddress}")

        encrypted_name = connectionSocket.recv(4096)
        username = unpack_secure_message(key, encrypted_name, recv_seq).strip()
        recv_seq += 1
        print(f"[INFO] Received username '{username}' from {clientAddress}")

        pass_prompt = "Enter your password: "
        encrypted_pass_prompt = pack_secure_message(key, send_seq, pass_prompt)
        connectionSocket.send(encrypted_pass_prompt)
        send_seq += 1

        encrypted_pass = connectionSocket.recv(4096)
        password = unpack_secure_message(key, encrypted_pass, recv_seq).strip()
        recv_seq += 1

        valid = (username in user_pass and user_pass[username] == password)

        if not valid:
            error_msg = "Invalid username or password. Terminating connection."
            encrypted_error = pack_secure_message(key, send_seq, error_msg)
            connectionSocket.send(encrypted_error)
            send_seq += 1
            print(f"[WARN] Invalid login attempt for username '{username}' from {clientAddress}")
            connectionSocket.close()
            return

        print(f"[INFO] Connection accepted for user '{username}' from {clientAddress}")

        
        # Main menu loop

        while True:
            menu = (
                "Select the operation:\n"
                "1) Create and send an email\n"
                "2) Display the inbox list\n"
                "3) Display the email contents\n"
                "4) Terminate the connection\n"
                "choice: "
            )

            encrypted_menu = pack_secure_message(key, send_seq, menu)
            connectionSocket.send(encrypted_menu)
            send_seq += 1

            encrypted_choice = connectionSocket.recv(4096)
            choice = unpack_secure_message(key, encrypted_choice, recv_seq).strip()
            recv_seq += 1
            print(f"[INFO] User '{username}' selected choice '{choice}'")

            if choice == '1':
            
                # Create and send an email

                # Destinations
                email_prompt = "Enter destinations (separated by ;): "
                encrypted_email_prompt = pack_secure_message(key, send_seq, email_prompt)
                connectionSocket.send(encrypted_email_prompt)
                send_seq += 1

                encrypted_email_input = connectionSocket.recv(4096)
                destinations = unpack_secure_message(key, encrypted_email_input, recv_seq).strip()
                recv_seq += 1

                # Title
                title_prompt = "Enter title: "
                encrypted_title_prompt = pack_secure_message(key, send_seq, title_prompt)
                connectionSocket.send(encrypted_title_prompt)
                send_seq += 1

                encrypted_title_input = connectionSocket.recv(4096)
                title = unpack_secure_message(key, encrypted_title_input, recv_seq).strip()
                recv_seq += 1

                # Load from file or enter contents
                load_prompt = "Would you like to load contents from a file? (Y/N): "
                encrypted_load_prompt = pack_secure_message(key, send_seq, load_prompt)
                connectionSocket.send(encrypted_load_prompt)
                send_seq += 1

                encrypted_load_input = connectionSocket.recv(4096)
                load_input = unpack_secure_message(key, encrypted_load_input, recv_seq).strip()
                recv_seq += 1

                load_from_file = (load_input.upper() == 'Y')

                if load_from_file:
                    path_prompt = "Enter filename: "
                    encrypted_path_prompt = pack_secure_message(key, send_seq, path_prompt)
                    connectionSocket.send(encrypted_path_prompt)
                    send_seq += 1

                    encrypted_path_input = connectionSocket.recv(4096)
                    filename = unpack_secure_message(key, encrypted_path_input, recv_seq).strip()
                    recv_seq += 1

                    try:
                        with open(filename, 'r') as f:
                            content = f.read()
                    except Exception:
                        content = ""
                else:
                    content_prompt = "Enter message contents: "
                    encrypted_content_prompt = pack_secure_message(key, send_seq, content_prompt)
                    connectionSocket.send(encrypted_content_prompt)
                    send_seq += 1

                    encrypted_content_input = connectionSocket.recv(4096)
                    content = unpack_secure_message(key, encrypted_content_input, recv_seq)
                    recv_seq += 1

                # Validate lengths
                if len(title) > 100 or len(content) > 1000000:
                    conf_msg = "Error: title or content length invalid. Email not sent."
                    encrypted_conf = pack_secure_message(key, send_seq, conf_msg)
                    connectionSocket.send(encrypted_conf)
                    send_seq += 1

                    # Receive ACK
                    encrypted_ack = connectionSocket.recv(4096)
                    _ = unpack_secure_message(key, encrypted_ack, recv_seq)
                    recv_seq += 1
                    continue

                # Construct email string
                time_received = datetime.datetime.now()
                content_len = len(content)

                email_text = (
                    f"From: {username}\n"
                    f"To: {destinations}\n"
                    f"Time and Date: {time_received}\n"
                    f"Title: {title}\n"
                    f"Content Length: {content_len}\n"
                    f"Content:\n"
                    f"{content}"
                )

                # Store email in each destination's mailbox
                dest_list = [d.strip() for d in destinations.split(';') if d.strip()]
                for dest_user in dest_list:
                    dest_dir = ensure_mailbox_dir(dest_user)
                    file_name = f"{username}_{title}.txt"
                    file_path = os.path.join(dest_dir, file_name)
                    with open(file_path, 'w') as f:
                        f.write(email_text)

                conf_msg = "The message is sent to the server."
                encrypted_conf = pack_secure_message(key, send_seq, conf_msg)
                connectionSocket.send(encrypted_conf)
                send_seq += 1

                # Receive ACK from client so we don't send menu immediately
                encrypted_ack = connectionSocket.recv(4096)
                _ = unpack_secure_message(key, encrypted_ack, recv_seq)
                recv_seq += 1

                print(f"[INFO] Email from '{username}' sent to {dest_list} with title '{title}'")

            elif choice == '2':
                
                # Display inbox list

                inbox_entries = get_inbox_files(username)
                if not inbox_entries:
                    summary = "Inbox is empty."
                else:
                    summary_lines = ["Index\tFrom\tDateTime\tTitle"]
                    for idx, (path, dt, title, from_user) in enumerate(inbox_entries, start=1):
                        summary_lines.append(f"{idx}\t{from_user}\t{dt}\t{title}")
                    summary = "\n".join(summary_lines)

                encrypted_summary = pack_secure_message(key, send_seq, summary)
                connectionSocket.send(encrypted_summary)
                send_seq += 1

                # Receive ACK
                encrypted_ack = connectionSocket.recv(4096)
                _ = unpack_secure_message(key, encrypted_ack, recv_seq)
                recv_seq += 1

                print(f"[INFO] Sent inbox list to '{username}'")

            elif choice == '3':

                # Display the email contents

                prompt = "Enter the email index you wish to view: "
                encrypted_prompt = pack_secure_message(key, send_seq, prompt)
                connectionSocket.send(encrypted_prompt)
                send_seq += 1

                encrypted_idx = connectionSocket.recv(4096)
                idx_str = unpack_secure_message(key, encrypted_idx, recv_seq).strip()
                recv_seq += 1

                inbox_entries = get_inbox_files(username)
                email_contents = ""

                try:
                    idx = int(idx_str)
                    if idx < 1 or idx > len(inbox_entries):
                        email_contents = "Invalid email index."
                    else:
                        file_path = inbox_entries[idx - 1][0]
                        with open(file_path, 'r') as f:
                            email_contents = f.read()
                except Exception:
                    email_contents = "Invalid email index."

                encrypted_contents = pack_secure_message(key, send_seq, email_contents)
                connectionSocket.send(encrypted_contents)
                send_seq += 1

                # Receive ACK
                encrypted_ack = connectionSocket.recv(4096)
                _ = unpack_secure_message(key, encrypted_ack, recv_seq)
                recv_seq += 1

                print(f"[INFO] Sent email contents to '{username}' for index {idx_str}")

            elif choice == '4':
                
                # Terminate connection
                

                goodbye_msg = "The connection is terminated with the server."
                encrypted_goodbye = pack_secure_message(key, send_seq, goodbye_msg)
                connectionSocket.send(encrypted_goodbye)
                send_seq += 1

                print(f"[INFO] Terminating connection with '{username}'")
                connectionSocket.close()
                break

            else:
                # Invalid choice: ignore and continue (client will see menu again)
                print(f"[WARN] User '{username}' sent invalid choice '{choice}'")
                continue

    except ValueError as ve:
        # Catches MAC / sequence number failures
        print(f"[SECURITY] Secure message verification failed for {clientAddress}: {ve}")
        print("[SECURITY] Terminating connection due to possible replay or tampering.")
        try:
            connectionSocket.close()
        except Exception:
            pass

    except socket.error as e:
        print(f"[ERROR] Socket error with {clientAddress}: {e}")
        try:
            connectionSocket.close()
        except Exception:
            pass



# Main server loop


def main():
    serverPort = 12001

    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:', e)
        sys.exit(1)

    try:
        serverSocket.bind(('', serverPort))
        serverSocket.listen(5)
        print(f"[INFO] The server is ready to accept connections on port {serverPort}")
    except socket.error as e:
        print('Bind/listen failed:', e)
        serverSocket.close()
        sys.exit(1)

    while True:
        try:
            connectionSocket, addr = serverSocket.accept()
            print(f"[INFO] Accepted connection from {addr}")
            # For simplicity, handle one client at a time (no fork here).
            handle_client(connectionSocket, addr)
        except KeyboardInterrupt:
            print("\n[INFO] Server shutting down.")
            serverSocket.close()
            break
        except Exception as e:
            print(f"[ERROR] Unexpected error in main loop: {e}")
            continue


if __name__ == "__main__":
    main()
