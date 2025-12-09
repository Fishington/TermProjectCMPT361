import socket
import sys
import os
import json
import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA Keys for Server or Client
def generateRSAKeys(username=None):

    # If no username is provided, generate server keys
    if username == None:
        
        key = RSA.generate(2048)
        private_key = key.export_key()
        with open('server_private.pem', 'wb') as f:
            f.write(private_key)

        public_key = key.publickey().export_key()
        with open('server_public.pem', 'wb') as f:
            f.write(public_key)
    
    # If username is provided, generate keys for that user
    else:
        
        key = RSA.generate(2048)
        private_key = key.export_key()
        if not os.path.exists(username):
            os.makedirs(username)
        with open(f'{username}/{username}_private.pem', 'wb') as f:
            f.write(private_key)

        public_key = key.publickey().export_key()
        with open(f'{username}/{username}_public.pem', 'wb') as f:
            f.write(public_key)
        

def generate():
    with open('user_pass.json', 'r') as f:
        user_pass_dict = json.load(f)
    
    generateRSAKeys()
    for username in user_pass_dict.keys():
        generateRSAKeys(username)


if __name__ == "__main__":
    generate()