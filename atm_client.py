# ATM Client with Secure Communication

import socket
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import hmac
import os
import getpass

# Global variables
global username
username = None

# Client configuration
key = "secure_bank_key_123!"
psk = b"pre_shared_key_456$"

# Session keys
enc_key = None
mac_key = None
username = None

# Debug settings
DEBUG = True

def debug_log(message):
    if DEBUG:
        print(f"[DEBUG] {message}")

def hmac_sha256(key: bytes, msg: bytes):
    return hmac.new(key, msg, hashlib.sha256).digest()

def generate_nonce():
    return os.urandom(16)

def to_b64(data):
    return base64.b64encode(data).decode()

def from_b64(data):
    return base64.b64decode(data)

def derive_keys(master_secret):
    """Derive encryption and MAC keys from master secret"""
    debug_log(f"Deriving keys from master secret: {master_secret.hex()[:16]}...")
    enc_key = hmac_sha256(master_secret, b"encryption" + b"\x00"*28)[:32]
    mac_key = hmac_sha256(master_secret, b"integrity" + b"\x00"*28)[:32]
    debug_log(f"Derived enc_key: {enc_key.hex()[:16]}..., mac_key: {mac_key.hex()[:16]}...")
    return enc_key, mac_key

def encrypt_and_sign(message, enc_key, mac_key):
    """Encrypt message and generate MAC"""
    debug_log(f"Encrypting message: {message[:50]}...")
    cipher = AES.new(enc_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    encrypted = base64.b64encode(iv + ct_bytes).decode()
    
    mac = hmac_sha256(mac_key, encrypted.encode())
    mac_b64 = base64.b64encode(mac).decode()
    debug_log(f"Generated MAC: {mac_b64[:16]}...")
    
    return f"{encrypted}:{mac_b64}"

def verify_and_decrypt(encrypted_message, enc_key, mac_key):
    """Verify MAC and decrypt message"""
    debug_log("Verifying and decrypting message...")
    try:
        encrypted, received_mac_b64 = encrypted_message.split(":")
        received_mac = base64.b64decode(received_mac_b64)
        
        expected_mac = hmac_sha256(mac_key, encrypted.encode())
        debug_log(f"Received MAC: {received_mac.hex()[:16]}..., Expected: {expected_mac.hex()[:16]}...")
        
        if not hmac.compare_digest(received_mac, expected_mac):
            print("[SECURITY ALERT] MAC verification failed!")
            return None
            
        combined = base64.b64decode(encrypted)
        iv = combined[:16]
        ct = combined[16:]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
        debug_log(f"Decrypted message: {pt[:50]}...")
        
        return pt
    except Exception as e:
        print(f"[SECURITY ERROR] Decryption failed: {str(e)}")
        return None

def connect_to_server():
    host = 'localhost'
    port = 5555

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect((host, port))
        debug_log("Connected to server")
        return client
    except ConnectionRefusedError:
        print("Server unavailable. Please try later.")
        return None
    except Exception as e:
        print(f"Connection error: {str(e)}")
        return None

def send_request(client, request, enc_key=None, mac_key=None):
    debug_log(f"Preparing {request['action']} request")
    try:
        if enc_key is None or mac_key is None:
            debug_log("Using pre-shared key")
            temp_enc_key = hashlib.sha256(key.encode()).digest()
            temp_mac_key = hashlib.sha256(key.encode()).digest()
        else:
            debug_log("Using session keys")
            temp_enc_key = enc_key
            temp_mac_key = mac_key

        secured_request = encrypt_and_sign(json.dumps(request), temp_enc_key, temp_mac_key)
        debug_log(f"Sending request (length: {len(secured_request)})")
        client.send(secured_request.encode())
        
        response = client.recv(1024).decode()
        if not response:
            debug_log("Empty server response")
            raise ValueError("Empty response")

        debug_log(f"Received response (length: {len(response)})")
        decrypted_response = verify_and_decrypt(response, temp_enc_key, temp_mac_key)
        if not decrypted_response:
            raise ValueError("Invalid server response")
            
        return json.loads(decrypted_response)
    except Exception as e:
        print(f"Error: {str(e)}")
        return {"status": "error", "message": "Server communication error."}

def run_akdp(client, username_param):
    global username  # Add this line
    username = username_param  # Use a different parameter name to avoid shadowing
    debug_log("Starting AKDP protocol")
    # ... rest of the function remains the same ...
    nonce1 = generate_nonce()
    debug_log(f"Generated nonce1: {to_b64(nonce1)}")

    step1 = {
        "action": "akdp_step1",
        "username": username,
        "nonce1": to_b64(nonce1)
    }
    response = send_request(client, step1, key, None)

    nonce2 = from_b64(response["nonce2"])
    server_hmac = from_b64(response["server_hmac"])
    debug_log(f"Received nonce2: {response['nonce2']}")
    debug_log(f"Received server_hmac: {response['server_hmac'][:16]}...")

    expected_hmac = hmac_sha256(psk, nonce1 + nonce2 + b"SERVER")
    debug_log(f"Verifying server HMAC...")
    debug_log(f"Expected: {expected_hmac.hex()[:16]}..., Received: {server_hmac.hex()[:16]}...")

    if not hmac.compare_digest(server_hmac, expected_hmac):
        print("Server authentication failed!")
        return None

    global enc_key, mac_key
    master_secret = hmac_sha256(psk, nonce1 + nonce2)
    enc_key, mac_key = derive_keys(master_secret)

    confirm = hmac_sha256(master_secret, b"CONFIRM")
    debug_log(f"Sending confirmation HMAC: {confirm.hex()[:16]}...")

    step3 = {
        "action": "akdp_confirm",
        "username": username,
        "client_hmac": to_b64(confirm)
    }
    response = send_request(client, step3, key, None)

    debug_log("AKDP completed successfully!")
    debug_log(f"Master Secret: {master_secret.hex()[:16]}...")
    debug_log(f"Encryption Key: {enc_key.hex()[:16]}...")
    debug_log(f"MAC Key: {mac_key.hex()[:16]}...")
    return master_secret

def login_action(client, username):
    global enc_key, mac_key
    debug_log(f"Starting session for {username}")
    try:
        while True:
            action = input("\nChoose action [deposit/withdraw/balance/exit]: ").strip().lower()
            if action == "exit":
                debug_log("Ending session")
                # Clear session keys
                enc_key = None
                mac_key = None
                # Close connection
                client.close()
                return False  # Signal that connection is closed
                
            if action not in ["deposit", "withdraw", "balance"]:
                print("Invalid option")
                continue

            amount = None
            if action in ["deposit", "withdraw"]:
                try:
                    amount = float(input("Amount: $"))
                    if amount <= 0:
                        print("Amount must be positive")
                        continue
                except ValueError:
                    print("Invalid amount")
                    continue

            request = {
                "action": "deposit" if action == "deposit" else 
                         "withdraw" if action == "withdraw" else 
                         "check_balance",
                "username": username,
                "amount": amount if amount else None
            }

            debug_log(f"Processing {action} request")
            response = send_request(client, request, enc_key, mac_key)
            print("\n" + response.get("message", "No response"))
            
    except Exception as e:
        debug_log(f"Session error: {str(e)}")
        client.close()
        return False

def handle_user_action(client, action):
    global username, enc_key, mac_key
    try:
        input_username = input("Username: ").strip()
        password = getpass.getpass("Password: ")

        request = {
            "action": action,
            "username": input_username,
            "password": password
        }

        response = send_request(client, request, key, None)

        if response.get("status") == "success":
            print("\n" + response.get("message", "Success"))
            if action == "login":
                username = input_username
                if not run_akdp(client, username):
                    print("Security setup failed!")
                    client.close()
                    return None
                # If login_action returns False, connection was closed
                if login_action(client, username) is False:
                    return None
            return client
        else:
            print("\n" + response.get("message", "Action failed"))
            return None
            
    except Exception as e:
        print(f"Connection error: {str(e)}")
        client.close()
        return None

def main():
    print("\n=== Secure ATM Client ===")
    
    while True:
        # Create new connection for each iteration
        client = connect_to_server()
        if not client:
            print("Failed to connect to server")
            continue  # Allow retry instead of exiting

        print("\n1. Register\n2. Login\n3. Exit")
        choice = input("Select option (1-3): ").strip()
        
        if choice == "1":
            if not handle_user_action(client, "register"):
                continue  # Skip to next iteration if failed
        elif choice == "2":
            if not handle_user_action(client, "login"):
                continue  # Skip to next iteration if failed
        elif choice == "3":
            print("Goodbye!")
            if client:
                client.close()
            break
        else:
            print("Invalid choice")
            client.close()
            continue
        
        # If we get here, the connection is already closed by login_action
        # or needs to be closed for register
        if client:
            try:
                client.close()
            except:
                pass

if __name__ == "__main__":
    main()