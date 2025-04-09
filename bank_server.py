# Bank Server with Secure Key Exchange and Audit Logging

import socket
import threading
import json
import logging
import bcrypt
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import hmac
import os

# Server configuration
bank_server_key = "secure_bank_key_123!"
psk = b"pre_shared_key_456$"
handshake_state = {}

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

def logout(username):
    with lock:
        if username in active_users:
            active_users.remove(username)
            logging.info(f"User {username} logged out.")
            return {"status": "success", "message": "Logged out successfully."}
        else:
            logging.warning(f"Logout attempt for user {username} who is not logged in.")
            return {"status": "fail", "message": "User not logged in."}

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

# Simulated database
customers = {
    "alice": {
        "password": bcrypt.hashpw("alice123".encode(), bcrypt.gensalt()).decode(),
        "balance": 1000,
        "transactions": []
    },
    "bob": {
        "password": bcrypt.hashpw("bob456".encode(), bcrypt.gensalt()).decode(),
        "balance": 500,
        "transactions": []
    }
}

lock = threading.Lock()
active_users = set() # Set to keep track of active users

# Replace the logging.basicConfig with:
if not os.path.exists("audit.log"):
    with open("audit.log", "w") as f:
        f.write("")  # Initialize empty encrypted log file

if not os.path.exists("audit_decrypt.log"):
    with open("audit_decrypt.log", "w") as f:
        f.write("Customer_ID, Action, Timestamp\n")  # Plaintext header

def log_audit(customer_id, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{customer_id}, {action}, {timestamp}"
    
    # Get appropriate keys
    if customer_id in handshake_state and handshake_state[customer_id].get("authenticated"):
        enc_key = handshake_state[customer_id]["enc_key"]
        mac_key = handshake_state[customer_id]["mac_key"]
        debug_log(f"Using derived keys for {customer_id}")
    else:
        enc_key = hashlib.sha256(bank_server_key.encode()).digest()
        mac_key = hashlib.sha256(bank_server_key.encode()).digest()
        debug_log("Using pre-shared key for audit")

    encrypted_log = encrypt_and_sign(log_entry, enc_key, mac_key)
    debug_log(f"Audit entry encrypted: {encrypted_log[:100]}...")

    with open("audit.log", "a") as encrypted_file:
        encrypted_file.write(encrypted_log + "\n")
    
    # Write to decrypted log
    with open("audit_decrypt.log", "a") as decrypted_file:
        decrypted_file.write(log_entry + "\n")

def handle_action(action, username, password, request):
    if action == "register":
        return handle_register(username, password)
    elif action == "login":
        return handle_login(username, password)
    elif action == "deposit":
        return handle_deposit(username, request.get("amount"))
    elif action == "withdraw":
        return handle_withdraw(username, request.get("amount"))
    elif action == "check_balance":
        return handle_check_balance(username)
    elif action == "logout":
        return logout(username)
    elif action == "akdp_step1":
        nonce1 = from_b64(request["nonce1"])
        nonce2 = generate_nonce()
        handshake_state[username] = {
            "nonce1": nonce1, 
            "nonce2": nonce2,
            "conn": request.get("conn")
        }
        server_hmac = hmac_sha256(psk, nonce1 + nonce2 + b"SERVER")

        debug_log(f"AKDP Step 1 from {username}")
        return {
            "action": "akdp_step2",
            "nonce2": to_b64(nonce2),
            "server_hmac": to_b64(server_hmac)
        }
    elif action == "akdp_confirm":
        debug_log(f"Received AKDP confirmation from {username}")
        client_hmac = from_b64(request["client_hmac"])
        state = handshake_state.get(username)
        if not state:
            debug_log("No handshake state for user")
            return {"status": "fail", "message": "Missing handshake"}

        nonce1, nonce2 = state["nonce1"], state["nonce2"]
        master_secret = hmac_sha256(psk, nonce1 + nonce2)
        expected = hmac_sha256(master_secret, b"CONFIRM")
        debug_log(f"Client HMAC: {client_hmac.hex()[:16]}..., Expected: {expected.hex()[:16]}...")

        if not hmac.compare_digest(client_hmac, expected):
            debug_log("Client HMAC verification failed!")
            return {"status": "fail", "message": "Client verification failed"}

        enc_key, mac_key = derive_keys(master_secret)
        state.update({
            "enc_key": enc_key,
            "mac_key": mac_key,
            "authenticated": True
        })
        debug_log(f"AKDP complete for {username}")
        return {"status": "success", "message": "Key exchange complete"}
    else:
        return {"status": "fail", "message": "Unknown action."}

def handle_register(username, password):
    with lock:
        debug_log(f"Registration attempt for {username}")
        if username in customers:
            return {"status": "fail", "message": "Username exists"}
        customers[username] = {
            "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "balance": 0,
            "transactions": []
        }
        log_audit(username, "registered")
        return {"status": "success", "message": "Registration successful"}

def handle_login(username, password):
    with lock:
        debug_log(f"Login attempt for {username}")
        if username in active_users:
                    logging.warning(f"User {username} already logged in.")
                    return {"status": "fail", "message": "User already logged in on another instance of the ATM."}

        if username in customers and bcrypt.checkpw(password.encode(), customers[username]["password"].encode()):
            active_users.add(username)
            log_audit(username, "logged in")
            return {"status": "success", "message": "Login successful"}
        return {"status": "fail", "message": "Invalid credentials"}

def handle_deposit(username, amount):
    if not isinstance(amount, (int, float)) or amount <= 0:
        log_audit(username, "DEPOSIT_FAILED, Invalid amount")
        return {"status": "fail", "message": "Invalid amount"}
    
    with lock:
        if username in customers:
            customers[username]["balance"] += amount
            customers[username]["transactions"].append(f"deposit {amount}")
            log_audit(username, f"DEPOSIT_SUCCESS, {amount}, NewBalance:{customers[username]['balance']}")
            return {"status": "success", "message": f"Deposited ${amount}. New balance: ${customers[username]['balance']}"}
    
    log_audit(username, "DEPOSIT_FAILED, User not found")
    return {"status": "fail", "message": "User not found"}

def handle_withdraw(username, amount):
    if not isinstance(amount, (int, float)) or amount <= 0:
        return {"status": "fail", "message": "Invalid amount"}
    with lock:
        if username in customers and customers[username]["balance"] >= amount:
            customers[username]["balance"] -= amount
            customers[username]["transactions"].append(f"withdraw {amount}")
            log_audit(username, f"withdraw {amount}")
            return {"status": "success", "message": f"Withdrew ${amount}. New balance: ${customers[username]['balance']}"}
    return {"status": "fail", "message": "Invalid withdrawal"}

def handle_check_balance(username):
    with lock:
        if username in customers:
            balance = customers[username]["balance"]
            log_audit(username, "balance inquiry")
            return {"status": "success", "message": f"Balance: ${balance}"}
    return {"status": "fail", "message": "User not found"}

def handle_client(conn, addr):
    debug_log(f"New connection from {addr}")
    log_audit("SYSTEM", f"CONNECTION_OPEN, {addr[0]}:{addr[1]}")
    username = None
    
    try:
        # Set timeout to prevent hanging connections
        #conn.settimeout(30)  # 30 seconds timeout
        
        while True:
            try:
                data = conn.recv(1024)
                if not data:
                    debug_log(f"{addr} disconnected gracefully")
                    break

                debug_log(f"Received raw data: {data[:100]}...")

                # Find username for this connection
                username = None
                for user, state in handshake_state.items():
                    if state.get("conn") == conn:
                        username = user
                        break

                # Get appropriate keys
                if username and username in handshake_state and handshake_state[username].get("authenticated"):
                    enc_key = handshake_state[username]["enc_key"]
                    mac_key = handshake_state[username]["mac_key"]
                    debug_log(f"Using session keys for {username}")
                else:
                    enc_key = hashlib.sha256(bank_server_key.encode()).digest()
                    mac_key = hashlib.sha256(bank_server_key.encode()).digest()
                    debug_log("Using pre-shared key")

                decrypted_data = verify_and_decrypt(data.decode(), enc_key, mac_key)
                if not decrypted_data:
                    log_audit("SECURITY", f"MAC_VERIFICATION_FAILED, {addr[0]}:{addr[1]}")
                    debug_log("Security violation - closing connection")
                    raise SecurityException("MAC verification failed")

                try:
                    request = json.loads(decrypted_data)
                    request["conn"] = conn  # Store connection reference
                    username = request.get("username")
                    action = request.get("action")
                    password = request.get("password")

                    if not all([action, username]):
                        raise ValueError("Missing required fields")

                    response = handle_action(action, username, password, request)
                    response_message = json.dumps(response)
                    secured_response = encrypt_and_sign(response_message, enc_key, mac_key)
                    conn.sendall(secured_response.encode())

                except json.JSONDecodeError:
                    log_audit("SECURITY", f"INVALID_JSON, {addr[0]}:{addr[1]}")
                    raise SecurityException("Invalid JSON format")
                except KeyError as e:
                    log_audit("SECURITY", f"MISSING_FIELD, {addr[0]}:{addr[1]}, {str(e)}")
                    raise SecurityException(f"Missing required field: {str(e)}")

            except socket.timeout:
                debug_log(f"Connection timeout with {addr}")
                log_audit("SYSTEM", f"CONNECTION_TIMEOUT, {addr[0]}:{addr[1]}")
                break
            except ConnectionResetError:
                debug_log(f"Connection reset by {addr}")
                break
            except SecurityException as e:
                debug_log(f"Security exception: {str(e)}")
                break

    except Exception as e:
        log_audit("SYSTEM", f"CONNECTION_ERROR, {addr[0]}:{addr[1]}, {str(e)}")
        debug_log(f"Error handling client: {str(e)}")
    finally:
        try:
            # Clean up connection state
            if username and username in handshake_state:
                debug_log(f"Cleaning up handshake state for {username}")
                del handshake_state[username]
            
            # Graceful connection shutdown
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Connection already closed
            
            conn.close()
            log_audit("SYSTEM", f"CONNECTION_CLOSE, {addr[0]}:{addr[1]}")
            debug_log(f"Connection with {addr} closed")
        except Exception as e:
            debug_log(f"Error during cleanup: {str(e)}")

class SecurityException(Exception):
    """Custom exception for security violations"""
    pass

def start_server():
    host = 'localhost'
    port = 5555

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[SERVER] Listening on {host}:{port}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        debug_log(f"Active connections: {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()
