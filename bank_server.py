import socket
import threading
import json
import logging
import bcrypt
from cryptography.fernet import Fernet
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import hmac
import os

bank_server_key = "key"
# cipher = Fernet(bank_server_key)
psk = b"key"
handshake_state = {}

def hmac_sha256(key: bytes, msg: bytes):
    return hmac.new(key, msg, hashlib.sha256).digest()

def generate_nonce():
    return os.urandom(16)

def to_b64(data):
    return base64.b64encode(data).decode()

def from_b64(data):
    return base64.b64decode(data)

customers = {
    "timmy ngo": {
        "password": bcrypt.hashpw("123".encode(), bcrypt.gensalt()).decode(),
        "balance": 1000,
        "transactions": ["deposit 100", "withdraw 20"]
    }
} # Simulated in-memory database for user accounts

lock = threading.Lock()

# Audit log configuration
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(message)s"
)

# Security protocols
def encrypt(message):
    if not isinstance(message, str):
        message = json.dumps(message)

    print(f"Encrypting message: {repr(message)}")
    key = hashlib.sha256(bank_server_key.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv_b64 = base64.b64encode(cipher.iv).decode('utf-8')
    ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')

    encrypted_message = f"{iv_b64}:{ct_b64}"
    print(f"Encrypted message: {repr(encrypted_message)}")
    return encrypted_message


def decrypt(encrypted_message):
    try:
        print(f"Encrypted message: {repr(encrypted_message)}")
        iv_b64, ct_b64 = encrypted_message.split(":")
        iv = base64.b64decode(iv_b64)
        ct = base64.b64decode(ct_b64)

        key = hashlib.sha256(bank_server_key.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

        print(f"Decrypted message: {repr(decrypted_message)}")
        return decrypted_message
    except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")
        return ""
    

def log_audit(customer_id, action):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{customer_id}, {action}, {timestamp}"
    encrypted_log = encrypt(log_entry)

    with open("audit.log", "a") as log_file:
        log_file.write(encrypted_log + "\n")

def hash(message):
    return bcrypt.hashpw(message.encode(), bcrypt.gensalt()).decode()

def verify_hash(message, hashed):
    return bcrypt.checkpw(message.encode(), hashed.encode())

def handle_client(conn, addr):
    logging.info(f"New connection from {addr}")
    print(f"[NEW CONNECTION] {addr} connected.")

    try:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                print(f"[DISCONNECTED] {addr} disconnected.")
                break

            print(f"[RECEIVED] {repr(data)} from {addr}")

            # Decrypt data to parse the JSON
            decrypted_data = decrypt(data)
            if not decrypted_data:
                print(f"[ERROR] Failed to decrypt data from {addr}.")
                conn.send(encrypt(json.dumps({"status": "fail", "message": "Decryption failed."})).encode())
                return
            
            print(f"[DECRYPTED] {repr(decrypted_data)} from {addr}")

            # Parse the incoming JSON data
            request = json.loads(decrypted_data)
            action = request.get("action")
            username = request.get("username")
            password = request.get("password")

            response = handle_action(action, username, password, request)
            response_message = json.dumps(response)
            encrypted_response = encrypt(response_message)

            print(f"[SENDING] {repr(encrypted_response)} to {addr}")

            conn.send(encrypted_response.encode())
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()

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
    elif action == "akdp_step1":
        nonce1 = from_b64(request["nonce1"])
        nonce2 = generate_nonce()
        handshake_state[username] = {"nonce1": nonce1, "nonce2": nonce2}
        server_hmac = hmac_sha256(psk, nonce1 + nonce2 + b"SERVER")

        print(f"[AKDP] Step 1 from {username}")
        return {
            "action": "akdp_step2",
            "nonce2": to_b64(nonce2),
            "server_hmac": to_b64(server_hmac)
        }

    elif action == "akdp_confirm":
        client_hmac = from_b64(request["client_hmac"])
        state = handshake_state.get(username)
        if not state:
            return {"status": "fail", "message": "Missing handshake"}

        nonce1, nonce2 = state["nonce1"], state["nonce2"]
        master_secret = hmac_sha256(psk, nonce1 + nonce2)
        expected = hmac_sha256(master_secret, b"CONFIRM")

        if client_hmac != expected:
            return {"status": "fail", "message": "Client verification failed"}

        print(f"[AKDP] Key exchange complete for {username}")
        return {"status": "success", "message": "Key exchange complete"}

    else:
        logging.error(f"Unknown action: {action}")
        return {"status": "fail", "message": "Unknown action."}

def handle_register(username, password):
    with lock:
        logging.info(f"Registration attempt for user: {username}")
        if username in customers:
            logging.warning(f"Registration failed for user: {username} - Username already exists.")
            return {"status": "fail", "message": "Username already exists."}
        customers[username] = {
            "password": hash(password),
            "balance": 0,
            "transactions": []
        }
        logging.info(f"Username {username} registered successfully.")
        return {"status": "success", "message": "Registration successful."}

def handle_login(username, password):
    with lock:
        logging.info(f"Login attempt for user: {username}")
        if username in customers and verify_hash(password, customers[username]["password"]):
            logging.info(f"User {username} logged in successfully.")
            return {"status": "success", "message": "Login successful."}
        logging.warning(f"Failed login attempt for user: {username}")
        return {"status": "fail", "message": "Invalid credentials."}

def handle_deposit(username, amount):
    if not isinstance(amount, (int, float)) or amount <= 0:
        return {"status": "fail", "message": "Invalid deposit amount."}
    with lock:
        if username in customers:
            customers[username]["balance"] += amount
            customers[username]["transactions"].append(f"deposit {amount}")
            log_audit(username, f"deposit {amount}")
            return {"status": "success", "message": f"Deposited ${amount}. New balance: ${customers[username]['balance']}"}
    return {"status": "fail", "message": "Username not found."}

def handle_withdraw(username, amount):
    if not isinstance(amount, (int, float)) or amount <= 0:
        return {"status": "fail", "message": "Invalid withdrawal amount."}
    with lock:    
        if username in customers and customers[username]["balance"] >= amount:
            customers[username]["balance"] -= amount
            customers[username]["transactions"].append(f"withdraw {amount}")
            log_audit(username, f"withdraw {amount}")
            return {"status": "success", "message": f"Withdrew ${amount}. New balance: ${customers[username]['balance']}"}
    return {"status": "fail", "message": "Invalid withdrawal request."}

def handle_check_balance(username):
    with lock:
        if username in customers:
            balance = customers[username]["balance"]
            log_audit(username, "Balance Inquiry")
            return {"status": "success", "message": f"Your balance is ${balance}."}
    return {"status": "fail", "message": "User not found."}

def start_server():
    host = 'localhost'
    port = 5555

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[LISTENING] Server is listening on {host}:{port}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    start_server()
