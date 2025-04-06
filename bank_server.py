import socket
import threading
import json
import logging
import bcrypt # type: ignore
from cryptography.fernet import Fernet # type: ignore
from datetime import datetime
from Crypto.Cipher import AES # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore
import base64
import hashlib
import hmac
import os
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import sys

bank_server_key = "key"
psk = b"key"
handshake_state = {}
<<<<<<< Updated upstream
=======


# Debug settings
DEBUG = True

def debug_log(message):
    if DEBUG:
        print(f"[DEBUG] {message}")
>>>>>>> Stashed changes

def hmac_sha256(key: bytes, msg: bytes):
    return hmac.new(key, msg, hashlib.sha256).digest()

def generate_nonce():
    return os.urandom(16)

def to_b64(data):
    return base64.b64encode(data).decode()

def from_b64(data):
    return base64.b64decode(data)

<<<<<<< Updated upstream
=======
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
>>>>>>> Stashed changes
customers = {
    "johnsmith416": {
        "password": bcrypt.hashpw("123".encode(), bcrypt.gensalt()).decode(),
        "balance": 1000,
        "transactions": ["deposit 100", "withdraw 20"]
    }
} # Simulated in-memory database for user accounts

lock = threading.Lock()
active_users = set() # Set to keep track of active users

# Audit log configuration
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(message)s"
)

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
    # print(f"Encrypted message: {repr(encrypted_message)}")
    return encrypted_message


def decrypt(encrypted_message):
    try:
        # print(f"Encrypted message: {repr(encrypted_message)}")
        iv_b64, ct_b64 = encrypted_message.split(":")
        iv = base64.b64decode(iv_b64)
        ct = base64.b64decode(ct_b64)

        key = hashlib.sha256(bank_server_key.encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

        # print(f"Decrypted message: {repr(decrypted_message)}")
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
    # logging.info(f"New connection from {addr}") type: ignore
    # print(f"[NEW CONNECTION] {addr} connected.")

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
        with lock:
            if 'username' in locals() and username in active_users:
                active_users.remove(username)
                print(f"[LOGOUT] {username} logged out.")
        conn.close()

def handle_action(action, username, password, request):
    if action == "register":
        return register(username, password)
    elif action == "login":
        return login(username, password)
    elif action == "deposit":
        return deposit(username, request.get("amount"))
    elif action == "withdraw":
        return withdraw(username, request.get("amount"))
    elif action == "check_balance":
<<<<<<< Updated upstream
        return check_balance(username)
=======
        return handle_check_balance(username)
    elif action == "logout":
        return logout(username)
>>>>>>> Stashed changes
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
        root_secret = hmac_sha256(psk, nonce1 + nonce2)
        expected = hmac_sha256(root_secret, b"CONFIRM")

        if client_hmac != expected:
            return {"status": "fail", "message": "Client verification failed"}

        print(f"[AKDP] Key exchange complete for {username}")
        return {"status": "success", "message": "Key exchange complete"}
    elif action == "logout":
        return logout(username)
    else:
        logging.error(f"Unknown action: {action}")
        return {"status": "fail", "message": "Unknown action."}

def register(username, password):
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

def login(username, password):
    with lock:
<<<<<<< Updated upstream
        logging.info(f"Login attempt for user: {username}")
        if username in active_users:
            logging.warning(f"User {username} already logged in.")
            return {"status": "fail", "message": "INVALID."}
=======
        debug_log(f"Login attempt for {username}")
        if username in active_users:
                    logging.warning(f"User {username} already logged in.")
                    return {"status": "fail", "message": "INVALID."}

        if username in customers and bcrypt.checkpw(password.encode(), customers[username]["password"].encode()):
            log_audit(username, "logged in")
            return {"status": "success", "message": "Login successful"}
        return {"status": "fail", "message": "Invalid credentials"}
>>>>>>> Stashed changes

        if username in customers and verify_hash(password, customers[username]["password"]):
            logging.info(f"User {username} logged in successfully.")
            return {"status": "success", "message": "Login successful."}
        logging.warning(f"Failed login attempt for user: {username}")
        return {"status": "fail", "message": "Invalid credentials."}

def deposit(username, amount):
    if not isinstance(amount, (int, float)) or amount <= 0:
        return {"status": "fail", "message": "Invalid deposit amount."}
    with lock:
        if username in customers:
            customers[username]["balance"] += amount
            customers[username]["transactions"].append(f"deposit {amount}")
            log_audit(username, f"deposit {amount}")
            return {"status": "success", "message": f"Deposited ${amount}. New balance: ${customers[username]['balance']}"}
    return {"status": "fail", "message": "Username not found."}

def withdraw(username, amount):
    if not isinstance(amount, (int, float)) or amount <= 0:
        return {"status": "fail", "message": "Invalid withdrawal amount."}
    with lock:    
        if username in customers and customers[username]["balance"] >= amount:
            customers[username]["balance"] -= amount
            customers[username]["transactions"].append(f"withdraw {amount}")
            log_audit(username, f"withdraw {amount}")
            return {"status": "success", "message": f"Withdrew ${amount}. New balance: ${customers[username]['balance']}"}
    return {"status": "fail", "message": "Invalid withdrawal request."}

def check_balance(username):
    with lock:
        if username in customers:
            balance = customers[username]["balance"]
            log_audit(username, "Balance Inquiry")
            return {"status": "success", "message": f"Your balance is ${balance}."}
    return {"status": "fail", "message": "User not found."}

def logout(username):
    with lock:
        if username in active_users:
            active_users.remove(username)
            logging.info(f"User {username} logged out.")
            return {"status": "success", "message": "Logged out successfully."}
        else:
            logging.warning(f"Logout attempt for user {username} who is not logged in.")
            return {"status": "fail", "message": "User not logged in."}

def start_server():
    host = 'localhost'
    port = 1

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[LISTENING] Server is listening on {host}:{port}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        # print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

""" 
GUI STARTS HERE ---------------------------------------
"""
class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Banking System - Bank Server")
        self.root.geometry("1000x700")

        # Terminal
        self.output_label = tk.Label(root, text="Terminal", font=("Arial", 12, "bold"))
        self.output_area = ScrolledText(root, height=15, bg="black", fg="white")
        self.output_label.pack()
        self.output_area.pack(fill="both", expand=True)

        # Audit log
        self.audit_label = tk.Label(root, text="Audit Log", font=("Arial", 12, "bold"))
        self.audit_area = ScrolledText(root, height=15, bg="black", fg="white")
        self.audit_label.pack()
        self.audit_area.pack(fill="both", expand=True)

        # Redirect stdout
        sys.stdout = self
        self.refresh_audit_log()

    def write(self, message):
        self.output_area.insert(tk.END, message)
        self.output_area.see(tk.END)

    def refresh_audit_log(self):
        try:
            current_pos = self.audit_area.yview() # Get scroll position
            at_bottom = current_pos[1] == 1  # Check if scrolled to bottom

            with open("audit.log", "r") as log_file:
                log_content = log_file.read()

            self.audit_area.delete(1.0, tk.END)
            self.audit_area.insert(tk.END, log_content)

            # Stay at bottom
            if at_bottom:
                self.audit_area.see(tk.END)
        except FileNotFoundError:
            self.audit_area.insert(tk.END, "No audit.log file found.\n")

        self.root.after(2000, self.refresh_audit_log)

if __name__ == "__main__":
    root = tk.Tk()
    gui = GUI(root)
    threading.Thread(target=start_server, daemon=True).start()
    root.mainloop()
