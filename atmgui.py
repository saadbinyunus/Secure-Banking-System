import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import threading
import socket
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import hmac
import os
import getpass
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



class ATMClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure ATM Client")
        self.root.geometry("600x500")
        
        # Client state
        self.client = None
        self.enc_key = None
        self.mac_key = None
        self.username = None
        self.logged_in = False
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Connection status
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_frame.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(self.status_frame, text="Status: Disconnected")
        self.status_label.pack(side=tk.LEFT)
        
        self.connect_btn = ttk.Button(self.status_frame, text="Connect", command=self.connect_to_server)
        self.connect_btn.pack(side=tk.RIGHT)
        
        # Authentication frame
        self.auth_frame = ttk.LabelFrame(self.main_frame, text="Authentication", padding="10")
        self.auth_frame.pack(fill=tk.X, pady=5)
        
        self.username_label = ttk.Label(self.auth_frame, text="Username:")
        self.username_label.grid(row=0, column=0, sticky=tk.W)
        
        self.username_entry = ttk.Entry(self.auth_frame)
        self.username_entry.grid(row=0, column=1, sticky=tk.EW, padx=5)
        
        self.password_label = ttk.Label(self.auth_frame, text="Password:")
        self.password_label.grid(row=1, column=0, sticky=tk.W)
        
        self.password_entry = ttk.Entry(self.auth_frame, show="*")
        self.password_entry.grid(row=1, column=1, sticky=tk.EW, padx=5)
        
        self.auth_btn_frame = ttk.Frame(self.auth_frame)
        self.auth_btn_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        self.register_btn = ttk.Button(self.auth_btn_frame, text="Register", command=self.register)
        self.register_btn.pack(side=tk.LEFT, padx=5)
        
        self.login_btn = ttk.Button(self.auth_btn_frame, text="Login", command=self.login)
        self.login_btn.pack(side=tk.LEFT, padx=5)
        
        self.logout_btn = ttk.Button(self.auth_btn_frame, text="Logout", command=self.logout, state=tk.DISABLED)
        self.logout_btn.pack(side=tk.LEFT, padx=5)
        
        # ATM Operations frame (only visible when logged in)
        self.operations_frame = ttk.LabelFrame(self.main_frame, text="ATM Operations", padding="10")
        
        self.deposit_btn = ttk.Button(self.operations_frame, text="Deposit", command=self.deposit)
        self.deposit_btn.pack(fill=tk.X, pady=2)
        
        self.withdraw_btn = ttk.Button(self.operations_frame, text="Withdraw", command=self.withdraw)
        self.withdraw_btn.pack(fill=tk.X, pady=2)
        
        self.balance_btn = ttk.Button(self.operations_frame, text="Check Balance", command=self.check_balance)
        self.balance_btn.pack(fill=tk.X, pady=2)
        
        # Log output
        self.log_frame = ttk.LabelFrame(self.main_frame, text="Activity Log", padding="10")
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights
        self.auth_frame.columnconfigure(1, weight=1)
        
    def log_message(self, message):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state=tk.DISABLED)
        self.log_text.see(tk.END)
        
    def connect_to_server(self):
        try:
            self.client = connect_to_server()  # Using your original function
            if self.client:
                self.status_label.config(text="Status: Connected")
                self.connect_btn.config(state=tk.DISABLED)
                self.log_message("Connected to server successfully")
            else:
                self.log_message("Failed to connect to server")
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {str(e)}")
            self.log_message(f"Connection error: {str(e)}")
    
    def register(self):
        if not self.client:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
            
        def do_register():
            try:
                request = {
                    "action": "register",
                    "username": username,
                    "password": password
                }
                
                response = send_request(self.client, request, key, None)  # Using your original function
                
                if response.get("status") == "success":
                    self.log_message(f"Registration successful for {username}")
                    messagebox.showinfo("Success", response.get("message", "Registration successful"))
                else:
                    self.log_message(f"Registration failed: {response.get('message', 'Unknown error')}")
                    messagebox.showerror("Error", response.get("message", "Registration failed"))
                    
            except Exception as e:
                self.log_message(f"Error during registration: {str(e)}")
                messagebox.showerror("Error", f"Registration failed: {str(e)}")
                
        threading.Thread(target=do_register, daemon=True).start()
    
    def login(self):
        if not self.client:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
            
        def do_login():
            try:
                request = {
                    "action": "login",
                    "username": username,
                    "password": password
                }
                
                response = send_request(self.client, request, key, None)  # Using your original function
                
                if response.get("status") == "success":
                    self.username = username
                    self.logged_in = True
                    self.log_message(f"Login successful for {username}")
                    
                    # Run AKDP protocol using your original function
                    if not run_akdp(self.client, username):
                        self.log_message("Security setup failed!")
                        messagebox.showerror("Error", "Security setup failed!")
                        return
                        
                    # Update UI for logged in state
                    self.root.after(0, self.update_logged_in_state)
                    messagebox.showinfo("Success", "Login successful")
                else:
                    self.log_message(f"Login failed: {response.get('message', 'Unknown error')}")
                    messagebox.showerror("Error", response.get("message", "Login failed"))
                    
            except Exception as e:
                self.log_message(f"Error during login: {str(e)}")
                messagebox.showerror("Error", f"Login failed: {str(e)}")
                
        threading.Thread(target=do_login, daemon=True).start()
    
    def logout(self):
        if self.logged_in and self.client:
            try:
                # Step 1: Notify server (sync session termination)
                request = {
                    "action": "logout",
                    "username": self.username
                }
                debug_log("Sending logout request to server")
                response = send_request(self.client, request, self.enc_key, self.mac_key)
                debug_log(f"Server response: {response}")
            except Exception as e:
                debug_log(f"Error during logout: {str(e)}")
                # Proceed to clear local state even if server communication fails

        # Step 2: Clear local state (matches CLI's 'exit')
        self.username = None
        self.logged_in = False
        self.enc_key = None
        self.mac_key = None

        # Step 3: Reset UI
        self.operations_frame.pack_forget()
        self.logout_btn.config(state=tk.DISABLED)
        self.login_btn.config(state=tk.NORMAL)
        self.register_btn.config(state=tk.NORMAL)
        self.log_message("Logged out successfully")

        # Optional: Close the socket (like CLI)
        if self.client:
            self.client.close()
            self.client = None
            self.status_label.config(text="Status: Disconnected")
            self.connect_btn.config(state=tk.NORMAL)
    
    def update_logged_in_state(self):
        self.login_btn.config(state=tk.DISABLED)
        self.register_btn.config(state=tk.DISABLED)
        self.logout_btn.config(state=tk.NORMAL)
        self.operations_frame.pack(fill=tk.X, pady=5)
        self.log_message(f"Welcome, {self.username}! You can now perform transactions.")
    
    def deposit(self):
        amount = simpledialog.askfloat("Deposit", "Enter amount to deposit:", minvalue=0.01)
        if amount is None:  # User cancelled
            return
            
        def do_deposit():
            try:
                request = {
                    "action": "deposit",
                    "username": self.username,
                    "amount": amount
                }
                
                response = send_request(self.client, request, enc_key, mac_key)  # Using your original function
                self.log_message(response.get("message", "Deposit completed"))
                messagebox.showinfo("Deposit", response.get("message", "Deposit completed"))
                
            except Exception as e:
                self.log_message(f"Error during deposit: {str(e)}")
                messagebox.showerror("Error", f"Deposit failed: {str(e)}")
                
        threading.Thread(target=do_deposit, daemon=True).start()
    
    def withdraw(self):
        amount = simpledialog.askfloat("Withdraw", "Enter amount to withdraw:", minvalue=0.01)
        if amount is None:  # User cancelled
            return
            
        def do_withdraw():
            try:
                request = {
                    "action": "withdraw",
                    "username": self.username,
                    "amount": amount
                }
                
                response = send_request(self.client, request, enc_key, mac_key)  # Using your original function
                self.log_message(response.get("message", "Withdrawal completed"))
                messagebox.showinfo("Withdraw", response.get("message", "Withdrawal completed"))
                
            except Exception as e:
                self.log_message(f"Error during withdrawal: {str(e)}")
                messagebox.showerror("Error", f"Withdrawal failed: {str(e)}")
                
        threading.Thread(target=do_withdraw, daemon=True).start()
    
    def check_balance(self):
        def do_check_balance():
            try:
                request = {
                    "action": "check_balance",
                    "username": self.username
                }
                
                response = send_request(self.client, request, enc_key, mac_key)  # Using your original function
                self.log_message(response.get("message", "Balance checked"))
                messagebox.showinfo("Balance", response.get("message", "Balance information"))
                
            except Exception as e:
                self.log_message(f"Error checking balance: {str(e)}")
                messagebox.showerror("Error", f"Balance check failed: {str(e)}")
                
        threading.Thread(target=do_check_balance, daemon=True).start()

def main():
    # Original main function replaced with GUI version
    root = tk.Tk()
    app = ATMClientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()


