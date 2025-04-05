# atm_client.py

import socket
import json
from Crypto.Cipher import AES # type: ignore
from Crypto.Util.Padding import pad, unpad # type: ignore
import hashlib
import base64
import hmac
import os
import tkinter as tk
from tkinter import messagebox, simpledialog

key = "key"
psk = b"key"

def hmac_sha256(key: bytes, msg: bytes):
    return hmac.new(key, msg, hashlib.sha256).digest()

def generate_nonce():
    return os.urandom(16)

def to_b64(data):
    return base64.b64encode(data).decode()

def from_b64(data):
    return base64.b64decode(data)

def encrypt(message, key):
    print(f"Encrypting message: {repr(message)}")
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ":" + ct

def decrypt(encrypted_message, key):
    temp_key = hashlib.sha256(key.encode()).digest()

    print(f"Decrypting message: {repr(encrypted_message)}")
    try:
        iv_b64, ct_b64 = encrypted_message.split(":")
        iv = base64.b64decode(iv_b64)
        ct = base64.b64decode(ct_b64)
    except ValueError:
        raise ValueError("Invalid encrypted message format. Expected 'iv:ct' format.")

    cipher = AES.new(temp_key, AES.MODE_CBC, iv)
    message = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return message

def connect_to_server():
    host = 'localhost'
    port = 1
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)
        client.connect((host, port))
        return client
    except ConnectionRefusedError:
        print("Connection refused. Is the server running?")
        return None

def send_request(client, request, key):
    try:
        encrypted_request = encrypt(json.dumps(request), key)
        client.send(encrypted_request.encode())

        response = client.recv(1024).decode()
        # print(f"From server: {repr(response)}")
        if not response:
            raise ValueError("Empty response from server.")
        decrypted_response = decrypt(response, key)
        return json.loads(decrypted_response)
    except Exception:
        print("Error communicating with server.")
        return {"status": "error", "message": "Server communication error."}

def run_akdp(client, username):
    nonce1 = generate_nonce()
    step1 = {
        "action": "akdp_step1",
        "username": username,
        "nonce1": to_b64(nonce1)
    }
    response = send_request(client, step1, key)

    nonce2 = from_b64(response["nonce2"])
    server_hmac = from_b64(response["server_hmac"])

    expected_hmac = hmac_sha256(psk, nonce1 + nonce2 + b"SERVER")
    if server_hmac != expected_hmac:
        return None

    master_secret = hmac_sha256(psk, nonce1 + nonce2)
    confirm = hmac_sha256(master_secret, b"CONFIRM")

    step3 = {
        "action": "akdp_confirm",
        "username": username,
        "client_hmac": to_b64(confirm)
    }
    send_request(client, step3, key)
    return master_secret

def login(client, username, password):
    request = {
        "action": "login",
        "username": username,
        "password": password
    }
    response = send_request(client, request, key)
    return response

def register(client, username, password):
    request = {
        "action": "register",
        "username": username,
        "password": password
    }
    response = send_request(client, request, key)
    return response

def handle_action(client, username, action, amount=None):
    request = {
        "action": action,
        "username": username,
        "amount": amount
    }
    return send_request(client, request, key)

""" 
GUI STARTS HERE ---------------------------------------
"""
class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Banking System - ATM Client")
        self.root.geometry("500x500")
        self.client = connect_to_server()
        if not self.client:
            messagebox.showerror("Connection Error", "Unable to connect to the server.")
            root.destroy()
            return

        self.username = None
        self.main_screen()

    def main_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text="ATM", font=("Arial", 16)).pack(pady=10)
        tk.Button(self.root, text="Register", width=20, command=self.register_screen).pack(pady=5)
        tk.Button(self.root, text="Login", width=20, command=self.login_screen).pack(pady=5)
        tk.Button(self.root, text="Exit", width=20, command=self.root.quit).pack(pady=5)

    def register_screen(self):
        def on_submit():
            entered_username = username_entry.get()
            entered_password = password_entry.get()
            if entered_username and entered_password:
                top.destroy()
                response = register(self.client, entered_username, entered_password)
                messagebox.showinfo("Registration", response.get("message", "No response"))
                self.client = connect_to_server()
            else:
                messagebox.showerror("Registration Failed", "Need username and password.")

        top = tk.Toplevel(self.root)
        top.title("Register")
        top.grab_set()

        tk.Label(top, text="Username:").grid(row=0, column=0, padx=10, pady=5)
        username_entry = tk.Entry(top)
        username_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(top, text="Password:").grid(row=1, column=0, padx=10, pady=5)
        password_entry = tk.Entry(top, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=5)

        submit_btn = tk.Button(top, text="Register", command=on_submit)
        submit_btn.grid(row=2, column=0, columnspan=2, pady=10)

        username_entry.focus_set()

    def login_screen(self):
        def on_submit():
            entered_username = username_entry.get()
            entered_password = password_entry.get()
            if entered_username and entered_password:
                top.destroy()
                response = login(self.client, entered_username, entered_password)
                if response.get("status") == "success":
                    self.username = entered_username
                    run_akdp(self.client, entered_username)
                    self.dashboard()
                else:
                    messagebox.showerror("Login Failed", response.get("message"))
            else:
                messagebox.showerror("Error", "Both fields are required.")

        top = tk.Toplevel(self.root)
        top.title("Login")
        top.grab_set()

        tk.Label(top, text="Username:").grid(row=0, column=0, padx=10, pady=5)
        username_entry = tk.Entry(top)
        username_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(top, text="Password:").grid(row=1, column=0, padx=10, pady=5)
        password_entry = tk.Entry(top, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=5)

        submit_btn = tk.Button(top, text="Login", command=on_submit)
        submit_btn.grid(row=2, column=0, columnspan=2, pady=10)

        username_entry.focus_set()

    def dashboard(self):
        for widget in self.root.winfo_children():
            widget.destroy()

        tk.Label(self.root, text=f"Welcome {self.username}", font=("Arial", 14)).pack(pady=10)
        tk.Button(self.root, text="Deposit", width=20, command=lambda: self.action("deposit")).pack(pady=5)
        tk.Button(self.root, text="Withdraw", width=20, command=lambda: self.action("withdraw")).pack(pady=5)
        tk.Button(self.root, text="Check Balance", width=20, command=lambda: self.action("check_balance")).pack(pady=5)
        tk.Button(self.root, text="Logout", width=20, command=self.logout).pack(pady=5)

    def action(self, action):
        amount = None
        if action in ["deposit", "withdraw"]:
            try:
                amount = float(simpledialog.askstring(action.title(), "Enter amount:"))
            except (TypeError, ValueError):
                messagebox.showerror("Invalid Input", "Please enter a valid number.")
                return

        response = handle_action(self.client, self.username, action, amount)
        messagebox.showinfo(action.title(), response.get("message", "No response"))

    def logout(self):
        self.username = None
        self.client = connect_to_server()
        self.main_screen()

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("300x300")
    app = GUI(root)
    root.mainloop()
