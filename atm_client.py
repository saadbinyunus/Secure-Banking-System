import socket
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64
import hmac
import os

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
    
    if len(iv) != 16:
        raise ValueError("Invalid IV length. Expected 16 bytes.")
    
    cipher = AES.new(temp_key, AES.MODE_CBC, iv)
    message = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return message

def connect_to_server():
    host = 'localhost'
    port = 5555

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(5)  # Set a timeout for the connection attempt
        client.connect((host, port))
        return client
    except ConnectionRefusedError:
        print("Connection to server failed. Please ensure the server is running.")
        return None

def send_request(client, request, key):
    try:
        encrypted_request = encrypt(json.dumps(request), key)
        client.send(encrypted_request.encode())
        
        # Receive the encrypted response
        response = client.recv(1024).decode()
        print(f"From server: {repr(response)}")

        if not response:
            raise ValueError("Empty response from server.")

        decrypted_response = decrypt(response, key)
        return json.loads(decrypted_response)
    except (socket.error, json.JSONDecodeError, ValueError) as e:
        print(f"Error communicating with server: {e}")
        return {"status": "error", "message": "Server communication error."}

def login_action(client, username):
    while True:
        action = input("Choose action: [deposit/withdraw/check_balance/exit]: ").strip().lower()
        if action == "exit":
            print("Logging out. Goodbye!")
            break
        if action not in ["deposit", "withdraw", "check_balance"]:
            print("Invalid option.")
            continue

        amount = None
        if action in["deposit", "withdraw"]:
            try:
                amount = float(input("Enter amount: ").strip())
                if amount <= 0:
                    print("Invalid amount. Please enter a number.")
                    continue
            except ValueError:
                print("Invalid amount. Please enter a valid number.")
                continue

        request = {
            "action": action,
            "username": username,
            "amount": amount
        }

        response = send_request(client, request, key)
        print(response.get('message', 'No message from server.'))
        

def handle_user_action(client, action):
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    request = {
        "action": action,
        "username": username,
        "password": password
    }

    response = send_request(client, request, key)

    if response.get('status') == "success":
        print(response.get("message", "Success."))
        if action == "register":
            print("You can now log in with your credentials.")
            client.close()
            client = connect_to_server()
            if not client:
                print("Unable to connect to server. Exiting.")
                return None
        elif action == "login":
            print("Login successful.")
            run_akdp(client, username)
            print("Welcome to your account!")
            login_action(client, username)
    return client

def run_akdp(client, username):
    print("\n[AKDP] Initiating authenticated key distribution...")
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
    print(f"[CLIENT] nonce1: {to_b64(nonce1)}")
    print(f"[SERVER] nonce2: {response['nonce2']}")
    print(f"[SERVER] server_hmac: {response['server_hmac']}")

    if server_hmac != expected_hmac:
        print("[ERROR] Server failed authentication.")
        return None

    master_secret = hmac_sha256(psk, nonce1 + nonce2)
    confirm = hmac_sha256(master_secret, b"CONFIRM")

    #confirm to server
    step3 = {
        "action": "akdp_confirm",
        "username": username,
        "client_hmac": to_b64(confirm)
    }
    response = send_request(client, step3, key)

    print("AKDP complete. Master Secret (hex):", master_secret.hex())
    return master_secret


def main():
    print("Welcome to Secure ATM")

    client = connect_to_server()
    if not client:
        print("Unable to connect to server. Exiting.")
        exit()    

    while True:
        action = input("Choose action: [register/login/exit]: ").strip().lower()
        if action == "exit":
            print("Exiting the ATM. Goodbye!")
            client.close()
            break
        if action not in ["register", "login"]:
            print("Invalid option.")
            continue

        client = handle_user_action(client, action)
        if client is None:
            break

if __name__ == "__main__":
    main()
