import socket
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import base64

key = "client_key"

def encrypt(message, key):
    key = hashlib.sha256(key.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt(encrypted_message, key):
    temp_key = hashlib.sha256(key.encode()).digest()
    iv = base64.b64decode(encrypted_message[:24])
    ct = base64.b64decode(encrypted_message[24:])
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
        decrypted_response = decrypt(response, key)
        return json.loads(decrypted_response)
    except (socket.error, json.JSONDecodeError):
        print("Error communicating with server")
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
            print("Welcome to your account!")
            login_action(client, username)
    return client


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
