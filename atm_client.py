import socket
import json

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

def send_request(request):
    client = connect_to_server()
    if not client:
        return {"status": "error", "message": "Unable to connect to server."}
    
    try:
        client.send(json.dumps(request).encode())
        response = client.recv(1024).decode()
        return json.loads(response)
    except (socket.error, json.JSONDecodeError):
        print("Error communicating with server")
        return {"status": "error", "message": "Server communication error."}
    finally:
        client.close()

def login_action(username):
    while True:
        action = input("Choose action: [deposit/withdraw/check_balance/exit]: ").strip().lower()
        if action == "exit":
            print("Logging out. Goodbye!")
            break
        if action not in ["deposit", "withdraw", "check_balance"]:
            print("Invalid option.")
            continue

        if action in["deposit", "withdraw"]:
            try:
                amount = float(input("Enter amount: ").strip())
                if amount <= 0:
                    print("Invalid amount. Please enter a number.")
                    continue
            except ValueError:
                print("Invalid amount. Please enter a valid number.")
                continue
        else:
            # For check_balance, we don't need an amount
            amount = None

        request = {
            "action": action,
            "username": username,
            "amount": amount
        }

        response = send_request(request)
        print(response.get('message', 'No message from server.'))
        

def handle_user_action(client, action):
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    request = {
        "action": action,
        "username": username,
        "password": password
    }

    response = send_request(request)

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
            login_action(username)
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
