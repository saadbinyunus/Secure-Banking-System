import socket
import json

def connect_to_server():
    host = 'localhost'
    port = 5555

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    return client

def send_request(client, request):
    client.send(json.dumps(request).encode())
    response = client.recv(1024).decode()
    return json.loads(response)
    
def login_action(client):
    while True:
        action = input("Choose action: [deposit/withdraw/check_balance/exit]: ").strip().lower()
        if action == "exit":
            break
        if action not in ["deposit", "withdraw", "check_balance"]:
            print("Invalid option.")
            continue

        if action in["deposit", "withdraw"]:
            amount = input("Enter amount: ").strip()
            if not amount.isdigit():
                print("Invalid amount. Please enter a number.")
                continue
            amount = int(amount)
        else:
            # For check_balance, we don't need an amount
            amount = None

        request = {
            "action": action,
            "amount": amount
        }
        

def main():
    print("Welcome to Secure ATM")

    client = connect_to_server()

    while True:
        action = input("Choose action: [register/login/exit]: ").strip().lower()
        if action == "exit":
            print("Exiting the ATM. Goodbye!")
            client.close()
            break
        if action not in ["register", "login"]:
            print("Invalid option.")
            continue

        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()

        request = {
            "action": action,
            "username": username,
            "password": password
        }

        response = send_request(client, request)

        # Check server response, after registering successfully
        if response['status'] == "success" and response['message'] == "Registration successful.":
            print("You can now log in with your credentials.")
            continue
        # Check server response, after logging in successfully
        elif response['status'] == "success" and response['message'] == "Login successful.":
            print("Welcome to your account!")
            login_action()

if __name__ == "__main__":
    main()
