import socket
import threading
import json
import logging

customers = {
    "timmy ngo": {
        "password": "123",
        "balance": 1000,
        "transactions": ["deposit 100", "withdraw 20"]
    }
} # Simulated in-memory database for user accounts

lock = threading.Lock()

# logging configuration
logging.basicConfig(
    filename="audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def handle_client(conn, addr):
    logging.info(f"New connection from {addr}")
    print(f"[NEW CONNECTION] {addr} connected.")

    try:
        while True:
            data = conn.recv(1024).decode()
            if not data:
                print(f"[DISCONNECTED] {addr} disconnected.")
                break

            print(f"[RECEIVED] {data} from {addr}")

            # Parse the incoming JSON data
            request = json.loads(data)
            action = request.get("action")
            username = request.get("username")
            password = request.get("password")

            response = handle_action(action, username, password, request)
            conn.send(json.dumps(response).encode())
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
            "password": password,
            "balance": 0,
            "transactions": []
        }
        logging.info(f"Username {username} registered successfully.")
        return {"status": "success", "message": "Registration successful."}

def handle_login(username, password):
    with lock:
        logging.info(f"Login attempt for user: {username}")
        if username in customers and customers[username]["password"] == password:
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
            logging.info(f"User {username} deposited ${amount}. New balance: ${customers[username]['balance']}")
            return {"status": "success", "message": f"Deposited ${amount}. New balance: ${customers[username]['balance']}"}
    return {"status": "fail", "message": "Username not found."}

def handle_withdraw(username, amount):
    if not isinstance(amount, (int, float)) or amount <= 0:
        return {"status": "fail", "message": "Invalid withdrawal amount."}
    with lock:    
        if username in customers and customers[username]["balance"] >= amount:
            customers[username]["balance"] -= amount
            customers[username]["transactions"].append(f"withdraw {amount}")
            logging.info(f"User {username} withdrew ${amount}. New balance: ${customers[username]['balance']}")
            return {"status": "success", "message": f"Withdrew ${amount}. New balance: ${customers[username]['balance']}"}
    return {"status": "fail", "message": "Invalid withdrawal request."}

def handle_check_balance(username):
    with lock:
        if username in customers:
            balance = customers[username]["balance"]
            logging.info(f"User {username} checked balance: ${balance}")
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
