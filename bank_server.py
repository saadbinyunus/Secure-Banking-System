import socket
import threading
import json
import logging

customers = {} # Simulated in-memory database for user accounts

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
        data = conn.recv(1024).decode()
        request = json.loads(data)

        action = request.get("action")
        username = request.get("username")
        password = request.get("password")

        if action == "register":
            logging.info(f"Registration attempt for user: {username}")
            if username in customers:
                response = {"status": "fail", "message": "Username already exists."}
                logging.warning(f"Registration failed for user: {username} - Username already exists.")
            else:
                customers[username] = password
                response = {"status": "success", "message": "Registration successful."}
                logging.info(f"User {username} registered successfully.")
        elif action == "login":
            logging.info(f"Login attempt for user: {username}")
            if username in customers and customers[username] == password:
                response = {"status": "success", "message": "Login successful."}
                logging.info(f"User {username} logged in successfully.")
            else:
                response = {"status": "fail", "message": "Invalid credentials."}
                logging.warning(f"Failed login attempt for user: {username}")
        else:
            logging.error(f"Unknown action: {action}")
            response = {"status": "fail", "message": "Unknown action."}

        conn.send(json.dumps(response).encode())
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()

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
