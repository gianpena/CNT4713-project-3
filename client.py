import socket
import threading
import base64
import binascii
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

print("Starting client...")

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")
server_public_key = None

current_command = ""
username = ""
quit_response = threading.Event()
command_response = threading.Event()
login_response = threading.Event()
requested_file = ""


def encrypt(message, key):
    if isinstance(message, str):
        message = message.encode("utf-8")

    encrypted = b""
    for i in range(0, len(message), 190):
        encrypted += key.encrypt(
            message[i:i + 190],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return base64.b64encode(encrypted) + b"\0"


def decrypt(message):
    ciphertext = base64.b64decode(message, validate=True)
    if not ciphertext or len(ciphertext) % 256 != 0:
        raise ValueError("Invalid ciphertext length")

    plaintext = b""
    for i in range(0, len(ciphertext), 256):
        plaintext += private_key.decrypt(
            ciphertext[i:i + 256],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    return plaintext.decode("utf-8")


def send_encrypted(connection, message):
    connection.sendall(encrypt(message, server_public_key))


def receive_message(connection, encrypted=False):
    message = bytearray()
    while True:
        character = connection.recv(1)
        if not character:
            return None
        if character == b"\0":
            return bytes(message) if encrypted else message.decode("utf-8")
        message.extend(character)


def listen_for_messages(data_connection):
    global current_command

    while True:
        response = receive_message(data_connection, encrypted=True)
        if response is None:
            login_response.set()
            quit_response.set()
            command_response.set()
            break

        # Before login, the server can send plaintext 500 errors.
        if response.startswith(b"500\n") or response == b"500":
            response = response.decode("utf-8")
        else:
            try:
                response = decrypt(response)
            except (ValueError, binascii.Error) as error:
                print(f"Could not decrypt response: {error}")
                login_response.set()
                quit_response.set()
                command_response.set()
                break
            print("Received encrypted message")

        status_code, _, data = response.partition("\n\n")
        status_code = status_code.strip()
        parts = data.splitlines()

        if status_code == "500":
            print(f"{status_code} status code received.")
            if data:
                print(data)
            failed_command = current_command
            current_command = ""
            if failed_command == "login":
                login_response.set()
            if failed_command == "quit":
                quit_response.set()
            command_response.set()
            continue

        if current_command == "login" and not parts:
            print(f"{status_code} status code received. Login successful")
            current_command = ""
            login_response.set()

        elif current_command == "private" and not parts:
            print(f"{status_code} status code received. Message sent.")
            current_command = ""

        elif current_command == "quit" and not parts:
            print(f"{status_code} status code received.")
            quit_response.set()
            break

        elif parts and parts[0] == "Private":
            sender = parts[1]
            message = "\n".join(parts[2:])
            if sender == username and current_command == "private":
                print(f"{status_code} status code received. Message sent.")
                current_command = ""
            else:
                print(f"{status_code} status code received.")
                print(f"{sender}: {message}")

        elif parts and parts[0] == "Broadcast":
            sender = parts[1]
            message = "\n".join(parts[2:])
            print(f"{status_code} status code received.")
            print(f"Broadcast message from {sender}: {message}")

        elif parts and parts[0] == "join":
            if current_command == "login":
                print(f"{status_code} status code received. Login successful")
                current_command = ""
                login_response.set()
            elif parts[1].strip() != username.strip():
                print(f"{parts[1]} joined")
        

        elif parts and parts[0] == "quit":
            if parts[1].strip() == username.strip():
                print(f"{status_code} status code received.")
                quit_response.set()
                break
            else:
                print(f"{parts[1]} left")

        elif current_command == "who":
            if parts and parts[0] == "ACTIVE USERS":
                users = ", ".join(parts[1:])
                print(f"{status_code} status code received. Users currently connected: {users}")
            elif data.startswith("Users currently connected:"):
                print(f"{status_code} status code received. {data}")
            else:
                print(f"{status_code} status code received. Users currently connected: {', '.join(parts)}")
            current_command = ""

        elif current_command == "list":
            print(f"{status_code} status code received. Files: {data}")
            current_command = ""
            command_response.set()

        elif current_command == "stor":
            print(f"{status_code} status code received. File Sent.")
            current_command = ""
            command_response.set()

        elif current_command == "retr":
            try:
                file_bytes = base64.b64decode(data.rstrip("\0"), validate=True)
                with open(requested_file, "wb") as file:
                    file.write(file_bytes)
                print("File retrieved.")
            except (ValueError, OSError, binascii.Error) as error:
                print(f"Could not save file: {error}")
            current_command = ""
            command_response.set()

        elif current_command == "dele":
            print(f"{status_code} status code received. File deleted.")
            current_command = ""
            command_response.set()


while True:
    try:
        command = input()
    except EOFError:
        break
    parts = command.split()

    if not parts:
        continue

    if parts[0] == "connect":
        server_ip = parts[1]
        server_port = int(parts[2])
        control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        control_socket.connect((server_ip, server_port))
        response = receive_message(control_socket)
        if response is None:
            control_socket.close()
            continue
        response_parts = response.split("\n\n", 1)
        status_code = response_parts[0].strip()
        if status_code != "200":
            print(f"{status_code} status code received.")
            control_socket.close()
            continue
        data_port_text, _, server_key_text = response_parts[1].partition("\n")
        data_port = int(data_port_text)
        server_public_key = serialization.load_pem_public_key(server_key_text.encode("utf-8"))
        print(f"{status_code} status code received. Starting data connection on port {data_port}")
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        data_socket.bind(("", data_port))
        data_socket.listen(1)
        data_connection, address = data_socket.accept()
        data_socket.close()
        listener = threading.Thread(target=listen_for_messages, args=(data_connection,))
        listener.daemon = True
        listener.start()

    elif parts[0] == "login":
        username = parts[1]
        login_response.clear()
        current_command = "login"
        send_encrypted(control_socket, f"login\n{username}\n{public_key_pem}")
        login_response.wait()

    elif parts[0] == "who":
        current_command = "who"
        send_encrypted(control_socket, command)

    elif parts[0] == "broadcast":
        send_encrypted(control_socket, command)

    elif parts[0] == "private":
        current_command = "private"
        send_encrypted(control_socket, command)

    elif parts[0] == "list":
        command_response.clear()
        current_command = "list"
        send_encrypted(control_socket, "list")
        command_response.wait()

    elif parts[0] == "stor" and len(parts) > 1:
        filename = parts[1]
        try:
            with open(filename, "rb") as file:
                file_data = base64.b64encode(file.read())
        except OSError as error:
            print(f"Could not open file: {error}")
            continue
        command_response.clear()
        current_command = "stor"
        send_encrypted(control_socket, command)
        send_encrypted(data_connection, file_data)
        command_response.wait()

    elif parts[0] == "retr" and len(parts) > 1:
        requested_file = parts[1]
        command_response.clear()
        current_command = "retr"
        send_encrypted(control_socket, command)
        command_response.wait()

    elif parts[0] == "dele" and len(parts) > 1:
        command_response.clear()
        current_command = "dele"
        send_encrypted(control_socket, command)
        command_response.wait()

    elif parts[0] == "quit":
        quit_response.clear()
        current_command = "quit"
        send_encrypted(control_socket, command)
        quit_response.wait()
        if current_command != "quit":
            continue
        data_connection.close()
        control_socket.close()
        break
