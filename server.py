import socketserver, socket, sys, re, time, base64
socketserver.ThreadingTCPServer.allow_reuse_address = True
from collections import deque
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

available_ports = deque(range(10000,65537))
active_users = {}

def encrypt(msg, key):
    ciphertext = key.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext)

def decrypt(msg):
    ciphertext = base64.b64decode(msg)
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def get_client_public_key(username):
    if username not in active_users: return None
    return active_users[username][1]

def broadcast(msg):
    for username, sock in list(active_users.items()):
        try:
            sock.sendall(encrypt(
                msg,
                get_client_public_key(username)
            ))
        except OSError:
            active_users.pop(username, None)

def read(socket):
    pieces = [b'']
    total = 0
    while b'\0' not in pieces[-1] and total < 1048576:
        pieces.append(socket.recv(128))
        total += len(pieces[-1])
    data = b''.join(pieces)
    ciphertext, _, _ = data.partition(b'\0')
    return decrypt(ciphertext)

class TCPServerRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.request.getpeername()[0]
        next_data_port = available_ports.popleft()
        try:
            self.request.sendall(f"200\n\n{next_data_port}\n{public_key_pem}\0".encode("utf-8"))

            print("Connection requested. Creating data socket")
            time.sleep(0.75)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                data_socket.connect((ip, next_data_port))
                username = ""

                while True:
                    command = read(self.request).decode("utf-8")
                    print("Received encrypted message")

                    if command.startswith("login"):
                        # TODO: Parse the username and the full PEM public key from the decrypted login message.
                        #       The current split assumes only two whitespace-separated tokens, which will
                        #       break when the PEM contains newlines.
                        # TODO: Validate that both username and public key are present; send 500 if any
                        #       component is missing (per the spec).
                        # TODO: The spec requires the entire login message (including the client's PEM
                        #       public key) to be encrypted with RSA-2048, but a PEM key is larger than
                        #       RSA-OAEP can encrypt. Determine how to handle this under the project rules.
                        username, client_public_key_string = command.split()[1:]
                        client_public_key = serialization.load_pem_public_key(client_public_key_string.encode("utf-8"))

                        print(f"Login requested by: {username}")
                        if username in active_users:
                            data_socket.sendall(encrypt(b"500\n\nThe username you entered is already taken.\0", client_public_key))
                            continue

                        active_users[username] = (data_socket, client_public_key)
                        broadcast(f"200\n\njoin\n{username}\0".encode("utf-8"))
                    elif command.startswith("who"):
                        print("Who requested. Sending users.")
                        if not username:
                            data_socket.sendall(b"500\n\nYou must be logged in to use this command.\0")
                            continue

                        # TODO: If the spec's SHA256-hash-response rule applies, compute the hash and
                        #       return encrypted hash instead of (or in addition to) the user list.
                        data_socket.sendall(encrypt(
                            f"200\n\nUsers currently connected: {", ".join(user for user in active_users.keys())}\0".encode("utf-8"),
                            get_client_public_key(username)
                        ))
                    elif command.startswith("broadcast"):
                        match = re.search(r"^broadcast (.+)$", command)
                        msg = match.group(1)
                        if not username:
                            data_socket.sendall(b"500\n\nYou must be logged in to use this command.\0")
                            continue

                        print(f"Broadcast requested by {username}")
                        print(f"Message: {msg}")
                        broadcast(f"200\n\nBroadcast\n{username}\n{msg}\0".encode("utf-8"))
                    elif command.startswith("private"):
                        if not username:
                            data_socket.sendall(b"500\n\nYou must be logged in to use this command.\0")
                            continue

                        match = re.search(r"^private ([^\s]+) (.+)$", command)
                        user, msg = match.group(1), match.group(2)
                        if user not in active_users:
                            data_socket.sendall(encrypt(
                                f"500\n\nUser {user} is not an active user.\0".encode("utf-8"),
                                get_client_public_key(username)
                            ))
                            continue

                        print(f"Private message from {username} to {user}")
                        client_side_msg = f"200\n\nPrivate\n{username}\n{msg}\0".encode("utf-8")
                        active_users[user][0].sendall(encrypt(client_side_msg, get_client_public_key(user)))
                        data_socket.sendall(encrypt(client_side_msg, get_client_public_key(username)))
                    elif command.startswith("quit"):
                        if not username:
                            data_socket.sendall(b"500\nYou must be logged in to use this command.\0")
                            continue

                        print(f"Quit requested by {username}")
                        quit_msg = f"200\n\nquit\n{username}\0".encode("utf-8")
                        data_socket.sendall(encrypt(quit_msg, get_client_public_key(username)))
                        active_users.pop(username, None)
                        broadcast(quit_msg)
                        break
                    elif command.startswith("list"):
                        if not username:
                            data_socket.sendall(b"500\nYou must be logged in to use this command.\0")
                            continue

                        files = ", ".join(item.name for item in Path("./").iterdir() if item.is_file())
                        msg = encrypt(f"200\n\n{files}\0".encode("utf-8"), get_client_public_key(username))
                        data_socket.sendall(msg)
                    elif command.startswith("stor"):
                        if not username:
                            data_socket.sendall(b"500\nYou must be logged in to use this command.\0")
                            continue

                        _, filename = command.split()
                        file_contents = read(data_socket)
                        file_contents_decoded = base64.b64decode(file_contents)
                        try:
                            with open(f"./{filename}", "wb") as file:
                                file.write(file_contents_decoded)
                                data_socket.sendall(encrypt(
                                    f"200\0".encode("utf-8"),
                                    get_client_public_key(username)
                                ))
                        except OSError:
                            data_socket.sendall(encrypt(
                                f"500\0".encode("utf-8"),
                                get_client_public_key(username)
                            ))
                    elif command.startswith("retr"):
                        _, filename = command.split()
                        try:
                            with open(f"./{filename}", "rb") as file:
                                contents = file.read()
                                encoded_contents = base64.b64encode(contents)
                                data_socket.sendall(encrypt(
                                    b"200\n\n%b\0" % (encoded_contents),
                                    get_client_public_key(username)
                                ))
                        except OSError:
                            data_socket.sendall(encrypt(
                                f"500\0".encode("utf-8"),
                                get_client_public_key(username)
                            ))
                    elif command.startswith("dele"):
                        _, filename = command.split()
                        try:
                            Path(f"./{filename}").unlink(missing_ok=True)
                            data_socket.sendall(encrypt(
                                f"200\0".encode("utf-8"),
                                get_client_public_key(username)
                            ))
                        except OSError:
                            data_socket.sendall(encrypt(
                                f"500\0".encode("utf-8"),
                                get_client_public_key(username)
                            ))

                available_ports.appendleft(next_data_port)
                data_socket.close()
                self.request.close()
        except (ConnectionError, OSError):
            pass
        finally:
            available_ports.appendleft(next_data_port)


if len(sys.argv) < 2:
    print("Please enter the port.")

HOST, PORT = "0.0.0.0", int(sys.argv[1])
print("Starting server…")
print("Creating RSA keypair")
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")
print("RSA keypair created")
print("Creating server socket")
with socketserver.ThreadingTCPServer((HOST, PORT), TCPServerRequestHandler) as server:
    print("Awaiting connections…")
    server.serve_forever()
