import socketserver, socket, sys, re, time, base64
socketserver.ThreadingTCPServer.allow_reuse_address = True
from collections import deque
from pathlib import Path

available_ports = deque(range(10000,65537))
active_users = {}

def broadcast(msg):
    # TODO: Encrypt the message for each specific recipient using their public key before sending.
    for username, sock in list(active_users.items()):
        try:
            sock.sendall(msg)
        except OSError:
            active_users.pop(username, None)

def read(socket):
    pieces = [b'']
    total = 0
    while b'\0' not in pieces[-1] and total < 1048576:
        pieces.append(socket.recv(128))
        total += len(pieces[-1])
    data = b''.join(pieces).decode("utf-8").strip("\0")
    return data

class TCPServerRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        ip = self.request.getpeername()[0]
        next_data_port = available_ports.popleft()
        try:
            # TODO: Append the server's public key to the connect response
            #       (status code, blank line, data port, public key).
            self.request.sendall(f"200\n\n{next_data_port}\0".encode("utf-8"))

            print("Connection requested. Creating data socket")
            time.sleep(0.75)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                data_socket.connect((ip, next_data_port))
                username = ""

                while True:
                    command = read(self.request)
                    print("Received encrypted message")
                    # TODO: Decrypt the incoming encrypted command using the server's private key.

                    if command.startswith("login"):
                        # TODO: Extract username and the client's public key from the decrypted login message.
                        username = command.split()[1]
                        print(f"Login requested by: {username}")
                        if username in active_users:
                            # TODO: Encrypt the 500 error response with the correct key.
                            data_socket.sendall(b"500\n\nThe username you entered is already taken.\0")
                            continue

                        # TODO: Store the client's public key along with the user's data socket
                        #       (e.g., active_users[username] = (data_socket, public_key)).
                        active_users[username] = data_socket
                        # TODO: Encrypt the join notification with each active client's public key before broadcasting.
                        broadcast(f"200\n\njoin\n{username}\0".encode("utf-8"))
                    elif command.startswith("who"):
                        print("Who requested. Sending users.")
                        if not username:
                            # TODO: Encrypt the 500 error response with the correct key.
                            data_socket.sendall(b"500\n\nYou must be logged in to use this command.\0")
                            continue

                        # TODO: Encrypt the active users list with the requesting client's public key before sending.
                        data_socket.sendall(f"200\n\nACTIVE USERS\n{"\n".join(user for user in active_users.keys())}\0".encode("utf-8"))
                    elif command.startswith("broadcast"):
                        match = re.search(r"^broadcast (.+)$", command)
                        msg = match.group(1)
                        if not username:
                            # TODO: Encrypt the 500 error response with the correct key.
                            data_socket.sendall(b"500\n\nYou must be logged in to use this command.\0")
                            continue

                        print(f"Broadcast requested by {username}")
                        print(f"Message: {msg}")
                        # TODO: Encrypt the broadcast message with each recipient's public key before sending.
                        broadcast(f"200\n\nBroadcast\n{username}\n{msg}\0".encode("utf-8"))
                    elif command.startswith("private"):
                        if not username:
                            # TODO: Encrypt the 500 error response with the correct key.
                            data_socket.sendall(b"500\n\nYou must be logged in to use this command.\0")
                            continue

                        match = re.search(r"^private ([^\s]+) (.+)$", command)
                        user, msg = match.group(1), match.group(2)
                        if user not in active_users:
                            # TODO: Encrypt the 500 error response with the correct key.
                            data_socket.sendall(f"500\n\nUser {user} is not an active user.\0".encode("utf-8"))
                            continue

                        print(f"Private message from {username} to {user}")
                        # TODO: Encrypt the private message with the recipient's public key before sending.
                        client_side_msg = f"200\n\nPrivate\n{username}\n{msg}\0".encode("utf-8")
                        active_users[user].sendall(client_side_msg)
                        data_socket.sendall(client_side_msg)
                    elif command.startswith("quit"):
                        if not username:
                            # TODO: Encrypt the 500 error response with the correct key.
                            data_socket.sendall(b"500\nYou must be logged in to use this command.\0")
                            continue

                        print(f"Quit requested by {username}")
                        # TODO: Encrypt the quit response/notification with the correct keys before sending.
                        quit_msg = f"200\n\nquit\n{username}\0".encode("utf-8")
                        data_socket.sendall(quit_msg)
                        active_users.pop(username, None)
                        broadcast(quit_msg)
                        break
                    elif command.startswith("list"):
                        files = ", ".join(item.name for item in Path("./").iterdir() if item.is_file())
                        msg = f"200\n\n{files}\0".encode("utf-8")
                        # TODO: Encrypt the response if this command is kept.
                        data_socket.sendall(msg)
                    elif command.startswith("stor"):
                        _, filename = command.split()
                        file_contents = read(data_socket)
                        file_contents_decoded = base64.b64decode(file_contents)
                        try:
                            with open(f"./{filename}", "wb") as file:
                                file.write(file_contents_decoded)
                                # TODO: Encrypt the response if this command is kept.
                                data_socket.sendall(f"200\0".encode("utf-8"))
                        except OSError:
                            # TODO: Encrypt the response if this command is kept.
                            data_socket.sendall(f"500\0".encode("utf-8"))
                    elif command.startswith("retr"):
                        _, filename = command.split()
                        try:
                            with open(f"./{filename}", "rb") as file:
                                contents = file.read()
                                encoded_contents = base64.b64encode(contents)
                                # TODO: Encrypt the response if this command is kept.
                                data_socket.sendall(b"200\n\n%b\0" % (encoded_contents))
                        except OSError:
                            # TODO: Encrypt the response if this command is kept.
                            data_socket.sendall(f"500\0".encode("utf-8"))
                    elif command.startswith("dele"):
                        _, filename = command.split()
                        try:
                            Path(f"./{filename}").unlink(missing_ok=True)
                            # TODO: Encrypt the response if this command is kept.
                            data_socket.sendall(f"200\0".encode("utf-8"))
                        except OSError:
                            # TODO: Encrypt the response if this command is kept.
                            data_socket.sendall(f"500\0".encode("utf-8"))

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
# TODO: Generate an RSA 2048 public-private key pair and store it in memory.
print("RSA keypair created")
print("Creating server socket")
with socketserver.ThreadingTCPServer((HOST, PORT), TCPServerRequestHandler) as server:
    print("Awaiting connections…")
    server.serve_forever()
