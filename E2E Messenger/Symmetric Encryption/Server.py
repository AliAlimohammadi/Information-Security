import socket
import os
import sys
import time
import threading
import select
from getpass import getpass

from Crypto import Random
from Crypto.Cipher import AES
from tinydb import TinyDB, Query

ADMIN_PASSWORD = ""
HOST = socket.gethostbyname(socket.gethostname())
PORT = 9999
MAX_CLIENTS = 2
BUFFER_SIZE = 4096
sockets_list = []
clients = {}

rooms = ["General"]

if not os.path.isdir("log"):
    os.mkdir("log")

file = open('log/users.json', 'w')
file.close()
db = TinyDB('log/users.json')

key = Random.get_random_bytes(32)
cipher = AES.new(key, AES.MODE_EAX)
file = open('log/AES_Key.key', 'wb')
[file.write(x) for x in (key, cipher.nonce)]
file.close()
session_key_map = dict()
session_cipher = dict()


class SessionKeyGen(threading.Thread):
    def __init__(self, username, client_socket):
        threading.Thread.__init__(self)
        self.setDaemon(True)
        self.username = username
        self.client_socket = client_socket

    def run(self):
        session_key_cipher = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
        session_cipher[self.username] = session_key_cipher
        while True:
            session_key = Random.get_random_bytes(32)
            session_key_map[self.username] = session_key
            session_key_cipher = session_cipher[self.username]
            negotiate = session_key_cipher.nonce + '~SK~'.encode() + session_key_cipher.encrypt(session_key) + '--END--'.encode()
            session_cipher[self.username] = session_key_cipher
            self.client_socket.send(negotiate)
            print("---NEW SESSION KEY FOR <" + self.username + ">---")
            print(session_key)
            time.sleep(30)


class Logger(object):
    def __init__(self, filename="Default.log"):
        self.terminal = sys.stdout
        self.log = open(filename, "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        pass


sys.stdout = Logger("log/server.txt")


class User(object):
    def __init__(self, username):
        self.username = username
        self.password = ""
        self.rooms = []
        self.default_room = "General"
        self.public_key = ""
        self.warn = 0


def run_server():
    while True:
        if clients:
            for client in clients:
                query = Query()
                if not db.search(query.username == clients[client].username):
                    data = {
                        "username": clients[client].username,
                        "password": clients[client].password,
                        "rooms": clients[client].rooms,
                        "default_room": clients[client].default_room,
                    }
                    db.insert(data)
        read_sockets, write_sockets, exception_sockets = select.select(sockets_list, [], [])
        for notified_socket in read_sockets:
            if notified_socket == server_socket:
                client_socket, client_address = server_socket.accept()
                print(f"New incoming connection from {client_address[0]}")
                sockets_list.append(client_socket)
                data = (client_socket.recv(BUFFER_SIZE)).decode()
                username = data.partition(" ")[0]
                confirm = data.partition(" ")[2]
                relogin_flag = False
                if confirm == "EXISTS":
                    success_message = "Successfully logged in!"
                    response = success_message
                    client_socket.send(response.encode())
                    relogin_flag = True
                else:
                    success_message = "Username set successfully!"
                    response = success_message
                    client_socket.send(response.encode())
                clients[client_socket] = User(username)
                SessionKeyGen(username, client_socket).start()
                clients[client_socket].rooms.append("General")
                if relogin_flag:
                    print(f"{clients[client_socket].username} logged back in")
                else:
                    print(f"{client_address[0]} set username to {clients[client_socket].username}")
                broadcast("[SERVER] " + str(clients[client_socket].username) +
                          " has joined the " + str(clients[client_socket].default_room) + " room.\n",
                          client_socket, server_socket, clients[client_socket].default_room)
                send_to_client("[SERVER] Welcome " + str(clients[client_socket].username) +
                               "! Kindly set a password using /p command, if not set.\n"
                               "You have joined the " + str(clients[client_socket].default_room) + " room.\n",
                               client_socket, server_socket)
                print(f"{clients[client_socket].username} joined {clients[client_socket].default_room} room")
            else:
                try:
                    stream = notified_socket.recv(BUFFER_SIZE)
                    if stream.partition(b" ")[0] == b"/private":
                        sub_string = stream.partition(b"<")[2]
                        destination_username = sub_string.partition(b">")[0].decode()
                        message = sub_string.partition(b"> ")[2]
                        session_key_cipher = AES.new(session_key_map[clients[notified_socket].username], AES.MODE_EAX, message.partition(b"~NONCE~")[0])
                        decrypted_message = session_key_cipher.decrypt_and_verify(message.partition(b"~PM~")[0].partition(b"~NONCE~")[2], message.partition(b"~PM~")[2])
                        send_private_message(destination_username, decrypted_message.decode(), notified_socket, server_socket)
                    # if stream and stream[0] == "~":
                    #     try:
                    #         cipher_instance = AES.new(session_key_map[clients[client_socket].username], AES.MODE_EAX)
                    #         print(stream)
                    #         tag = bytes(stream.partition("****")[2], encoding="ISO-8859-1")
                    #         print("HELLO            ")
                    #         print(tag)
                    #         stream = cipher_instance.decrypt_and_verify(bytes(stream.partition("****")[0], encoding="ISO-8859-1"), tag)
                    #     except ValueError:
                    #         send_to_client("[SERVER] Data was damaged.\nPlease try again.", client_socket, server_socket)
                    #         continue
                    else:
                        stream = stream.decode()
                        if stream:
                            if stream[0] == "/":
                                if stream.partition(" ")[2] != "":
                                    command = stream.partition(" ")[0].strip()
                                else:
                                    command = stream.strip()
                                if command == "/u":
                                    new_username = stream.partition("/u ")[2].strip()
                                    change_username(new_username, notified_socket, server_socket)
                                elif command == "/p":
                                    new_password = client_password(notified_socket, server_socket).strip()
                                    if new_password:
                                        change_password(new_password, notified_socket, server_socket)
                                    else:
                                        send_to_client("Invalid password", notified_socket, server_socket)
                                elif command == "/c":
                                    new_room = stream.partition("/c ")[2].strip()
                                    create_room(new_room, notified_socket, server_socket)
                                elif command == "/j":
                                    new_room = stream.partition("/j ")[2].strip()
                                    join_room(new_room, notified_socket, server_socket)
                                elif command == "/l":
                                    selected_room = stream.partition("/l ")[2].strip()
                                    leave_room(selected_room, notified_socket, server_socket)
                                elif command == "/cd":
                                    selected_room = stream.partition("/cd ")[2].strip()
                                    change_default_room(selected_room, notified_socket, server_socket)
                                elif command == "/list":
                                    if check_admin_password(notified_socket, server_socket):
                                        list_rooms(notified_socket, server_socket)
                                    else:
                                        send_to_client("Wrong Admin password!", notified_socket, server_socket)
                                        print(f"Failed admin attempt: {clients[notified_socket].username}")
                                elif command == "/users":
                                    if check_admin_password(notified_socket, server_socket):
                                        list_users(notified_socket, server_socket)
                                    else:
                                        send_to_client("Wrong Admin password!", notified_socket, server_socket)
                                        print(f"Failed admin attempt: {clients[notified_socket].username}")
                                elif command == "/public":
                                    sub_string = stream.partition("<")[2]
                                    destination_room = sub_string.partition(">")[0]
                                    message = sub_string.partition("> ")[2].strip()
                                    send_different_room(destination_room, message, notified_socket, server_socket)
                                elif command == "/logout":
                                    broadcast("[SERVER] " + clients[notified_socket].username + " has left the server!\n",
                                            notified_socket, server_socket, clients[notified_socket].default_room)
                                    remove_socket(notified_socket)
                                    print(f"{clients[notified_socket].username} has disconnected")
                                else:
                                    send_to_client("[SERVER] Invalid command!\n", client_socket, server_socket)
                            else:
                                if clients[notified_socket].default_room in clients[notified_socket].rooms:
                                    broadcast(str(clients[notified_socket].username) + " : " + stream.decode(),
                                            notified_socket, server_socket, clients[notified_socket].default_room)
                                    print(f"{clients[client_socket].username} sent a message in "
                                        f"{clients[notified_socket].default_room}, broadcasting now")
                                else:
                                    send_to_client("[SERVER] Please set the default room!\n",
                                               notified_socket, server_socket)
                        else:
                            broadcast("[SERVER] " + clients[notified_socket].username + " has left the server!\n",
                                    notified_socket, server_socket, clients[notified_socket].default_room)
                            remove_socket(notified_socket)
                            print(f"{clients[notified_socket].username} has disconnected")
                except ConnectionResetError:
                    print(f"Connection reset by {clients[client].username}")
                    continue


def check_admin_password(client_socket, server_socket):
    for client in sockets_list[1:]:
        if client == client_socket and client != server_socket:
            client_socket.send("GETADMINPASS".encode())
            rcv_pass = client_socket.recv(BUFFER_SIZE).decode()
            cipher_instance = AES.new(session_key_map[clients[client_socket].username], AES.MODE_EAX)
            tag = rcv_pass.partition("****")[2]
            try:
                rcv_pass = cipher_instance.decrypt_and_verify(rcv_pass.partition("****")[0], tag)
            except ValueError:
                return False
            if rcv_pass == cipher_instance.decrypt_and_verify(ADMIN_PASSWORD).decode():
                return True
            else:
                return False


def client_password(client_socket, server_socket):
    for client in sockets_list[1:]:
        if client == client_socket and client != server_socket:
            client_socket.send("GETUSERPASS".encode())
            rcv_pass = client_socket.recv(BUFFER_SIZE).decode()
            if rcv_pass:
                return rcv_pass
            else:
                return False


def check_username(username, server_socket):
    for user in sockets_list:
        if user != server_socket:
            if clients[user].username == username:
                return False
    return True


def change_username(username, client_socket, server_socket):
    if username:
        if check_username(username, server_socket):
            print(f"{clients[client_socket].username} changed username to {username}")
            send_to_client("[SERVER] Username changed to " + username + "\n",
                           client_socket, server_socket)
            broadcast(clients[client_socket].username + " changed username to " + username + "!\n",
                      client_socket, server_socket, "General")
            clients[client_socket].username = username
        else:
            send_to_client("[SERVER] Username " + username + " is already taken." + "\n",
                           client_socket, server_socket)
    else:
        send_to_client("[SERVER] Correct usage: /u [username]\n", client_socket, server_socket)


def change_password(new_pass, client_socket, server_socket):
    clients[client_socket].password = cipher.encrypt(str(new_pass).encode()).decode("ISO-8859-1")
    send_to_client("[SERVER] Password changed!\n", client_socket, server_socket)


def create_room(room, client_socket, server_socket):
    if room:
        if room not in rooms:
            send_to_client("[SERVER] New room created: " + room + "\n", client_socket, server_socket)
            rooms.append(room)
            print(f"{clients[client_socket].username} created a new room: {room}")
        else:
            send_to_client("[SERVER] " + room + " room already exists!\n", client_socket, server_socket)
    else:
        send_to_client("[SERVER] Correct usage: /c [room_name]\n", client_socket, server_socket)


def join_room(room, client_socket, server_socket):
    if room:
        if room in rooms:
            if room in clients[client_socket].rooms:
                send_to_client("[SERVER] You are already in the room!\n", client_socket, server_socket)
            else:
                clients[client_socket].rooms.append(room)
                send_to_client("[SERVER] You have been added to " + room + "!\n", client_socket, server_socket)
                broadcast("[SERVER] " + str(clients[client_socket].username) + " has joined the " +
                          str(room) + " room\n", client_socket, server_socket, room)
                print(f"{clients[client_socket].username} joined {room} room")
        else:
            send_to_client("[SERVER] " + room + "does not exist!\n", client_socket, server_socket)
    else:
        send_to_client("[SERVER] Correct usage: /j [room_name]\n", client_socket, server_socket)


def leave_room(room, client_socket, server_socket):
    if room:
        if room in clients[client_socket].rooms:
            broadcast("[SERVER] " + str(clients[client_socket].username) + " has left the room!\n",
                      client_socket, server_socket, room)
            send_to_client("[SERVER] You have left the " + room + " room!\n", client_socket, server_socket)
            clients[client_socket].rooms.remove(room)
            print(f"{clients[client_socket].username} left {room} room")
        else:
            send_to_client("[SERVER] You cannot leave a room you are not a part of!\n",
                           client_socket, server_socket)
    else:
        send_to_client("[SERVER] Correct usage: /l [room_name]\n", client_socket, server_socket)


def list_rooms(client_socket, server_socket):
    room_list = ""
    for room in rooms:
        room_list += str(room) + "\n"
    send_to_client("[SERVER] List of rooms on server:\n" + room_list, client_socket, server_socket)
    print(f"{clients[client_socket].username} listed rooms using admin credentials")


def list_users(client_socket, server_socket):
    users = ""
    for u in sockets_list:
        if u != server_socket:
            users += str(clients[u].username) + "\n"
    send_to_client("[SERVER] Online Users:\n" + users,
                   client_socket, server_socket)
    print(f"{clients[client_socket].username} listed users using admin credentials")


def change_default_room(room, client_socket, server_socket):
    if room:
        if room in clients[client_socket].rooms:
            send_to_client("[SERVER] Default room changed from " + clients[client_socket].default_room +
                           " to " + room + "\n", client_socket, server_socket)
            clients[client_socket].default_room = room
            print(f"{clients[client_socket].username} changed default room to {room}")
        else:
            send_to_client("[SERVER] Cannot change default room to a room you are not part of "
                           "or if it does not exist!\n", client_socket, server_socket)
    else:
        send_to_client("[SERVER] Correct usage: /public <[room]> [message]\n", client_socket, server_socket)


def send_different_room(room, message, client_socket, server_socket):
    if room and message:
        if room in clients[client_socket].rooms:
            broadcast(str(clients[client_socket].username) + " : " + message + "\n",
                      client_socket, server_socket, room)
            print(f"Public message sent from {clients[client_socket].username} to {room} room")
        else:
            send_to_client("[SERVER] Cannot send message to room you are not part of!\n",
                           client_socket, server_socket)
    else:
        send_to_client("[SERVER] Correct usage: /public <[room]> [message]", client_socket, server_socket)


def send_private_message(username, message, client_socket, server_socket):
    if username and message:
        for client in sockets_list:
            if len(sockets_list) > 2:
                if client != client_socket and client != server_socket:
                    if clients[client].username.strip() == username.strip():
                        message_string = str("[E2E][Private message by " + clients[client_socket].username + \
                                             "] : " + message).encode()
                        session_key_cipher = AES.new(session_key_map[username], AES.MODE_EAX)
                        encrypted_message, tag = session_key_cipher.encrypt_and_digest(message_string)
                        client.send(session_key_cipher.nonce + "~NONCE~".encode() + encrypted_message + "~PM~".encode() + tag)
                        session_cipher[session_key_map[username]] = session_key_cipher
                        send_to_client("[SERVER] Private message sent!\n", client_socket,
                                       server_socket)
                        print(f"Private message sent from {clients[client_socket].username} to {username}")
                    elif clients[client_socket].username == username:
                        send_to_client("[SERVER] Private message cannot be sent to self!\n",
                                       client_socket, server_socket)
            else:
                send_to_client("[SERVER] Server needs to have more than 1 user!\n", client_socket, server_socket)
    else:
        send_to_client("[SERVER] Correct usage: /private <[username]> [message]\n", client_socket, server_socket)


def broadcast(message, client_socket, server_socket, room):
    for client in clients:
        if room in clients[client].rooms:
            file_name = str("log/" + clients[client].username + ".txt")
            with open(file_name, 'a+') as f:
                f.write(message)
                f.close()
    for client in sockets_list[1:]:
        if client != client_socket and client != server_socket and room in clients[client].rooms:
            try:
                client.send(message.encode())
            except:
                remove_socket(client)


def send_to_client(message, client_socket, server_socket):
    file_name = str("log/" + clients[client_socket].username + ".txt")
    with open(file_name, 'a+') as f:
        f.write(message)
        f.close()
    for client in sockets_list[1:]:
        if client == client_socket and client != server_socket:
            try:
                client_socket.send(message.encode())
            except:
                remove_socket(client)


def remove_socket(client_socket):
    if client_socket in sockets_list:
        sockets_list.remove(client_socket)
        client_socket.close()


if __name__ == "__main__":
    try:
        print("Running server script..")
        try:
            PORT = int(input("Specify port number for the server (default = 9999): "))
        except ValueError:
            print("Starting server on default port 9999!")
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(MAX_CLIENTS)
        sockets_list.append(server_socket)
        print(f"Server started on {HOST} : {PORT}")
        tmp_admin_password = getpass("Admin Password: ")
        ADMIN_PASSWORD = cipher.encrypt(tmp_admin_password.encode())
        tmp_admin_password = ""
        print("Password set and encrypted successfully!")
        print("Waiting for incoming connections..")
        threading.Thread(target=run_server())
    except KeyboardInterrupt:
        server_socket.close()
        print("\nServer stopped!")
