import select
import socket
import sys
from base64 import b64decode
from getpass import getpass

from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from tinydb import TinyDB, Query

file = open('log/AES_Key.key', 'rb')
key, nonce = [file.read(x) for x in (32, 16)]
file.close()
cipher = AES.new(key, AES.MODE_EAX, nonce)
session_cipher = cipher
session_key = None

db = TinyDB('log/users.json')

BUFFER_SIZE = 4096


def chat(h, p):
    host = str(h)
    port = int(p)
    client_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_connection.settimeout(30)
    try:
        client_connection.connect((host, port))
    except socket.error:
        print("Unable to connect!")
        sys.exit(0)
    print("Connected to the server!")
    is_user = False
    global cipher
    global session_key
    global server_public_key
    while True:
        username = input("Username: ")
        user_query = Query()
        result = db.search(user_query.username == username)
        for r in result:
            if r['username']:
                password = getpass()
                if r['password'] == "" and password == "":
                    client_connection.send((r['username'] + " EXISTS").encode())
                    response = client_connection.recv(BUFFER_SIZE).decode()
                    # elif response.partition("~SK~")[2] != '':
                    #     token = response.partition("~SK~")[2].encode()
                    #     decrypted_key = cipher.decrypt(token)
                    #     print(decrypted_key.decode())
                    #     session_cipher = AES.new(decrypted_key, AES.MODE_EAX)
                    is_user = True
                    break
                else:
                    if cipher.decrypt(r['password'].encode()) == password.encode():
                        client_connection.send((r['username'] + " EXISTS" + client_public_key).encode())
                        response = client_connection.recv(BUFFER_SIZE).decode()
                        server_public_key = response.partition("~PK~")[2]
                        is_user = True
                        break
                    else:
                        print("Wrong password!")
                        sys.exit(0)
            else:
                sys.exit(0)
        if is_user:
            break
        elif len(username.strip()) != 0:
            response = str(username)
            client_connection.send(response.encode())
            break
        else:
            continue
    print("Type /help to display the list of available commands.")
    sys.stdout.write("> ")
    sys.stdout.flush()
    global session_cipher
    while True:
        sockets_list = [sys.stdin, client_connection]
        r, w, e = select.select(sockets_list, [], [])
        for notified_socket in r:
            if notified_socket == client_connection:
                data = client_connection.recv(BUFFER_SIZE)
                if data == b"GETADMINPASS":
                    tmp_pass = getpass("Admin Password: ")
                    client_connection.send(tmp_pass.encode())
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                elif data == b"GETUSERPASS":
                    tmp_pass = getpass("New Password: ")
                    client_connection.send(tmp_pass.encode())
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                elif data.partition(b"~SK~")[2] != b"":
                    cipher.nonce = data.partition(b"~SK~")[0]
                    session_key = cipher.decrypt(data.partition(b"~SK~")[2].partition(b"--END--")[0])
                    print("\n---NEW SESSION KEY---")
                    print(session_key)
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                elif data.partition(b"~PM~")[2] != b"":
                    session_cipher = AES.new(session_key, AES.MODE_EAX, data.partition(b"~NONCE~")[0])
                    decrypted_message = session_cipher.decrypt_and_verify(data.partition(b"~PM~")[0].partition(b"~NONCE~")[2], data.partition(b"~PM~")[2])
                    print(decrypted_message.decode())
                    sys.stdout.write("\n")
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                elif data:
                    sys.stdout.write(data.decode())
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                else:
                    print("You have been disconnected from the server!")
                    sys.exit(0)
            else:
                message = sys.stdin.readline()
                if message == '/logout\n':
                    client_connection.send("/quit".encode())
                    print("[SERVER] You have been disconnected from the server!")
                    sys.exit(0)
                elif message == '/help\n':
                    list_commands()
                    sys.stdout.write("> ")
                    sys.stdout.flush()
                elif message.partition(' ')[0] == '/private':
                    content = message.partition("> ")[2].strip().encode()
                    session_cipher = AES.new(session_key, AES.MODE_EAX)
                    encrypted_message, tag = session_cipher.encrypt_and_digest(content)
                    client_connection.send(message.partition("> ")[
                                               0].strip().encode() + "> ".encode() + session_cipher.nonce + "~NONCE~".encode() + encrypted_message + "~PM~".encode() + tag)
                    print(message.partition("> ")[
                                               0].strip().encode() + "> ".encode() + session_cipher.nonce + "~NONCE~".encode() + encrypted_message + "~PM~".encode() + tag)
                else:
                    client_connection.send(message.encode())
                    sys.stdout.write("> ")
                    sys.stdout.flush()


def list_commands():
    print("/u [username]                      - Change the username"
          "\n/p                                 - Change the password"
          "\n/c [room_name]                     - Create a new room"
          "\n/j [room_name]                     - Join a room"
          "\n/l [room_name]                     - Leave a room"
          "\n/cd [room_name]                    - Change default room"
          "\n/list                              - (Admin) List all the rooms on the server"
          "\n/users                             - (Admin) List all the users on the server"
          "\n/public <[room_name]> [message]    - Sends a message to any room you are a part of"
          "\n/private <[username]> [message]    - Send a private (encrypted) message to any user"
          "\n/logout                            - Disconnect from the server")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Please enter the server host and port number as arguments!"
              "\nUsage: python Client.py [host] [port]"
              "\nExample: python Client.py 127.0.0.1 9999")
        sys.exit(0)
    try:
        chat(sys.argv[1], sys.argv[2])
    except KeyboardInterrupt:
        print("\nClient Disconnected!")
