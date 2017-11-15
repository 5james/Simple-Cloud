import socket
import random
import json
import datetime
import socketserver
import os
from DiffieHellman import DiffieHellman
from Protocol import *
from SerpentCipherClassicalString import *
import Users
from UserFS import *

session_ids_lock = threading.Condition()
session_ids = set()


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        bAuthSuccessful = self.auth()
        if bAuthSuccessful:
            while True:
                recv = self.request.recv(2048)
                # check if client closed socket
                if len(recv) == 0:
                    break
                message_type, request_id, message = self.cipher_protocol.encrypted_establish_message_type(recv)
                if message_type == MessageType.LIST_FILES.value:
                    self.handle_list_request(request_id)

    def auth(self) -> bool:
        req_0 = self.request.recv(Protocol.req_0_len())
        username = Protocol.hello_decode(req_0)
        # print(username)
        bUserExists = Users.check_user_existence(username)
        self.request.sendall(Protocol.username_status_encode(bUserExists))
        if not bUserExists:
            return False
        dh = DiffieHellman()
        self.request.sendall(Protocol.dh_encode(dh.publicKey))

        client_pubKey_bytes = self.request.recv(Protocol.dh_len())
        client_pubKey = Protocol.dh_decode(client_pubKey_bytes)
        dh.generateKey(client_pubKey)
        cipher = SerpentCipherClassicalString(BitArray(bytes=dh.symmectricKey).hex)
        self.cipher_protocol = Protocol(cipher)

        pwd = self.cipher_protocol.encrypted_passwd_decode(self.request.recv(256))
        bPasswordIsCorrect = Users.check_user_password(username, pwd)
        if not bPasswordIsCorrect:
            return False
        with session_ids_lock:
            session_id = os.urandom(64)
            while session_id in session_ids:
                session_id = os.urandom(64)
            session_ids.add(session_id)
            self.session_id = session_id
        response = self.cipher_protocol.encrypted_auth_status_encode(True, self.session_id)
        # print(response)
        self.request.sendall(response)
        self.user_fs = UserFS(username)
        return True

    def handle_list_request(self, request_id: bytes):
        files = self.user_fs.list_all_files()
        json_files = json.dumps(files, default=datetime_handler)
        # json_bytes = self.cipher_protocol.encrypt(json_files.encode('utf-8'))
        json_bytes = self.cipher_protocol.encrypt(json_files.encode('utf-8'))

        HOST = socket.gethostbyname(socket.gethostname())
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with sock:
            sock.bind((HOST, 0))
            sock.listen(10)
            response = self.cipher_protocol.encrypted_response_request_list_files_encode(request_id, len(json_bytes),
                                                                                         sock.getsockname()[1])
            print(sock.getsockname()[1])
            # print(response)
            self.request.sendall(response)

            conn, addr = sock.accept()
            with conn:
                conn.sendall(json_bytes)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def datetime_handler(x):
    if isinstance(x, datetime.datetime):
        return x.isoformat()
    raise TypeError("Unknown type")


def client(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))

        dh = DiffieHellman()
        username = 'johny'
        req_0 = Protocol.hello_encode(username)
        sock.sendall(req_0)

        bUsernameExists = sock.recv(Protocol.username_status_len())
        usernameExists = Protocol.username_status_decode(bUsernameExists)
        # print(usernameExists)

        server_pubKey_bytes = sock.recv(Protocol.dh_len())
        server_pubKey = Protocol.dh_decode(server_pubKey_bytes)

        sock.sendall(Protocol.dh_encode(dh.publicKey))

        dh.generateKey(server_pubKey)
        cipher = SerpentCipherClassicalString(BitArray(bytes=dh.symmectricKey).hex)
        cipher_protocol = Protocol(cipher)

        sock.sendall(cipher_protocol.encrypted_passwd_encode('123456'))

        recv = sock.recv(2048)
        bSuccess, session_id = cipher_protocol.encrypted_auth_status_decode(recv)
        # print(bSuccess)
        # print(session_id)

        to_send = cipher_protocol.encrypted_request_list_files_encode(session_id, bytearray(
            random.getrandbits(8) for i in range(64)))
        # print(to_send)
        sock.sendall(to_send)

        recv = sock.recv(2048)
        request_id, json_size, port = cipher_protocol.encrypted_response_request_list_files_decode(recv)
        print(port)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
            HOST = socket.gethostbyname(socket.gethostname())
            sock2.connect((HOST, port))
            recv = sock2.recv(json_size)
            print(cipher_protocol.decrypt(recv))
            sock2.close()

        sock.close()


if __name__ == "__main__":
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = "localhost", 0

    server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
    with server:
        ip, port = server.server_address

        # Start a thread with the server -- that thread will then start one
        # more thread for each request
        server_thread = threading.Thread(target=server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        print("Server loop running in thread:", server_thread.name)

        client(ip, port)

        # server.shutdown()
