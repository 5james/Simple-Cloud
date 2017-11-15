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


# TODO: uporządkować session_ids i request_ids


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        bAuthSuccessful = self.auth()
        if bAuthSuccessful:
            while True:
                recv = self.request.recv(2048)
                # check if client closed socket
                if len(recv) == 0:
                    break
                req_session_id, request_id, message_type, message = \
                    self.cipher_protocol.encrypted_establish_message_type(recv)
                if req_session_id != self.session_id:
                    print('+{}\n+{}'.format(str(req_session_id), str(self.session_id)))
                    break

                if message_type == MessageType.LIST_FILES.value:
                    self.handle_list_request(request_id, message)

                elif message_type == MessageType.UPLOAD_FILE.value:
                    self.handle_file_upload_request(request_id, message)

                elif message_type == MessageType.GET_HASH.value:
                    self.handle_get_file_hash(request_id, message)

                elif message_type == MessageType.DOWNLOAD_FILE.value:
                    self.handle_download_file(request_id, message)

                elif message_type == MessageType.DELETE_FILE.value:
                    self.handle_delete_file(request_id, message)

                elif message_type == MessageType.LOG_OUT.value:
                    break

                else:
                    break

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
        self.request.sendall(response)
        self.user_fs = UserFS(username)
        return True

    def handle_list_request(self, request_id: bytes, message: bytes):
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
            self.request.sendall(response)

            conn, addr = sock.accept()
            with conn:
                conn.sendall(json_bytes)

    def handle_file_upload_request(self, request_id: bytes, message: bytes):
        filename = Protocol.request_upload_file_decode(message)
        try:
            can_upload = not self.user_fs.check_file_existence(filename)
        except errors.InvalidCharsInPath:
            can_upload = False

        if not can_upload:
            self.request.sendall(self.cipher_protocol.encrypted_response_upload_file_encode(request_id, False, 0))
        else:
            HOST = socket.gethostbyname(socket.gethostname())
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with sock:
                sock.bind((HOST, 0))
                sock.listen(10)
                response = self.cipher_protocol.encrypted_response_upload_file_encode(request_id, can_upload,
                                                                                      sock.getsockname()[1])
                # print(sock.getsockname()[1])
                self.request.sendall(response)

                recv = self.request.recv(1024)
                request_id, file_size = self.cipher_protocol.encrypted_client_response_upload_file_decode(recv)

                conn, addr = sock.accept()
                with conn:
                    file = conn.recv(file_size)
                    self.user_fs.save_file_from_bytes(filename, self.cipher_protocol.decrypt(file))
                    # print(file)
                    conn.close()
                sock.close()

    def handle_get_file_hash(self, request_id: bytes, message):
        filename = Protocol.request_file_hash_decode(message)
        try:
            file_hash = self.user_fs.hash_sha3_512(filename)
            self.request.sendall(self.cipher_protocol.encrypted_response_file_hash_encode(request_id, True, file_hash))

        except FileDoesNotExistsException:
            self.request.sendall(self.cipher_protocol.encrypted_response_file_hash_encode(request_id, False))

    def handle_download_file(self, request_id: bytes, message: bytes):
        filename = self.cipher_protocol.request_download_file_decode(message)
        try:
            file_bytes = self.user_fs.get_file_as_bytes(filename)
            encrypted_file = self.cipher_protocol.encrypt(file_bytes)

            HOST = socket.gethostbyname(socket.gethostname())
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with sock:
                sock.bind((HOST, 0))
                sock.listen(10)
                response = self.cipher_protocol.encrypted_response_download_file_encode(request_id, True,
                                                                                        len(file_bytes),
                                                                                        sock.getsockname()[1])
                # print(sock.getsockname()[1])
                self.request.sendall(response)

                conn, addr = sock.accept()
                with conn:
                    conn.sendall(encrypted_file)
                    conn.close()
                sock.close()

        except FileDoesNotExistsException:
            self.request.sendall(self.cipher_protocol.encrypted_response_download_file_encode(request_id, False))

    def handle_delete_file(self, request_id: bytes, message: bytes):
        filename = self.cipher_protocol.request_delete_file_decode(message)
        bDidDelete = self.user_fs.delete_file(filename)
        response = self.cipher_protocol.encrypted_response_delete_file_encode(request_id, bDidDelete)
        self.request.sendall(response)


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
        # print(port)
        if port != 0:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                HOST = socket.gethostbyname(socket.gethostname())
                sock2.connect((HOST, port))
                recv = sock2.recv(json_size)
                # print(cipher_protocol.decrypt(recv))
                sock2.close()

        sock.sendall(cipher_protocol.encrypted_request_upload_file_encode(session_id, bytearray(
            random.getrandbits(8) for i in range(64)), 'test4.txt'))
        recv = sock.recv(2048)
        request_id, can_upload, port = cipher_protocol.encrypted_response_upload_file_decode(recv)
        # print(can_upload)
        # print(port)
        # print(session_id)

        if port != 0:
            myfile = b'12341234'
            myfile = cipher_protocol.encrypt(myfile)
            sock.sendall(cipher_protocol.encrypted_client_response_upload_file_encode(request_id, len(myfile)))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                HOST = socket.gethostbyname(socket.gethostname())
                sock2.connect((HOST, port))
                sock2.send(myfile)
                # print(myfile)

        sock.sendall(cipher_protocol.encrypted_request_file_hash_encode(session_id, bytearray(
            random.getrandbits(8) for i in range(64)), 'test.txt'))

        # print(session_id)

        recv = sock.recv(1024)

        request_id, bFileExists, file_hash = cipher_protocol.encrypted_response_file_hash_decode(recv)
        # print(bFileExists)
        # print(file_hash)

        sock.sendall(cipher_protocol.encrypted_request_download_file_encode(session_id, bytearray(
            random.getrandbits(8) for i in range(64)), 'test.txt'))

        recv = sock.recv(1024)
        request_id_new, bFileExists, file_size, port = cipher_protocol.encrypted_response_download_file_decode(recv)

        if port != 0:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                HOST = socket.gethostbyname(socket.gethostname())
                sock2.connect((HOST, port))
                myfile = sock2.recv(2048)
                myfile = cipher_protocol.decrypt(myfile)
                # print(myfile[:file_size])

        sock.sendall(cipher_protocol.encrypted_request_delete_file_encode(session_id, bytearray(
            random.getrandbits(8) for i in range(64)), 'test4.txt'))

        recv = sock.recv(1024)
        request_id_new, bDidDelete = cipher_protocol.encrypted_response_delete_file_decode(recv)
        # print(bDidDelete)



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
