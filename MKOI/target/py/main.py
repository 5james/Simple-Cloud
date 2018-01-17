import socket
import random
import json
import datetime
import socketserver
import os
from DiffieHellman import DiffieHellman
from Protocol import *
from SerpentCipherClassicalString import *
from SerpentCipher import *
import Users
from UserFS import *
import logging

logging.basicConfig(
    # filename="test.log",
    level=logging.DEBUG,
    format="%(asctime)s:%(levelname)s:%(message)s"
)
logger = logging.getLogger(__name__)

MY_HOST = '192.168.43.71'
PORT_MAIN = 54047


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        logger.info('New connection from {}.'.format(self.client_address))
        self.auth()
        while True:
            try:
                recv = self.request.recv(2048)
                # check if client closed socket
                if len(recv) == 0:
                    break
                message_type, message = \
                    self.cipher_protocol.encrypted_establish_message_type(recv)
                if message_type == MessageType.LIST_FILES.value:
                    self.handle_list_request(message)

                elif message_type == MessageType.UPLOAD_FILE.value:
                    self.handle_file_upload_request(message)

                elif message_type == MessageType.GET_HASH.value:
                    self.handle_get_file_hash(message)

                elif message_type == MessageType.DOWNLOAD_FILE.value:
                    self.handle_download_file(message)

                elif message_type == MessageType.DELETE_FILE.value:
                    self.handle_delete_file(message)

                elif message_type == MessageType.LOG_OUT.value:
                    break

                else:
                    break
            except Exception:
                return
    def auth(self):
        dh = DiffieHellman()
        req_0 = self.request.recv(SECRET_LEN + HEADER_SIZE)
        clientSecret = Protocol.req_0_dh_decode(req_0)

        self.request.sendall(Protocol.res_dh_encode(dh.publicKey))
        dh.generateKey(clientSecret)
        # cipher = SerpentCipherClassicalString(BitArray(bytes=dh.symmectricKey).hex)
        cipher = SerpentCipher(BitArray(bytes=dh.symmectricKey).hex)
        self.cipher_protocol = Protocol(cipher)

        logger.info('{}: Keys generated and cipher initialized.'.format(self.client_address))

        authSuccess = False
        while not authSuccess:
            msg = self.request.recv(1024)
            username, password_sha3_512 = self.cipher_protocol.encrypted_authentication_decode(msg)
            bUserExists = Users.check_user_existence(username)
            if not bUserExists:
                logger.info('{}: Failed login attempt - user {} doesnt exist.'.format(self.client_address, username))
                self.request.sendall(self.cipher_protocol.encrypted_auth_status_encode(False))
                continue
            authSuccess = Users.check_user_password(username, password_sha3_512)
            if not authSuccess:
                logger.info(
                    '{}: Failed login attempt - bad password for user {} .'.format(self.client_address, username))
                self.request.sendall(self.cipher_protocol.encrypted_auth_status_encode(False))
                continue
            else:
                logger.info('{}: user {} successfully log on.'.format(self.client_address, username))
                self.user_fs = UserFS(username)
                self.request.sendall(self.cipher_protocol.encrypted_auth_status_encode(True))
                return True

    def handle_list_request(self, message: bytes):
        logger.info('{}:{}: requests files list.'.format(self.client_address, self.user_fs.username))
        files = self.user_fs.list_all_files()
        json_files = json.dumps(files, default=datetime_handler)
        json_bytes = self.cipher_protocol.encrypt(json_files.encode('utf-8'))
        logger.info('{}:{}: list of files prepared.'.format(self.client_address, self.user_fs.username))

        HOST = socket.gethostbyname(socket.gethostname())
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with sock:
            sock.bind((MY_HOST, 0))
            sock.listen(10)
            logger.info(
                '{}:{}: socket (port={}) for transfer list of files prepared.'.format(self.client_address,
                                                                                      self.user_fs.username,
                                                                                      sock.getsockname()[1]))
            response = self.cipher_protocol.encrypted_response_request_list_files_encode(len(json_files),
                                                                                         sock.getsockname()[1])
            self.request.sendall(response)
            logger.info('{}:{}: message with new socket port sent.'.format(self.client_address, self.user_fs.username))
            conn, addr = sock.accept()
            with conn:
                logger.info('{}:{}: new connection accepted, start sending list of files'.format(self.client_address,
                                                                                                 self.user_fs.username))
                conn.sendall(json_bytes)
                logger.info('{}:{}: list of files sent.'.format(self.client_address, self.user_fs.username))

    def handle_file_upload_request(self, message: bytes):
        filename = Protocol.request_upload_file_decode(message)
        logger.info('{}:{}: file {} upload request.'.format(self.client_address, self.user_fs.username, filename))
        try:
            can_upload = not self.user_fs.check_file_existence(filename)
        except errors.InvalidCharsInPath:
            can_upload = False

        if not can_upload:
            self.request.sendall(self.cipher_protocol.encrypted_response_upload_file_encode(False, 0))
            logger.info('{}:{}: cannot upload file {} because it already exists.'.format(self.client_address,
                                                                                         self.user_fs.username,
                                                                                         filename))
        else:
            HOST = socket.gethostbyname(socket.gethostname())
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with sock:
                sock.bind((MY_HOST, 0))
                sock.listen(10)
                logger.info(
                    '{}:{}: socket (port={}) for file uploading prepared.'.format(self.client_address,
                                                                                  self.user_fs.username,
                                                                                  sock.getsockname()[1]))
                response = self.cipher_protocol.encrypted_response_upload_file_encode(can_upload,
                                                                                      sock.getsockname()[1])
                self.request.sendall(response)
                logger.info(
                    '{}:{}: message with new socket port sent.'.format(self.client_address, self.user_fs.username))
                recv = self.request.recv(1024)
                file_size = self.cipher_protocol.encrypted_client_response_upload_file_decode(recv)
                if file_size % 16 != 0:
                    encrypted_file_size = file_size + (16 - (file_size % 16))
                else:
                    encrypted_file_size = file_size
                # encrypted_file_size = file_size + (BYTES_IN_SINGLE_CHUNK -(file_size % BYTES_IN_SINGLE_CHUNK))

                conn, addr = sock.accept()
                with conn:
                    logger.info(
                        '{}:{}: new connection accepted, start receiving new file {}.'.format(self.client_address,
                                                                                              self.user_fs.username,
                                                                                              filename))
                    file = b''
                    while len(file) < encrypted_file_size:
                        packet = conn.recv(encrypted_file_size - len(file))
                        if not packet:
                            return None
                        file += packet

                    # file = conn.recv(encrypted_file_size)
                    self.user_fs.save_file_from_bytes(filename, self.cipher_protocol.decrypt(file)[:file_size])
                    # print(file)
                    logger.info('{}:{}: file {} receiver.'.format(self.client_address, self.user_fs.username, filename))
                    conn.close()
                sock.close()

    def handle_get_file_hash(self, message):
        filename = Protocol.request_file_hash_decode(message)
        logger.info('{}:{}: file {} hash request.'.format(self.client_address, self.user_fs.username, filename))
        try:
            file_hash = self.user_fs.hash_sha3_512(filename)
            self.request.sendall(self.cipher_protocol.encrypted_response_file_hash_encode(True, file_hash))
            logger.info('{}:{}: sent hash of file {}.'.format(self.client_address, self.user_fs.username, filename))

        except FileDoesNotExistsException:
            logger.info('{}:{}: file {} does not exist.'.format(self.client_address, self.user_fs.username, filename))
            self.request.sendall(self.cipher_protocol.encrypted_response_file_hash_encode(False))

    def handle_download_file(self, message: bytes):
        filename = self.cipher_protocol.request_download_file_decode(message)
        logger.info('{}:{}: file {} download request.'.format(self.client_address, self.user_fs.username, filename))
        try:
            file_bytes = self.user_fs.get_file_as_bytes(filename)
            # print(len(file_bytes))
            encrypted_file = self.cipher_protocol.encrypt(file_bytes)
            # print(len(encrypted_file))

            HOST = socket.gethostbyname(socket.gethostname())
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            with sock:
                sock.bind((MY_HOST, 0))
                sock.listen(10)
                logger.info('{}:{}: socket (port={}) for file download prepared.'.format(self.client_address,
                                                                                         self.user_fs.username,
                                                                                         sock.getsockname()[1]))
                response = self.cipher_protocol.encrypted_response_download_file_encode(True,
                                                                                        len(file_bytes),
                                                                                        sock.getsockname()[1])
                self.request.sendall(response)
                logger.info(
                    '{}:{}: message with new socket port sent.'.format(self.client_address, self.user_fs.username))
                conn, addr = sock.accept()
                with conn:
                    logger.info(
                        '{}:{}: new connection accepted, start sending new file {}.'.format(self.client_address,
                                                                                            self.user_fs.username,
                                                                                            filename))
                    conn.sendall(encrypted_file)
                    logger.info('{}:{}: file {} sent.'.format(self.client_address, self.user_fs.username, filename))
                    conn.close()
                sock.close()

        except FileDoesNotExistsException:
            logger.info('{}:{}: file {} doesnt exist.'.format(self.client_address, self.user_fs.username, filename))
            self.request.sendall(self.cipher_protocol.encrypted_response_download_file_encode(False))

    def handle_delete_file(self, message: bytes):
        filename = self.cipher_protocol.request_delete_file_decode(message)
        logger.info('{}:{}: file {} delete request.'.format(self.client_address, self.user_fs.username, filename))
        bDidDelete = self.user_fs.delete_file(filename)
        response = self.cipher_protocol.encrypted_response_delete_file_encode(bDidDelete)
        self.request.sendall(response)
        logger.info('{}:{}: response {} sent.'.format(self.client_address, self.user_fs.username, str(bDidDelete)))


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
        req_0 = Protocol.req_0_dh_encode(dh.publicKey)
        sock.sendall(req_0)
        recv = sock.recv(SECRET_LEN)
        secret = Protocol.res_dh_decode(recv)
        dh.generateKey(secret)
        cipher = SerpentCipher(BitArray(bytes=dh.symmectricKey).hex)
        cipher_protocol = Protocol(cipher)
        auth_msg = cipher_protocol.encrypted_authentication_encode('johny', '123456')
        sock.sendall(auth_msg)
        recv = sock.recv(1024)
        didSucceed = cipher_protocol.encrypted_auth_status_decode(recv)
        if didSucceed:
            print('Udalo sie zalogowac')

        to_send = cipher_protocol.encrypted_request_list_files_encode()
        sock.sendall(to_send)
        recv = sock.recv(2048)
        json_size, port = cipher_protocol.encrypted_response_request_list_files_decode(recv)
        if json_size % 128 != 0:
            json_size_to_recv = json_size + (128 - (json_size % 128))
        else:
            json_size_to_recv = json_size
        # print(port)
        if port != 0:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                HOST = socket.gethostbyname(socket.gethostname())
                sock2.connect((HOST, port))
                recv = sock2.recv(json_size_to_recv)
                print('lista plików w json: {}'.format(cipher_protocol.decrypt(recv).decode('utf-8')[:json_size]))
                sock2.close()

        sock.sendall(cipher_protocol.encrypted_request_upload_file_encode('test4.txt'))
        recv = sock.recv(2048)
        can_upload, port = cipher_protocol.encrypted_response_upload_file_decode(recv)
        print(can_upload, port)
        if port != 0:
            myfile = b'12341234'
            myfile_encrypted = cipher_protocol.encrypt(myfile)
            sock.sendall(cipher_protocol.encrypted_client_response_upload_file_encode(len(myfile)))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                HOST = socket.gethostbyname(socket.gethostname())
                sock2.connect((HOST, port))
                sock2.send(myfile_encrypted)
                print('Udalo sie wyslac plik test4.txt: {}'.format(myfile))

        sock.sendall(cipher_protocol.encrypted_request_file_hash_encode('test.txt'))
        recv = sock.recv(1024)
        bFileExists, file_hash = cipher_protocol.encrypted_response_file_hash_decode(recv)
        print('Plik istenieje: {}, jego hash: {}'.format(bFileExists, file_hash))

        sock.sendall(cipher_protocol.encrypted_request_download_file_encode('test4.txt'))
        recv = sock.recv(1024)
        bFileExists, file_size, port = cipher_protocol.encrypted_response_download_file_decode(recv)
        print(file_size)
        if port != 0:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                HOST = socket.gethostbyname(socket.gethostname())
                sock2.connect((HOST, port))
                myfile_encrypted = sock2.recv(2048)
                myfile_encrypted = cipher_protocol.decrypt(myfile_encrypted)
                print('Pobrano plik test4.txt: {}'.format(myfile_encrypted[:file_size]))

        sock.sendall(cipher_protocol.encrypted_request_delete_file_encode('test4.txt'))
        recv = sock.recv(1024)
        bDidDelete = cipher_protocol.encrypted_response_delete_file_decode(recv)
        if bDidDelete:
            print('Udalo sie usunac plik')

        sock.close()


if __name__ == "__main__":
    # Port 0 means to select an arbitrary unused port
    HOST, PORT = MY_HOST, PORT_MAIN

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

        # client(ip, port)

        server_thread.join()
        # server.shutdown()
