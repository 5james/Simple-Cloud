import socket
import threading
import socketserver
import random
from DiffieHellman import DiffieHellman
from Protocol import Protocol, MessageType


class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):

        while True:
            length = self.receive_message_len()
            # check if client closed socket
            if length == 0:
                break
            self.ack_message_len(length)
            self.receive_message(length)

    def receive_message(self, length: int):
        data_recv = bytes(self.request.recv(length))
        data_str = str(data_recv.decode('ascii'))
        msg_type, data = Protocol.decoder(data_str)
        if msg_type == MessageType.LOG_IN.value:
            self.proceed_connecting(data)

    def receive_message_len(self) -> int:
        data = bytes(self.request.recv(Protocol.get_message_size()))
        try:
            return int(data)
        except:
            return 0
            # data = bytes()
            # data_recv = bytes(self.request.recv(Protocol.get_message_size()))
            # if len(data_recv) > 0:
            #     data += data_recv
            #     if len(data) < Protocol.get_message_size():
            #         continue
            #     else:
            #         message = self.receive_message(int(data))
            # elif len(data_recv) == 0:
            #     break
            # elif len(data_recv) < 0:
            #     raise Exception('Socket error')

    def ack_message_len(self, length: int):
        response = bytes("{}".format(length), 'ascii')
        self.request.sendall(response)

    def proceed_connecting(self, data_json):
        self.diffie_hellman = DiffieHellman()
        self.diffie_hellman.generateKey(collaborator_key=data_json['key'])
        message_len, message = Protocol.connect_encode(self.diffie_hellman.publicKey)
        # send message_length
        response_len = bytes("{}".format(message_len), 'ascii')
        self.request.sendall(response_len)

        # get ack
        ack = bytes(self.request.recv(len(response_len)))
        if ack != response_len:
            raise Exception('bad ack')

        response = bytes("{}".format(message), 'ascii')
        self.request.sendall(response)

        print(self.diffie_hellman.symmectricKey)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def client(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))

        dh = DiffieHellman()
        session_id = random.getrandbits(64)
        username = 'james'

        # message_len, message_connect = Protocol.connect_encode(dh.publicKey)
        # sock.sendall(bytes(message_len, 'ascii'))
        # ack = str(sock.recv(64), 'ascii')
        # sock.sendall(bytes(message_connect, 'ascii'))
        #
        # response_len = str(sock.recv(64), 'ascii')
        # sock.sendall(bytes(response_len, 'ascii'))
        # response = str(sock.recv(int(response_len)), 'ascii')
        # msg_type, response = Protocol.decoder(response)
        # key = response['key']
        # dh.generateKey(key)
        # sym_key = dh.symmectricKey
        # print(sym_key)
        # print(response_key)
        # print("Received: {}".format(response))
        # sock.sendall(bytes(message, 'ascii'))
        # response = str(sock.recv(1024), 'ascii')
        # print("Received: {}".format(response))
        # sock.sendall(bytes(message, 'ascii'))
        # response = str(sock.recv(1024), 'ascii')
        # print("Received: {}".format(response))
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
