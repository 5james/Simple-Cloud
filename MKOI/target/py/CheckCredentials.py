import socket
from DiffieHellman import DiffieHellman
from Protocol import *
from SerpentCipherClassicalString import *
from SerpentCipher import *
from UserFS import *
import argparse
import json


def check_credentials(username, password, ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))

        dh = DiffieHellman()
        req_0 = Protocol.req_0_dh_encode(dh.publicKey)
        sock.sendall(req_0)
        rec_v = sock.recv(SECRET_LEN)
        secret = Protocol.res_dh_decode(rec_v)
        dh.generateKey(secret)
        cipher = SerpentCipherClassicalString(BitArray(bytes=dh.symmectricKey).hex)
        cipher_protocol = Protocol(cipher)
        auth_msg = cipher_protocol.encrypted_authentication_encode(username, password)
        sock.sendall(auth_msg)
        rec_v = sock.recv(1024)
        did_succeed = cipher_protocol.encrypted_auth_status_decode(rec_v)

        if did_succeed:
            return 0
        else:
            return -1


def check_credentials_lib(username, password, ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, port))

        dh = DiffieHellman()
        req_0 = Protocol.req_0_dh_encode(dh.publicKey)
        sock.sendall(req_0)
        recv = sock.recv(SECRET_LEN)
        secret = Protocol.res_dh_decode(recv)
        dh.generateKey(secret)
        cipher = SerpentCipherClassicalString(BitArray(bytes=dh.symmectricKey).hex)
        cipher_protocol = Protocol(cipher)
        auth_msg = cipher_protocol.encrypted_authentication_encode(username, password)
        sock.sendall(auth_msg)
        recv = sock.recv(1024)
        did_succeed = cipher_protocol.encrypted_auth_status_decode(recv)

        if did_succeed:
            return (sock, cipher_protocol)
        else:
            return (-1, -1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("u", help="Username", type=str)
    parser.add_argument("psw", help="User password", type=str)
    args = parser.parse_args()
    with open("server.json") as data:
        d = json.load(data)
        if check_credentials(args.u, args.psw, d["ip"], d["port"]) == 0:
            sys.exit(0)
        else:
            sys.exit(-1)
