import socket
from Protocol import *
from CheckCredentials import check_credentials_lib
import argparse
import sys


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("u", help="Username", type=str)
    parser.add_argument("psw", help="User password", type=str)
    parser.add_argument("file", help="Name of file to delete!", type=str)
    args = parser.parse_args()
    with open("server.json") as data:
        d = json.load(data)
        sock, cipher_protocol = check_credentials_lib(args.u, args.psw, d["ip"], d["port"])
        if sock != -1:
            sock.sendall(cipher_protocol.encrypted_request_download_file_encode(args.file))
            recv = sock.recv(1024)
            bFileExists, file_size, port = cipher_protocol.encrypted_response_download_file_decode(recv)
            if port != 0:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                    HOST = socket.gethostbyname(socket.gethostname())
                    sock2.connect((HOST, port))
                    my_file_encrypted = sock2.recv(2048)
                    my_file_encrypted = cipher_protocol.decrypt(my_file_encrypted)
                    file = open(args.file, "bw")
                    file.write(my_file_encrypted)
                    sys.exit(0)
            else:
                sys.exit(-2)
        else:
            sys.exit(-1)
