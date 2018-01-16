import socket
import sys
from CheckCredentials import check_credentials_lib
import argparse
import json


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("u", help="Username", type=str)
    parser.add_argument("psw", help="User password", type=str)
    args = parser.parse_args()
    with open("server.json") as data:
        d = json.load(data)
        sock, cipher_protocol = check_credentials_lib(args.u, args.psw, d["ip"], d["port"])
        if sock != -1:
            to_send = cipher_protocol.encrypted_request_list_files_encode()
            sock.sendall(to_send)
            rec_v = sock.recv(2048)
            json_size, port = cipher_protocol.encrypted_response_request_list_files_decode(rec_v)
            if port != 0:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                    HOST = socket.gethostbyname(socket.gethostname())
                    sock2.connect((HOST, port))
                    recv = sock2.recv(json_size)
                    print(format(cipher_protocol.decrypt(recv)))
                    sock2.close()
                    sys.exit(0)
            else:
                sys.exit(-2)
        else:
            files = open("files.json").read()
            print(files)
            sys.exit(0)
