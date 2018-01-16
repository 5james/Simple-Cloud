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
            sock.sendall(cipher_protocol.encrypted_request_delete_file_encode(args.file))
            rec_v = sock.recv(1024)
            bDidDelete = cipher_protocol.encrypted_response_delete_file_decode(rec_v)
            if bDidDelete:
                sys.exit(0)
            else:
                sys.exit(-2)
        else:
            sys.exit(-1)
