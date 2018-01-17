import socket
from Protocol import *
from UserFS import *
from CheckCredentials import check_credentials_lib
import argparse


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
            sock.sendall(cipher_protocol.encrypted_request_upload_file_encode(args.file))
            rec_v = sock.recv(2048)
            can_upload, port = cipher_protocol.encrypted_response_upload_file_decode(rec_v)
            print(can_upload, port)
            if port != 0:
                my_file = open(args.file, "rb").read()
                my_file_encrypted = cipher_protocol.encrypt(my_file)
                sock.sendall(cipher_protocol.encrypted_client_response_upload_file_encode(len(my_file)))
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                    # HOST = socket.gethostbyname(socket.gethostname())
                    sock2.connect((d["ip"], port))
                    sock2.send(my_file_encrypted)
                    sys.exit(0)
            else:
                sys.exit(-2)
        else:
            sys.exit(-1)
