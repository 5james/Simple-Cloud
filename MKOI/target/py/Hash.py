from Protocol import *
from UserFS import *
from CheckCredentials import check_credentials_lib
import argparse
import hashlib

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
            sock.sendall(cipher_protocol.encrypted_request_file_hash_encode(args.file))
            rec_v = sock.recv(1024)
            bFileExists, file_hash = cipher_protocol.encrypted_response_file_hash_decode(rec_v)
            if bFileExists:
                print(file_hash)
                sys.exit(0)
            else:
                sys.exit(-2)
        else:
            print(hashlib.sha256(args.file.encode('utf-8')).hexdigest())
            sys.exit(0)
