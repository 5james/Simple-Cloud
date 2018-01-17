import socket
#import sys
#from CheckCredentials import check_credentials_lib
import argparse
from DiffieHellman import DiffieHellman
from Protocol import *
from SerpentCipherClassicalString import *
from SerpentCipher import *
from UserFS import *


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("u", help="Username", type=str)
    parser.add_argument("psw", help="User password", type=str)
    args = parser.parse_args()
    with open("server.json") as data:
        d = json.load(data)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((d["ip"], d["port"]))

            dh = DiffieHellman()
            req_0 = Protocol.req_0_dh_encode(dh.publicKey)
            sock.sendall(req_0)
            recv = sock.recv(SECRET_LEN)
            secret = Protocol.res_dh_decode(recv)
            dh.generateKey(secret)
            cipher = SerpentCipherClassicalString(BitArray(bytes=dh.symmectricKey).hex)
            cipher_protocol = Protocol(cipher)
            auth_msg = cipher_protocol.encrypted_authentication_encode(args.u, args.psw)
            sock.sendall(auth_msg)
            recv = sock.recv(1024)
            did_succeed = cipher_protocol.encrypted_auth_status_decode(recv)

        #(sock, cipher_protocol) = check_credentials_lib(args.u, args.psw, d["ip"], d["port"])
            #if sock != -1:
            to_send = cipher_protocol.encrypted_request_list_files_encode()
            sock.sendall(to_send)
            rec_v = sock.recv(2048)
            json_size, port = cipher_protocol.encrypted_response_request_list_files_decode(rec_v)
            if port != 0:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock2:
                    # HOST = socket.gethostbyname(socket.gethostname())
                    sock2.connect((d["ip"], port))
                    recv = sock2.recv(json_size)
                    print(cipher_protocol.decrypt(recv).decode('utf-8')[:json_size])
                    sock2.close()
                    sys.exit(0)
            else:
                sys.exit(-2)
        #else:
        #    files = open("files.json").read()
        #    print(files)
        #    sys.exit(0)
