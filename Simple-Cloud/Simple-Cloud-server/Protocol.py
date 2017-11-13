import json
from enum import Enum
import random
import os
import hashlib


# TODO: get exceptions right

class MessageType(Enum):
    LOG_IN = 0


# message_length_size_bit = 64
# message_length_size_byte = 8
MAX_LEN_USERNAME = 64
LEN_SESSION_ID = 64
SECRET_LEN = 64
SHA_512_LEN = 64


class Protocol:
    @staticmethod
    def req_0_encode(username: str) -> bytes:
        # if len(session_id) != LEN_SESSION_ID:
        #     raise Exception('Bad length of session_id')
        if len(username) > MAX_LEN_USERNAME:
            raise Exception('Too long username')
        message = bytes()
        # message += session_id
        message += MessageType.LOG_IN.value.to_bytes(1, byteorder='big')
        username_bytes = username.encode('utf-8')
        # username_bytes_len = len(username_bytes)
        # len_diff = MAX_LEN_USERNAME - username_bytes_len
        # username_bytes += b'\x00' * len_diff
        message += username_bytes.ljust(MAX_LEN_USERNAME, b'\x00')
        return message

    @staticmethod
    def req_0_decode(message_bytes: bytes) -> (bytes, str):
        if len(message_bytes) != Protocol.req_0_len():
            raise Exception('Bad message length')
        # session_id = message_bytes[0:64]
        if message_bytes[0:1] != MessageType.LOG_IN.value.to_bytes(1, byteorder='big'):
            raise Exception('Wrong message!')
        username = str(message_bytes[1:65])
        return session_id, username

    @staticmethod
    def req_0_len() -> int:
        return MAX_LEN_USERNAME + 1

    @staticmethod
    def username_status_encode(did_succeed: bool) -> bytes:
        if did_succeed:
            return b'\x00'
        else:
            return b'\x11'

    @staticmethod
    def username_status_decode(did_succeed_byte: bytes) -> bool:
        if len(did_succeed_byte) != Protocol.username_status_len():
            raise Exception('Wrong message length')
        if did_succeed_byte == b'\x00':
            return True
        elif did_succeed_byte == b'\x11':
            return False
        else:
            raise Exception('Wrong login status')

    @staticmethod
    def username_status_len() -> int:
        return 1

    @staticmethod
    def dh_encode(secret: bytes) -> bytes:
        if len(secret) != Protocol.dh_len:
            raise Exception('Wrong secret key length')
        return secret

    @staticmethod
    def dh_decode(message: bytes) -> bytes:
        if len(message) != Protocol.dh_len:
            raise Exception('Bad message length')
        return message

    @staticmethod
    def dh_len():
        return SECRET_LEN

    @staticmethod
    def passwd_encode(password: str) -> bytes:
        if len(password) > Protocol.passwd_len():
            raise Exception('Password is too long')
        pwd_sha_512 = hashlib.sha3_512(password.encode('utf-8')).digest()
        return pwd_sha_512

    @staticmethod
    def passwd_decode(password_sha_512_bytes: bytes) -> bytes:
        if len(password_sha_512_bytes) != Protocol.passwd_len():
            raise Exception('Bad password length')
        return password_sha_512_bytes

    @staticmethod
    def passwd_len():
        return SHA_512_LEN

    @staticmethod
    def auth_status_encode(auth_success: bool, session_id: bytes) -> bytes:
        if len(session_id) != LEN_SESSION_ID:
            raise Exception('Wrong session ID length')
        message = bytes()
        if auth_success:
            message += b'\x00'
        else:
            message += b'\x11'
        message += session_id
        return message

    @staticmethod
    def auth_status_decode(message: bytes) -> (bool, bytes):
        if len(message) != Protocol.auth_status_len():
            raise Exception('Wrong message length')
        auth_status_byte = message[0:1]
        if auth_status_byte == b'\x00':
            auth_status = True
        elif auth_status_byte == b'\x11':
            auth_status = False
        else:
            raise Exception('Wrong login status')
        session_id = message[1:65]
        return auth_status, session_id

    @staticmethod
    def auth_status_len():
        return 1 + LEN_SESSION_ID




            # @staticmethod
            # def dh_1_encode(secret: bytes) -> bytes:
            #     return secret
            #
            # @staticmethod
            # def dh_1_decode(message: bytes) -> bytes:
            #     return message
            #
            # @staticmethod
            # def dh_1_len():
            #     return SECRET_LEN
            #
            # @staticmethod
            # def dh_2_encode(secret: bytes) -> bytes:
            #     message = bytes()
            #     # message += session_id
            #     message += secret
            #     return message
            #
            # @staticmethod
            # def dh_2_decode(message: bytes) -> bytes:
            #     return message
            #
            # @staticmethod
            # def dh_2_len():
            #     return LEN_SESSION_ID+SECRET_LEN
            #
            # @staticmethod
            # def connect_encode(key) -> (str, str):
            #     if key is None:
            #         raise Exception("No key input")
            #     data_python = {'message_type': MessageType.LOG_IN.value, 'key': key}
            #     data_json = json.dumps(data_python)
            #     message_length = Protocol.__message_length_encode(len(data_json))
            #     return message_length, data_json
            #
            # @staticmethod
            # def decoder(message: str) -> (int, dict):
            #     try:
            #         parsed_json = json.loads(message)
            #         if parsed_json['message_type'] == MessageType.LOG_IN.value:
            #             return Protocol._connect_decode(parsed_json)
            #     except:
            #         raise Exception('Bad json encoding')
            #
            # @staticmethod
            # def _connect_decode(parsed_json) -> (int, dict):
            #     if 'key' not in parsed_json:
            #         raise Exception('Lack of data in json')
            #     return parsed_json['message_type'], parsed_json
            #
            # @staticmethod
            # def __message_length_encode(length: int) -> bytes:
            #     # length_str = str(length)
            #     # # if length of string containing length of sending message > 64 then Exception
            #     # if len(length_str) > message_length_size:
            #     #     raise Exception("Too large message")
            #     # return length_str
            #     try:
            #         length_bytes = length.to_bytes(message_length_size_byte, byteorder='big', signed=False)
            #         return length_bytes
            #     except OverflowError:
            #         raise Exception('Tried to send message bigger than 2^64b')
            #
            # @staticmethod
            # def message_length_decode(length_bytes: bytes) -> int:
            #     length = int.from_bytes(length_bytes, byteorder='big', signed=False)
            #     return length
            #
            # @staticmethod
            # def get_message_size():
            #     return message_length_size_byte


if __name__ == "__main__":
    session_id = bytearray(random.getrandbits(8) for i in range(64))
    username = 'james'
    m1 = Protocol.req_0_encode(username)
    # print(m1)
    print(len(m1) == Protocol.req_0_len())
    username_2 = Protocol.req_0_decode(m1)
    if username == username:
        print('OK')
