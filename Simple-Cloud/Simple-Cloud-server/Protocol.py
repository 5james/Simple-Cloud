import json
from enum import Enum
import random
import re
import hashlib
from SerpentCipherClassicalString import *


# TODO: get exceptions right

class MessageType(Enum):
    LOG_IN = 0
    LIST_FILES = 1


# message_length_size_bit = 64
# message_length_size_byte = 8
MAX_LEN_USERNAME = 64
LEN_SESSION_ID = 64
LEN_REQUEST_ID = 64
SECRET_LEN = 768
SHA_512_LEN = 64
MAX_JSON_SIZE = 8
MAX_PORT_SIZE = 2


class Protocol:
    def __init__(self, cipher: SerpentCipherClassicalString):
        self.cipher = cipher

    @staticmethod
    def hello_encode(username: str) -> bytes:
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
    def hello_decode(message_bytes: bytes) -> str:
        if len(message_bytes) != Protocol.req_0_len():
            raise Exception('Bad message length')
        # session_id = message_bytes[0:64]
        if message_bytes[0:1] != MessageType.LOG_IN.value.to_bytes(1, byteorder='big'):
            raise Exception('Wrong message!')
        username = message_bytes[1:65].decode('utf-8')
        username = re.sub(r'\W', "", username)
        return username

    @staticmethod
    def req_0_len() -> int:
        return MAX_LEN_USERNAME + 1

    @staticmethod
    def username_status_encode(did_succeed: bool) -> bytes:
        if did_succeed:
            return b'\x00'
        else:
            return b'\xFF'

    @staticmethod
    def username_status_decode(did_succeed_byte: bytes) -> bool:
        if len(did_succeed_byte) != Protocol.username_status_len():
            raise Exception('Wrong message length')
        if did_succeed_byte == b'\x00':
            return True
        elif did_succeed_byte == b'\xFF':
            return False
        else:
            raise Exception('Wrong login status')

    @staticmethod
    def username_status_len() -> int:
        return 1

    @staticmethod
    def dh_encode(secret: int) -> bytes:
        if secret > _max_unsigned_int(Protocol.dh_len() * 8):
            raise Exception('secret is too big')
        bPubKey = secret.to_bytes(Protocol.dh_len(), byteorder='big')
        return bPubKey

    @staticmethod
    def dh_decode(message: bytes) -> int:
        # if len(message) != Protocol.dh_len:
        #     raise Exception('Bad message length')
        return int.from_bytes(message, byteorder='big')

    @staticmethod
    def dh_len():
        return SECRET_LEN

    @staticmethod
    def passwd_encode(password: str) -> bytes:
        if len(password) > Protocol.passwd_len():
            raise Exception('Password is too long')
        pwd_sha_512 = hashlib.sha3_512(password.encode('utf-8')).digest()
        return pwd_sha_512

    def encrypted_passwd_encode(self, password: str) -> bytes:
        return self.cipher.encrypt_bytes(self.passwd_encode(password))

    @staticmethod
    def passwd_decode(password_sha_512_bytes: bytes) -> bytes:
        if len(password_sha_512_bytes) != Protocol.passwd_len():
            raise Exception('Bad password length')
        return password_sha_512_bytes

    def encrypted_passwd_decode(self, encrypted_password_sha_512_bytes: bytes) -> bytes:
        return self.passwd_decode(self.cipher.decrypt_bytes(encrypted_password_sha_512_bytes))

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
            message += b'\xFF'
        message += session_id
        return message

    def encrypted_auth_status_encode(self, auth_success: bool, session_id: bytes) -> bytes:
        return self.cipher.encrypt_bytes(self.auth_status_encode(auth_success, session_id))

    @staticmethod
    def auth_status_decode(message: bytes) -> (bool, bytes):
        # if len(message) != Protocol.auth_status_len():
        #     raise Exception('Wrong message length')
        auth_status_byte = message[0:1]
        if auth_status_byte == b'\x00':
            auth_status = True
        elif auth_status_byte == b'\xFF':
            auth_status = False
        else:
            raise Exception('Wrong login status')
        session_id = message[1:65]
        return auth_status, session_id

    def encrypted_auth_status_decode(self, encrypted_message: bytes) -> (bool, bytes):
        return self.auth_status_decode(self.cipher.decrypt_bytes(encrypted_message))

    @staticmethod
    def auth_status_len():
        return 1 + LEN_SESSION_ID

    @staticmethod
    def request_list_files_encode(session_id: bytes, request_id: bytes) -> bytes:
        if len(session_id) != LEN_SESSION_ID or len(request_id) != LEN_REQUEST_ID:
            raise Exception('Wrong session or request ID length')
        message = bytes()
        message += session_id
        message += request_id
        message += MessageType.LIST_FILES.value.to_bytes(1, byteorder='big')
        return message

    def encrypted_request_list_files_encode(self, session_id: bytes, request_id: bytes) -> bytes:
        return self.cipher.encrypt_bytes(self.request_list_files_encode(session_id, request_id))

    @staticmethod
    def request_list_files_decode(message: bytes) -> bytes:
        # if len(message) != Protocol.request_list_files_len():
        #     raise Exception('Wrong message length')
        actual_position = 0
        session_id = message[actual_position:LEN_SESSION_ID]
        actual_position += LEN_SESSION_ID
        request_id = message[actual_position:actual_position + LEN_REQUEST_ID]
        actual_position += LEN_REQUEST_ID
        message_type = int.from_bytes(message[actual_position: actual_position + 1], byteorder='big')

        if message_type != MessageType.LIST_FILES.value:
            raise Exception('Wrong message to decode')
        return request_id

    def encrypted_request_list_files_decode(self, encrypted_message: bytes) -> bytes:
        return self.request_list_files_decode(self.cipher.decrypt_bytes(encrypted_message))

    @staticmethod
    def request_list_files_len():
        return LEN_SESSION_ID + LEN_REQUEST_ID + 1

    @staticmethod
    def response_request_list_files_encode(request_id: bytes, size_in_bytes: int, port: int) -> bytes:
        if len(request_id) != LEN_REQUEST_ID:
            raise Exception('Wrong request ID length')
        message = bytes()
        message += request_id

        try:
            message += size_in_bytes.to_bytes(MAX_JSON_SIZE, byteorder='big', signed=False)
        except OverflowError:
            raise Exception('Too large data to send')

        try:
            message += port.to_bytes(MAX_PORT_SIZE, byteorder='big', signed=False)
        except OverflowError:
            raise Exception('Too large data to send')

        return message

    def encrypted_response_request_list_files_encode(self, request_id: bytes, size_in_bytes: int, port: int) -> bytes:
        return self.cipher.encrypt_bytes(self.response_request_list_files_encode(request_id, size_in_bytes, port))

    @staticmethod
    def response_request_list_files_decode(message: bytes) -> (bytes, int, int):
        # if len(message) != Protocol.response_request_list_files_len():
        #     raise Exception('Wrong message length')
        actual_position = 0
        request_id = message[actual_position: LEN_REQUEST_ID]
        actual_position += LEN_REQUEST_ID
        json_size = int.from_bytes(message[actual_position: actual_position + MAX_JSON_SIZE], byteorder='big')
        actual_position += MAX_JSON_SIZE
        port = int.from_bytes(message[actual_position: actual_position + MAX_PORT_SIZE], byteorder='big')
        return request_id, json_size, port

    def encrypted_response_request_list_files_decode(self, encrypted_message: bytes) -> (bytes, int, int):
        return self.response_request_list_files_decode(self.cipher.decrypt_bytes(encrypted_message))

    @staticmethod
    def response_request_list_files_len():
        return LEN_REQUEST_ID + MAX_JSON_SIZE + MAX_PORT_SIZE

    @staticmethod
    def establish_message_type(message: bytes) -> (MessageType, bytes, bytes):
        """

        :param message: decrypted message
        :return MessageType
        :return request_id
        :return decrypted message
        """
        msg_type_position = LEN_REQUEST_ID + LEN_SESSION_ID
        message_type = int.from_bytes(message[msg_type_position: msg_type_position + 1], byteorder='big')
        return message_type, message[LEN_SESSION_ID: LEN_SESSION_ID + LEN_REQUEST_ID], message

    def encrypted_establish_message_type(self, encrypted_message: bytes) -> (MessageType, bytes, bytes):
        return self.establish_message_type(self.cipher.decrypt_bytes(encrypted_message))

    def encrypt(self, message: bytes) -> bytes:
        return self.cipher.encrypt_bytes(message)

    def decrypt(self, message: bytes) -> bytes:
        return self.cipher.decrypt_bytes(message)

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


def _max_unsigned_int(bit_size: int) -> int:
    if bit_size <= 0:
        return 0
    result = 1
    for i in range(bit_size - 1):
        result = result << 1
        result += 1
    return result


if __name__ == "__main__":
    session_id = bytearray(random.getrandbits(8) for i in range(64))
    username = 'james'
    m1 = Protocol.hello_encode(username)
    # print(m1)
    print(len(m1) == Protocol.req_0_len())
    username_2 = Protocol.hello_decode(m1)
    if username == username:
        print('OK')
