import json
from enum import Enum
import random
import re
import hashlib
from SerpentCipherClassicalString import *
from SerpentCipher import *


# TODO: get exceptions right

class MessageType(Enum):
    LOG_IN = 0
    LIST_FILES = 1
    UPLOAD_FILE = 2
    GET_HASH = 3
    DOWNLOAD_FILE = 4
    DELETE_FILE = 5
    LOG_OUT = 6


# message_length_size_bit = 64


# message_length_size_byte = 8
MAX_USERNAME_SIZE = 64
MAX_PASSWORD_SIZE = 64
SECRET_LEN = 768
SHA_512_LEN = 64
MAX_JSON_SIZE = 8
MAX_PORT_SIZE = 2
MAX_FILENAME_SIZE = 64
MAX_FILE_SIZE_LEN = 8
HEADER_SIZE = 1


class Protocol:
    def __init__(self, cipher: SerpentCipher):
        self.cipher = cipher

    # @staticmethod
    # def hello_encode(username: str) -> bytes:
    #     # if len(session_id) != :
    #     #     raise Exception('Bad length of session_id')
    #     if len(username) > MAX_USERNAME_SIZE:
    #         raise Exception('Too long username')
    #     message = bytes()
    #     # message += session_id
    #     message += MessageType.LOG_IN.value.to_bytes(1, byteorder='big')
    #     username_bytes = username.encode('utf-8')
    #     # username_bytes_len = len(username_bytes)
    #     # len_diff = MAX_USERNAME_SIZE - username_bytes_len
    #     # username_bytes += b'\x00' * len_diff
    #     message += username_bytes.ljust(MAX_USERNAME_SIZE, b'\x00')
    #     return message
    #
    # @staticmethod
    # def hello_decode(message_bytes: bytes) -> str:
    #     if len(message_bytes) != Protocol.req_0_len():
    #         raise Exception('Bad message length')
    #     # session_id = message_bytes[0:64]
    #     if message_bytes[0:1] != MessageType.LOG_IN.value.to_bytes(1, byteorder='big'):
    #         raise Exception('Wrong message!')
    #     username = message_bytes[1:65].decode('utf-8')
    #     username = re.sub(r'\W', "", username)
    #     return username
    #
    # @staticmethod
    # def req_0_len() -> int:
    #     return MAX_USERNAME_SIZE + 1
    #
    # @staticmethod
    # def username_status_encode(did_succeed: bool) -> bytes:
    #     if did_succeed:
    #         return b'\x00'
    #     else:
    #         return b'\xFF'
    #
    # @staticmethod
    # def username_status_decode(did_succeed_byte: bytes) -> bool:
    #     if len(did_succeed_byte) != Protocol.username_status_len():
    #         raise Exception('Wrong message length')
    #     if did_succeed_byte == b'\x00':
    #         return True
    #     elif did_succeed_byte == b'\xFF':
    #         return False
    #     else:
    #         raise Exception('Wrong login status')
    #
    # @staticmethod
    # def username_status_len() -> int:
    #     return 1
    #
    # @staticmethod
    # def dh_encode(secret: int) -> bytes:
    #     if secret > _max_unsigned_int(Protocol.dh_len() * 8):
    #         raise Exception('secret is too big')
    #     bPubKey = secret.to_bytes(Protocol.dh_len(), byteorder='big')
    #     return bPubKey
    #
    # @staticmethod
    # def dh_decode(message: bytes) -> int:
    #     # if len(message) != Protocol.dh_len:
    #     #     raise Exception('Bad message length')
    #     return int.from_bytes(message, byteorder='big')
    #
    # @staticmethod
    # def dh_len():
    #     return SECRET_LEN
    #
    # @staticmethod
    # def passwd_encode(password: str) -> bytes:
    #     if len(password) > Protocol.passwd_len():
    #         raise Exception('Password is too long')
    #     pwd_sha_512 = hashlib.sha3_512(password.encode('utf-8')).digest()
    #     return pwd_sha_512
    #
    # def encrypted_passwd_encode(self, password: str) -> bytes:
    #     return self.encrypt(self.passwd_encode(password))
    #
    # @staticmethod
    # def passwd_decode(password_sha_512_bytes: bytes) -> bytes:
    #     if len(password_sha_512_bytes) != Protocol.passwd_len():
    #         raise Exception('Bad password length')
    #     return password_sha_512_bytes
    #
    # def encrypted_passwd_decode(self, encrypted_password_sha_512_bytes: bytes) -> bytes:
    #     return self.passwd_decode(self.decrypt(encrypted_password_sha_512_bytes))
    #
    # @staticmethod
    # def passwd_len():
    #     return SHA_512_LEN

    @staticmethod
    def req_0_dh_encode(secret: int) -> bytes:
        message = bytes()
        message += Protocol.header_encode(MessageType.LOG_IN)
        if secret > _max_unsigned_int(SECRET_LEN * 8):
            raise Exception('secret is too big')
        bPubKey = secret.to_bytes(SECRET_LEN, byteorder='big')
        message += bPubKey
        return message

    @staticmethod
    def req_0_dh_decode(message: bytes) -> int:
        # if len(message) != Protocol.dh_len:
        #     raise Exception('Bad message length')
        if len(message) != HEADER_SIZE + SECRET_LEN:
            raise Exception('Wrong message length')
        if int.from_bytes(message[0:1], byteorder='big') != MessageType.LOG_IN.value:
            raise Exception('Wrong request encoding')
        return int.from_bytes(message[1:], byteorder='big')

    @staticmethod
    def res_dh_encode(secret: int) -> bytes:
        if secret > _max_unsigned_int(SECRET_LEN * 8):
            raise Exception('secret is too big')
        bPubKey = secret.to_bytes(SECRET_LEN, byteorder='big')
        return bPubKey

    @staticmethod
    def res_dh_decode(message: bytes) -> int:
        if len(message) != SECRET_LEN:
            raise Exception('Wrong message length')
        return int.from_bytes(message, byteorder='big')

    @staticmethod
    def header_encode(msg_type: MessageType) -> bytes:
        message = bytes()
        message += msg_type.value.to_bytes(1, byteorder='big')
        return message

    @staticmethod
    def establish_message_type(message: bytes) -> (MessageType, bytes):
        """

        :param message: decrypted message
        :return session_id
        :return request_id
        :return MessageType
        :return decrypted message
        """
        actual_position = 0
        message_type = int.from_bytes(message[actual_position: actual_position + 1], byteorder='big')
        return message_type, message

    def encrypted_establish_message_type(self, encrypted_message: bytes) -> (MessageType, bytes):
        return self.establish_message_type(self.decrypt(encrypted_message))

    def encrypt(self, message: bytes) -> bytes:
        return self.cipher.encrypt_bytes(message)

    def decrypt(self, message: bytes) -> bytes:
        return self.cipher.decrypt_bytes(message)

    @staticmethod
    def authentication_encode(username: str, password: str) -> bytes:
        if len(username) > MAX_USERNAME_SIZE or len(password) > MAX_PASSWORD_SIZE:
            raise Exception('Wrong username or password length')
        message = bytes()
        message += username.encode('utf-8').ljust(MAX_USERNAME_SIZE, b'\x00')
        message += hashlib.sha3_512(password.encode('utf-8')).digest()
        return message

    def encrypted_authentication_encode(self, username: str, password: str) -> bytes:
        return self.encrypt(Protocol.authentication_encode(username, password))

    @staticmethod
    def authentication_decode(message: bytes) -> (str, bytes):
        if len(message) != MAX_USERNAME_SIZE + MAX_PASSWORD_SIZE:
            raise Exception('Wrong message length')
        actualPosition = 0
        username = message[actualPosition: actualPosition + MAX_USERNAME_SIZE].decode('utf-8')
        username = re.match(r'[\w +-/*,()\[\]&]*', username, re.M | re.I).group()
        actualPosition += MAX_USERNAME_SIZE
        passwordDigest = message[actualPosition: actualPosition + SHA_512_LEN]
        return username, passwordDigest

    def encrypted_authentication_decode(self, message: bytes) -> (str, bytes):
        return self.authentication_decode(self.decrypt(message))

    @staticmethod
    def auth_status_encode(auth_success: bool) -> bytes:
        if auth_success:
            return b'\x00'
        else:
            return b'\xFF'

    def encrypted_auth_status_encode(self, auth_success: bool) -> bytes:
        return self.encrypt(self.auth_status_encode(auth_success))

    @staticmethod
    def auth_status_decode(message: bytes) -> bool:
        # if len(message) != Protocol.auth_status_len():
        #     raise Exception('Wrong message length')
        auth_status_byte = message[0:1]
        if auth_status_byte == b'\x00':
            auth_status = True
        elif auth_status_byte == b'\xFF':
            auth_status = False
        else:
            raise Exception('Wrong login status')
        return auth_status

    def encrypted_auth_status_decode(self, encrypted_message: bytes) -> bool:
        return self.auth_status_decode(self.decrypt(encrypted_message))

    @staticmethod
    def auth_status_len():
        return 1

    @staticmethod
    def request_list_files_encode() -> bytes:
        return Protocol.header_encode(MessageType.LIST_FILES)

    def encrypted_request_list_files_encode(self) -> bytes:
        return self.encrypt(self.request_list_files_encode())

    @staticmethod
    def request_list_files_decode(message: bytes):
        # if len(message) != Protocol.request_list_files_len():
        #     raise Exception('Wrong message length')
        pass

    def encrypted_request_list_files_decode(self, encrypted_message: bytes):
        pass

    @staticmethod
    def request_list_files_len():
        return 1

    @staticmethod
    def response_request_list_files_encode(size_in_bytes: int, port: int) -> bytes:
        message = bytes()
        try:
            message += size_in_bytes.to_bytes(MAX_JSON_SIZE, byteorder='big', signed=False)
        except OverflowError:
            raise Exception('Too large data to send')
        try:
            message += port.to_bytes(MAX_PORT_SIZE, byteorder='big', signed=False)
        except OverflowError:
            raise Exception('Too large data to send')
        return message

    def encrypted_response_request_list_files_encode(self, size_in_bytes: int, port: int) -> bytes:
        return self.encrypt(self.response_request_list_files_encode(size_in_bytes, port))

    @staticmethod
    def response_request_list_files_decode(message: bytes) -> (int, int):
        # if len(message) != Protocol.response_request_list_files_len():
        #     raise Exception('Wrong message length')
        actual_position = 0
        json_size = int.from_bytes(message[actual_position: actual_position + MAX_JSON_SIZE], byteorder='big')
        actual_position += MAX_JSON_SIZE
        port = int.from_bytes(message[actual_position: actual_position + MAX_PORT_SIZE], byteorder='big')
        return json_size, port

    def encrypted_response_request_list_files_decode(self, encrypted_message: bytes) -> (int, int):
        return self.response_request_list_files_decode(self.decrypt(encrypted_message))

    @staticmethod
    def response_request_list_files_len():
        return MAX_JSON_SIZE + MAX_PORT_SIZE

    @staticmethod
    def request_upload_file_encode(filename: str) -> bytes:
        message = Protocol.header_encode(MessageType.UPLOAD_FILE)
        message += filename.encode('utf-8').ljust(MAX_FILENAME_SIZE, b'\x00')
        return message

    def encrypted_request_upload_file_encode(self, filename: str) -> bytes:
        return self.encrypt(self.request_upload_file_encode(filename))

    @staticmethod
    def request_upload_file_decode(message: bytes) -> str:
        """
        :param message: decrypted message containing session_id, request_id, MessageType, filename
        :return filename  in str
        """
        filename_position = HEADER_SIZE
        filename_with_junk = message[filename_position: filename_position + MAX_FILENAME_SIZE].decode('utf-8')
        filename = re.match(r'[\w +-/*,()\[\]&]*', filename_with_junk, re.M | re.I).group()
        return filename

    def encrypted_request_upload_file_decode(self, encrypted_message: bytes) -> str:
        return self.request_upload_file_decode(self.decrypt(encrypted_message))

    @staticmethod
    def response_upload_file_encode(perm_flag: bool, port: int) -> bytes:
        message = bytes()
        if perm_flag:
            message += b'\x00'
        else:
            message += b'\xFF'
        message += port.to_bytes(MAX_PORT_SIZE, byteorder='big')
        return message

    def encrypted_response_upload_file_encode(self, perm_flag: bool, port: int) -> bytes:
        return self.encrypt(self.response_upload_file_encode(perm_flag, port))

    @staticmethod
    def response_upload_file_decode(message: bytes) -> (bool, int):
        actual_position = 0
        perm_flag_encoded = message[actual_position: actual_position + 1]
        if perm_flag_encoded == b'\x00':
            perm_flag = True
        elif perm_flag_encoded == b'\xFF':
            perm_flag = False
        else:
            raise Exception('perm flag wrong content')
        actual_position += 1
        port = int.from_bytes(message[actual_position: actual_position + MAX_PORT_SIZE], byteorder='big')
        return perm_flag, port

    def encrypted_response_upload_file_decode(self, encrypted_message: bytes) -> (bool, int):
        return self.response_upload_file_decode(self.decrypt(encrypted_message))

    @staticmethod
    def client_response_upload_file_encode(file_size: int) -> bytes:
        return file_size.to_bytes(MAX_FILE_SIZE_LEN, byteorder='big')

    def encrypted_client_response_upload_file_encode(self, file_size: int) -> bytes:
        return self.encrypt(self.client_response_upload_file_encode(file_size))

    @staticmethod
    def client_response_upload_file_decode(message: bytes) -> int:
        file_size = int.from_bytes(message[0: MAX_FILE_SIZE_LEN], byteorder='big')
        return file_size

    def encrypted_client_response_upload_file_decode(self, encrypted_message: bytes) -> int:
        return self.client_response_upload_file_decode(self.decrypt(encrypted_message))

    @staticmethod
    def request_file_hash_encode(filename: str) -> bytes:
        message = bytes()
        message += Protocol.header_encode(MessageType.GET_HASH)
        message += filename.encode('utf-8').ljust(MAX_FILENAME_SIZE, b'\x00')
        return message

    def encrypted_request_file_hash_encode(self, filename: str) -> bytes:
        return self.encrypt(self.request_file_hash_encode(filename))

    @staticmethod
    def request_file_hash_decode(message: bytes) -> str:
        filename_pos = HEADER_SIZE
        filename_with_junk = message[filename_pos: filename_pos + MAX_FILENAME_SIZE].decode('utf-8')
        filename = re.match(r'[\w +-/*,()\[\]&]*', filename_with_junk, re.M | re.I).group()
        return filename

    def encrypted_request_file_hash_decode(self, encrypted_message: bytes) -> str:
        return self.request_file_hash_decode(self.decrypt(encrypted_message))

    @staticmethod
    def response_file_hash_encode(file_exists: bool, file_hash: bytes = None) -> bytes:
        message = bytes()
        if file_exists:
            message += b'\x00'
            message += file_hash
        else:
            message += b'\xFF'
            message += bytes(SHA_512_LEN)
        return message

    def encrypted_response_file_hash_encode(self, file_exists: bool,
                                            file_hash: bytes = None) -> bytes:
        return self.encrypt(self.response_file_hash_encode(file_exists, file_hash))

    @staticmethod
    def response_file_hash_decode(message: bytes) -> (bool, bytes):
        actual_position = 0
        bFileExists_bytes = message[actual_position: actual_position + 1]
        if bFileExists_bytes == b'\x00':
            bFileExists = True
            actual_position += 1
            file_hash = message[actual_position: actual_position + SHA_512_LEN]
        elif bFileExists_bytes == b'\xFF':
            bFileExists = False
            actual_position += 1
            file_hash = message[actual_position: actual_position + SHA_512_LEN]
            if file_hash != bytes(64):
                raise Exception('file_hash is not 0x000...000 with non existing file!')
        else:
            raise Exception('Wrong file_exists encoding')
        return bFileExists, file_hash

    def encrypted_response_file_hash_decode(self, encrypted_message: bytes) -> (bool, bytes):
        return self.response_file_hash_decode(self.decrypt(encrypted_message))

    @staticmethod
    def request_download_file_encode(filename: str) -> bytes:
        message = bytes()
        message += Protocol.header_encode(MessageType.DOWNLOAD_FILE)
        message += filename.encode('utf-8').ljust(MAX_FILENAME_SIZE, b'\x00')
        return message

    def encrypted_request_download_file_encode(self, filename: str) -> bytes:
        return self.encrypt(self.request_download_file_encode(filename))

    @staticmethod
    def request_download_file_decode(message: bytes) -> str:
        filename_pos = HEADER_SIZE
        filename_with_junk = message[filename_pos: filename_pos + MAX_FILENAME_SIZE].decode('utf-8')
        filename = re.match(r'[\w +-/*,()\[\]&]*', filename_with_junk, re.M | re.I).group()
        return filename

    def encrypted_request_download_file_decode(self, encrypted_message: bytes) -> str:
        return self.request_download_file_decode(self.decrypt(encrypted_message))

    @staticmethod
    def response_download_file_encode(file_exists: bool, file_size: int = 0, port: int = 0) -> bytes:
        message = bytes()
        if file_exists:
            message += b'\x00'
        else:
            message += b'\xFF'
        message += file_size.to_bytes(MAX_FILE_SIZE_LEN, byteorder='big')
        message += port.to_bytes(MAX_PORT_SIZE, byteorder='big')
        return message

    def encrypted_response_download_file_encode(self, file_exists: bool, file_size: int = 0,
                                                port: int = 0) -> bytes:
        return self.encrypt(self.response_download_file_encode(file_exists, file_size, port))

    @staticmethod
    def response_download_file_decode(message: bytes) -> (bool, int, int):
        actual_position = 0
        bFileExists_bytes = message[actual_position: actual_position + 1]
        if bFileExists_bytes == b'\x00':
            bFileExists = True
            actual_position += 1
            file_size = int.from_bytes(message[actual_position: actual_position + MAX_FILE_SIZE_LEN], byteorder='big')
            actual_position += MAX_FILE_SIZE_LEN
            port = int.from_bytes(message[actual_position: actual_position + MAX_PORT_SIZE], byteorder='big')

        elif bFileExists_bytes == b'\xFF':
            bFileExists = False
            actual_position += 1
            if message[actual_position: actual_position + MAX_FILE_SIZE_LEN + MAX_PORT_SIZE] != bytes(
                            MAX_FILE_SIZE_LEN + MAX_PORT_SIZE):
                raise Exception('file size and port are not filled with 0')
            file_size = 0
            port = 0

        else:
            raise Exception('Wrong file_exists encoding')

        return bFileExists, file_size, port

    def encrypted_response_download_file_decode(self, encrypted_message: bytes) -> (bool, int, int):
        return self.response_download_file_decode(self.decrypt(encrypted_message))

    @staticmethod
    def request_delete_file_encode(filename: str) -> bytes:
        message = bytes()
        message += Protocol.header_encode(MessageType.DELETE_FILE)
        message += filename.encode('utf-8').ljust(MAX_FILENAME_SIZE, b'\x00')
        return message

    def encrypted_request_delete_file_encode(self, filename: str) -> bytes:
        return self.encrypt(self.request_delete_file_encode(filename))

    @staticmethod
    def request_delete_file_decode(message: bytes) -> str:
        filename_pos = HEADER_SIZE
        filename_with_junk = message[filename_pos: filename_pos + MAX_FILENAME_SIZE].decode('utf-8')
        filename = re.match(r'[\w +-/*,()\[\]&]*', filename_with_junk, re.M | re.I).group()
        return filename

    def encrypted_request_delete_file_decode(self, encrypted_message: bytes) -> str:
        return self.request_delete_file_decode(self.decrypt(encrypted_message))

    @staticmethod
    def response_delete_file_encode(did_delete: bool) -> bytes:
        message = bytes()
        if did_delete:
            message += b'\x00'
        else:
            message += b'\xFF'
        return message

    def encrypted_response_delete_file_encode(self, did_delete: bool) -> bytes:
        return self.encrypt(self.response_delete_file_encode(did_delete))

    @staticmethod
    def response_delete_file_decode(message: bytes) -> bool:
        bDidDelete_bytes = message[0: 1]
        if bDidDelete_bytes == b'\x00':
            bDidDelete = True
        elif bDidDelete_bytes == b'\xFF':
            bDidDelete = False
        else:
            raise Exception('Wrong bool did_delete encoding')
        return bDidDelete

    def encrypted_response_delete_file_decode(self, encrypted_message: bytes) -> bool:
        return self.response_delete_file_decode(self.decrypt(encrypted_message))

    @staticmethod
    def request_logout_encode() -> bytes:
        message = bytes()
        message += Protocol.header_encode(MessageType.LOG_OUT)
        return message

    def encrypted_request_logout_encode(self, ) -> bytes:
        return self.encrypt(self.request_logout_encode())


def _max_unsigned_int(bit_size: int) -> int:
    if bit_size <= 0:
        return 0
    result = 1
    for i in range(bit_size - 1):
        result = result << 1
        result += 1
    return result
