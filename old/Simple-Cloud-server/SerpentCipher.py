from ctypes import *
import re
from bitstring import BitStream, BitArray
import binascii
import numpy as np

c_uint_p = POINTER(c_uint)
c_byte_p = POINTER(c_byte)

# load the shared object file
SerpentLib = cdll.LoadLibrary(".\serpent.dll")

MAX_KEY_SIZE = 64
MAX_IV_SIZE = 32
MODE_ECB = 1
MODE_CBC = 2
DIR_ENCRYPT = 0
DIR_DECRYPT = 1
BYTES_IN_SINGLE_CHUNK = 16
BITS_IN_SINGLE_CHUNK = 128


class keyInstance(Structure):
    _fields_ = [("direction", c_byte),
                ("keyLen", c_int),
                ("keyMaterial", c_char * (MAX_KEY_SIZE + 1)),
                ("key", (c_uint * 8)),
                ("subkeys", (c_uint * 33) * 4)]


class cipherInstance(Structure):
    _fields_ = [("mode", c_byte),
                ("IV", (c_char * MAX_IV_SIZE)),
                ("blockSize", c_int)]


class SerpentCipher:
    def __init__(self, hex_key: str, mode=MODE_ECB, key_length=256, iv: str = ""):
        self.SerpentLib = cdll.LoadLibrary("./Serpent.dll")
        # self.SerpentLib.makeKey.restype = c_int
        # self.SerpentLib.makeKey.argtypes = [c_void_p, c_int, c_int, c_char_p]

        self.keyInstanceEncrypt = keyInstance()
        self.keyInstanceDecrypt = keyInstance()

        userKey = hex_key.encode('utf-8')
        rc_e = SerpentLib.makeKey(byref(self.keyInstanceEncrypt), DIR_ENCRYPT, key_length, userKey)
        rc_d = SerpentLib.makeKey(byref(self.keyInstanceDecrypt), DIR_DECRYPT, key_length, userKey)

        if rc_e <= 0 or rc_d <= 0:
            raise Exception('Key Generation Failure')
        self.keylen = key_length
        self.mode = mode
        self.iv = iv.encode('utf-8')

    def encrypt_bytes(self, bytes_to_encrypt: bytes) -> bytes:
        cipherI = cipherInstance()
        # SerpentLib.cipherInit.restype = c_int
        # SerpentLib.cipherInit.argtypes = [POINTER(cipherInstance), c_int, c_char_p]
        rc = SerpentLib.cipherInit(byref(cipherI), self.mode, self.iv)
        if rc <= 0:
            raise Exception('Cipher Initialize Failure')

        # SerpentLib.blockEncrypt.restype = c_int
        # SerpentLib.blockEncrypt.argtypes = [POINTER(cipherInstance), POINTER(keyInstance), POINTER(c_byte), c_int,
        #                                     POINTER(c_byte)]

        bytes_fill = len(bytes_to_encrypt) % BYTES_IN_SINGLE_CHUNK
        if bytes_fill != 0:
            bytes_to_encrypt = bytes_to_encrypt.ljust(len(bytes_to_encrypt) + BYTES_IN_SINGLE_CHUNK - bytes_fill,
                                                      b'\x00')

        b = BitArray(bytes=bytes_to_encrypt)
        chunks = [b[i:i + BITS_IN_SINGLE_CHUNK] for i in range(0, len(b), BITS_IN_SINGLE_CHUNK)]

        encrypted_chunks = bytes()
        for chunk in chunks:
            i1 = int.from_bytes(chunk.bytes[0:4], byteorder='big')
            i2 = int.from_bytes(chunk.bytes[4:8], byteorder='big')
            i3 = int.from_bytes(chunk.bytes[8:12], byteorder='big')
            i4 = int.from_bytes(chunk.bytes[12:16], byteorder='big')
            to_encrypt = (c_uint * 4)(*[i4, i3, i2, i1])
            ciphertext = (c_uint * 4)(*[0, 0, 0, 0])
            rc = SerpentLib.blockEncrypt(byref(cipherI), byref(self.keyInstanceEncrypt), to_encrypt, 128, ciphertext)
            if rc < 0:
                raise Exception('Block Encrypt Error')
            encrypted = bytes()
            for i in reversed(range(4)):
                # print(ciphertext[i])
                encrypted += ciphertext[i].to_bytes(4, byteorder='big')
            encrypted_chunks += encrypted
        return encrypted_chunks


    def decrypt_bytes(self, encrypted_bytes: bytes) -> bytes:
        cipherI = cipherInstance()
        # SerpentLib.cipherInit.restype = c_int
        # SerpentLib.cipherInit.argtypes = [POINTER(cipherInstance), c_int, c_char_p]
        rc = SerpentLib.cipherInit(byref(cipherI), self.mode, self.iv)
        if rc <= 0:
            raise Exception('Cipher Initialize Failure')

        # SerpentLib.blockEncrypt.restype = c_int
        # SerpentLib.blockEncrypt.argtypes = [POINTER(cipherInstance), POINTER(keyInstance), POINTER(c_byte), c_int,
        #                                     POINTER(c_byte)]

        bytes_fill = len(encrypted_bytes) % BYTES_IN_SINGLE_CHUNK
        if bytes_fill != 0:
            bytes_to_encrypt = encrypted_bytes.ljust(len(encrypted_bytes) + BYTES_IN_SINGLE_CHUNK - bytes_fill,
                                                     b'\x00')

        b = BitArray(bytes=encrypted_bytes)
        chunks = [b[i:i + BITS_IN_SINGLE_CHUNK] for i in range(0, len(b), BITS_IN_SINGLE_CHUNK)]

        encrypted_chunks = bytes()
        for chunk in chunks:
            i1 = int.from_bytes(chunk.bytes[12:16], byteorder='big')
            i2 = int.from_bytes(chunk.bytes[8:12], byteorder='big')
            i3 = int.from_bytes(chunk.bytes[4:8], byteorder='big')
            i4 = int.from_bytes(chunk.bytes[0:4], byteorder='big')
            ciphertext = (c_uint * 4)(*[i1, i2, i3, i4])
            # for i in range(4):
            #     print(ciphertext[i])
            text = (c_uint * 4)(*[0, 0, 0, 0])
            rc = SerpentLib.blockDecrypt(byref(cipherI), byref(self.keyInstanceDecrypt), ciphertext, 128, text)
            if rc < 0:
                raise Exception('Block Encrypt Error')
            encrypted = bytes()
            for i in reversed(range(4)):
                # print(ciphertext[i])
                encrypted += text[i].to_bytes(4, byteorder='big')
            encrypted_chunks += encrypted
        return encrypted_chunks


if __name__ == "__main__":
    textToEncrypt = '100100000000000000000000000000001001000000000000000000000000000011'
    textToEncryptBytes = bytes(BitArray(hex=textToEncrypt).bytes)
    print(BitArray(bytes=textToEncryptBytes).hex)
    s = SerpentCipher('0000000000000000000000000000000000000000000000000000000000000000', mode=MODE_CBC, iv='10010000000000000000000000000000')
    encrypted = s.encrypt_bytes(textToEncryptBytes)
    print(BitArray(bytes=encrypted).hex)

    decrypted = s.decrypt_bytes(encrypted)
    print(BitArray(bytes=decrypted).hex)

