import json
from enum import Enum


# TODO: uporządkować exception

class MessageType(Enum):
    CONNECTION_DH = 1


message_length_size = 64


class Protocol:
    @staticmethod
    def connect_encode(key) -> (str, str):
        if key is None:
            raise Exception("No key input")
        data_python = {'message_type': MessageType.CONNECTION_DH.value, 'key': key}
        data_json = json.dumps(data_python)
        message_length = Protocol.__message_length_encode(len(data_json))
        return message_length, data_json

    @staticmethod
    def decoder(message: str) -> (int, dict):
        try:
            parsed_json = json.loads(message)
            if parsed_json['message_type'] == MessageType.CONNECTION_DH.value:
                return Protocol._connect_decode(parsed_json)
        except:
            raise Exception('Bad json encoding')

    @staticmethod
    def _connect_decode(parsed_json) -> (int, dict):
        if 'key' not in parsed_json:
            raise Exception('Lack of data in json')
        return parsed_json['message_type'], parsed_json

    @staticmethod
    def __message_length_encode(length: int) -> str:
        length_str = str(length)
        # if length of string containing length of sending message > 64 then Exception
        if len(length_str) > message_length_size:
            raise Exception("Too large message")
        return length_str

    @staticmethod
    def get_message_size():
        return message_length_size
