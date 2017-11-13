import pickle
import hashlib
from pathlib import Path

user_database_filename = r'users'


class UserExistsException(Exception):
    pass


def add_user(username: str, password: str):
    try:
        with open(user_database_filename, 'rb+') as file:
            try:
                user_database = pickle.load(file)
                if not isinstance(user_database, dict):
                    user_database = {}
            except EOFError:
                user_database = {}
    except FileNotFoundError:
        user_database = {}
    with open(user_database_filename, 'wb+') as file:
        if user_database.get(username) is not None:
            pickle.dump(user_database, file)
            raise UserExistsException('User with username \'{}\' already exists.'.format(username))
        user_database[username] = hashlib.sha3_512(password.encode('utf-8')).digest()
        pickle.dump(user_database, file)


def check_user_existence(username: str) -> bool:
    try:
        with open(user_database_filename, 'rb') as file:
            try:
                user_database = pickle.load(file)
                if not isinstance(user_database, dict):
                    return False
                if user_database.get(username) is not None:
                    return True
                else:
                    return False
            except EOFError:
                return False
    except FileNotFoundError:
        return False


def check_user_password_str(username: str, password_str: str) -> bool:
    try:
        with open(user_database_filename, 'rb') as file:
            try:
                user_database = pickle.load(file)
                if not isinstance(user_database, dict):
                    return False
                password_from_db = user_database.get(username)
                if password_from_db is not None:
                    password = hashlib.sha3_512(password_str.encode('utf-8')).digest()
                    if password_from_db == password:
                        return True
                    else:
                        return False
                else:
                    return False
            except EOFError:
                return False
    except FileNotFoundError:
        return False


def check_user_password(username: str, password_sha512: bytes) -> bool:
    try:
        with open(user_database_filename, 'rb') as file:
            try:
                user_database = pickle.load(file)
                if not isinstance(user_database, dict):
                    return False
                password_from_db = user_database.get(username)
                if password_from_db is not None:
                    if password_from_db == password_sha512:
                        return True
                    else:
                        return False
                else:
                    return False
            except EOFError:
                return False
    except FileNotFoundError:
        return False


if __name__ == "__main__":
    try:
        add_user('admin', '123')
        add_user('adminn', '123')
        add_user('adminnn', '123')
        add_user('admin', '123')
    except UserExistsException as e:
        print(e)
    print(check_user_existence('admin'))
    print(check_user_existence('adminn'))
    print(check_user_existence('adminnn'))
    print(check_user_existence('adminnnn'))
    print(check_user_password_str('admin', '123'))
    print(check_user_password_str('adminn', '123'))
    print(check_user_password_str('admin', '1234'))
    print(check_user_password_str('adminnnnn', '123'))
