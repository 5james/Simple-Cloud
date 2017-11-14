import pickle
import hashlib
from pathlib import Path
import os

user_database_filename = r'users'


class UserExistsException(Exception):
    pass


def add_user(username: str, password: str, user_database: dict = None):
    if user_database is None:
        user_database = _get_user_database()
    with open(user_database_filename, 'wb+') as file:
        if user_database.get(username) is not None:
            pickle.dump(user_database, file)
            raise UserExistsException('User with username \'{}\' already exists.'.format(username))
        user_database[username] = hashlib.sha3_512(password.encode('utf-8')).digest()
        pickle.dump(user_database, file)


def check_user_existence(username: str, user_database: dict = None) -> bool:
    if user_database is None:
        user_database = _get_user_database()
    if user_database.get(username) is not None:
        return True
    else:
        return False


def check_user_password_str(username: str, password_str: str, user_database: dict = None) -> bool:
    if user_database is None:
        user_database = _get_user_database()
    password_from_db = user_database.get(username)
    if password_from_db is not None:
        password = hashlib.sha3_512(password_str.encode('utf-8')).digest()
        if password_from_db == password:
            return True
        else:
            return False
    else:
        return False


def check_user_password(username: str, password_sha512: bytes, user_database: dict = None) -> bool:
    if user_database is None:
        user_database = _get_user_database()
    password_from_db = user_database.get(username)
    if password_from_db is not None:
        if password_from_db == password_sha512:
            return True
        else:
            return False
    else:
        return False


def _get_user_database() -> dict:
    try:
        with open(user_database_filename, 'rb') as file:
            try:
                user_database = pickle.load(file)
                if not isinstance(user_database, dict):
                    return {}
                else:
                    return user_database
            except EOFError:
                return {}
    except FileNotFoundError:
        return {}


# PROMPT FUNCTIONS #


def _display_main_menu_title_bar():
    # os.system('clear')

    main_menu_title = "\t*******************************" + '\n' + \
                      "\t***        MAIN MENU        ***" + '\n' + \
                      "\t*******************************" + '\n'
    print(main_menu_title)


def _get_user_main_menu_choice() -> str:
    # Let users know what they can do.
    print("[1] Add new user.")
    # print("[2] Check if you know user's password.")
    print("[Q] Quit. (q is NOT Q)")

    return input("> ")


def _display_add_new_user_title_bar():
    # os.system('clear')

    main_menu_title = "\t*******************************" + '\n' + \
                      "\t***      ADD NEW USER       ***" + '\n' + \
                      "\t*******************************" + '\n'
    print(main_menu_title)


def _create_new_user(user_database: dict = None):
    username = ''
    bUserExists = True
    bPasswordNOTCorrect = True

    while bUserExists:
        print("Please enter new user's username ('Q' exists this section).")
        username = input("Username: ")
        if user_database == 'Q':
            break
        try:
            bUserExists = check_user_existence(username, user_database)
        except UserExistsException:
            print('User with that username already exists.')
    if username == 'Q':
        return

    while bPasswordNOTCorrect:
        print("Please enter user's password for user \'{}\'."
              "The password should be between 6 and 64 characters.".format(username))
        password = input("Password: ")
        if 6 <= len(password) <= 64:
            bPasswordNOTCorrect = False
            add_user(username, password, user_database)


if __name__ == "__main__":
    user_database = _get_user_database()
    choice = ''
    _display_main_menu_title_bar()
    while choice != 'Q':
        choice = _get_user_main_menu_choice()

        if choice == '1':
            _display_add_new_user_title_bar()
            _create_new_user(user_database)
        elif choice == 'Q':
            print("\nThanks for playing. Bye.")
        else:
            print("\nI didn't understand that choice.\n")
