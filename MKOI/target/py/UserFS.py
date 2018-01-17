from Users import VIRTUAL_FILESYSTEM_DIR
from fs import *
from fs.osfs import *
from fs.base import *
import os
import hashlib


class FileDoesNotExistsException(Exception):
    pass


class UserFS:
    def __init__(self, username: str):
        # self.home_FS = open_fs(VIRTUAL_FILESYSTEM_DIR + username)
        self.home_OSFS = OSFS(VIRTUAL_FILESYSTEM_DIR + username + '/')
        # self.lock = threading.Condition()
        self.username = username

    def list_all_files(self) -> list:
        result_list = []
        files = self.home_OSFS.listdir('.')
        for file in files:
            result_file = {'name': file}
            file_info = self.home_OSFS.getinfo(file, namespaces=['details', 'link'])
            result_file['size'] = int(file_info.size)
            result_file['last_modification'] = file_info.modified
            result_list.append(result_file)
        return result_list

    def get_file_as_bytes(self, file_path: str) -> bytes:
        with self.home_OSFS.lock():
            try:
                file_bytes = self.home_OSFS.getbytes(file_path)
                return file_bytes
            except:
                raise FileDoesNotExistsException('File {} does not exists'.format(file_path))

    def hash_sha3_512(self, file_path: str):
        sha3_512 = hashlib.sha3_512()
        sha3_512.update(self.get_file_as_bytes(file_path))
        return sha3_512.digest()

    def save_file_from_bytes(self, file_path: str, file_bytes: bytes) -> bool:
        with self.home_OSFS.lock():
            try:
                self.home_OSFS.setbytes(file_path, file_bytes)
                return True
            except TypeError:
                return False

    def check_file_existence(self, file_path: str) -> bool:
        with self.home_OSFS.lock():
            try:
                file_info = self.home_OSFS.getinfo(file_path)
                return file_info.is_file
            except errors.ResourceNotFound:
                return False

    def delete_file(self, file_path: str) -> bool:
        absolute_path = self.home_OSFS.getsyspath(file_path)
        try:
            os.remove(absolute_path)
            return True
        except FileNotFoundError:
            return False



if __name__ == "__main__":
    johny = UserFS('johny')
    print(johny.list_all_files())
    test_bytes = b'123456'
    print(johny.save_file_from_bytes('test3.txt', test_bytes))
    print(johny.get_file_as_bytes('test.txt') == test_bytes)
    print(johny.hash_sha3_512('test.txt'))
    print(johny.check_file_existence('test2.txt'))
    print(johny.delete_file('test3.txt'))
