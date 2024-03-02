import pefile
import sys
import os


class LoaderError(Exception):
    pass


class Loader:
    def __init__(self, path):
        self.path = path

    def load_pe(self, name):
        name = name.lower()

        dllnames = os.listdir(self.path)
        path = ''
        for eachname in dllnames:
            if name == eachname.lower():
                path = os.path.join(self.path, eachname)
                break
        if not path:
            raise LoaderError(f"DLL not found ({name})")
        return pefile.PE(path)
