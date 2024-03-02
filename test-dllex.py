from holo.loader import Loader, LoaderError
from holo.apisetschema import ApisetSchema

import sys
import pefile

if __name__ == '__main__':
    schema = ApisetSchema("dll/apisetschema.dll")
    if not sys.argv[1:]:
        loader = Loader("dll")
        while 1:
            dll = input("DLL: ")
            print(schema.resolve(dll))
        sys.exit(0)

    path = sys.argv[1]
    pef = pefile.PE(path)
    petable = {}

    loader = Loader("dll")
    for lib in pef.DIRECTORY_ENTRY_IMPORT:
        dllname = lib.dll.decode().lower()
        real_dll = schema.resolve(dllname)
        if not petable.get(real_dll):
            try:
                petable[real_dll] = loader.load_pe(real_dll)
            except LoaderError as e:
                print(e)
                continue

        if dllname != real_dll:
            print(dllname, "->", real_dll)
        else:
            print(dllname)
        for imp in lib.imports:
            print("   ", imp.name.decode())
    print(petable)
    

