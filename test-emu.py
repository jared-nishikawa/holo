from holo.winemulator import WinEmulator
from holo.unicrud import UC_ARCH_X86, UC_MODE_32

import sys


if __name__ == '__main__':
    if not sys.argv[1:]:
        path = 'exe/consoleapp.exe'
    else:
        path = sys.argv[1]
    mu = WinEmulator(UC_ARCH_X86, UC_MODE_32)
    mu.init_pe(path)
    mu.start()



