from holo.unicrud import *
from holo.util import fmt

from collections import OrderedDict

import pefile
import struct


__all__ = [
        'WinError',
        'WinEmulator']


class Import:
    def __init__(self, dll, name):
        self.dll = dll
        self.name = name


class WinError(Exception):
    pass


class WinSection:
    def __init__(self, addr, size):
        self.addr = addr
        self.size = size


class WinEmulator:
    def __init__(self, arch, mode):
        self.uc = Uc(arch, mode)
        self.uc.mem_map(0x0, 2*1024*1024)
        self.pe = None
        self.sections = {}
        self.sections['.text'] = WinSection(0x1000, 0)
        self.mnemonics = set()

    def init_pe(self, path):
        pef = pefile.PE(path)
        txt = None
        for sec in pef.sections:
            if sec.Name == b'.text\x00\x00\x00':
                txt = sec
        if txt is None:
            raise WinError("No text section")

        self.uc.mem_write(self.sections['.text'].addr, txt.get_data())
        self.sections['.text'].size = len(txt.get_data())

        addrs = []
        self.import_table = {}
        for dllimport in pef.DIRECTORY_ENTRY_IMPORT:
            dllname = dllimport.dll.decode()
            for imp in dllimport.imports:
                funcname = imp.name.decode()
                self.import_table[imp.address] = Import(dllname, funcname)
                addrs.append(imp.address)

        addrs.sort()

    def start(self):
        addr_start = self.sections['.text'].addr
        size = self.sections['.text'].size
        #self.uc.hook_add(UC_HOOK_CODE, lambda uc, i: print(self.dump_regs(uc,i)))
        self.uc.hook_add(UC_HOOK_CODE, lambda uc, i: print(fmt(i)))
        self.uc.emu_start(addr_start, addr_start + size)

    def start_singlestep(self):
        addr_start = self.sections['.text'].addr
        size = self.sections['.text'].size
        for _ in self.uc.emu_start_gen(addr_start, addr_start + size):
            yield self.uc

    def dump_regs(self, uc, i):
        lines = []
        eax = uc.reg_read(UC_X86_REG_EAX)
        ebx = uc.reg_read(UC_X86_REG_EBX)
        ecx = uc.reg_read(UC_X86_REG_ECX)
        edx = uc.reg_read(UC_X86_REG_EDX)
        edi = uc.reg_read(UC_X86_REG_EDI)
        esi = uc.reg_read(UC_X86_REG_ESI)
        ebp = uc.reg_read(UC_X86_REG_EBP)
        eip = uc.reg_read(UC_X86_REG_EIP)
        esp = uc.reg_read(UC_X86_REG_ESP)
        names = OrderedDict({
                "eax": eax,
                "ebx": ebx,
                "ecx": ecx,
                "edx": edx,
                "edi": edi,
                "ebp": ebp,
                "eip": eip,
                "esp": esp})
        for reg_name in names:
            reg = names[reg_name]
            addr = f"0x{reg:08x}"
            value = uc.mem_read_ptr(reg)
            fval = f"0x{value:08x}"

            lines.append(f"{reg_name} => {addr} = {fval}")

        return '\n'.join(lines)


    #def hookcode(self, uc, i):
    #    self.mnemonics.add(i.mnemonic)

    #    if i.mnemonic == "call":
    #        if i.bytes[0] == 0xe8:
    #            addr = struct.unpack("<i", i.bytes[1:5])[0]
    #            if addr & 0xffff0000:
    #                pass
    #            else:
    #                pass
    #                print("relative call", hex(addr + i.address + len(i.bytes)))
    #        elif i.bytes[0] == 0xff:
    #            if i.bytes[1] == 0x15:
    #                addr = struct.unpack("<i", i.bytes[-4:])[0]
    #                if addr in self.import_table:
    #                    imp = self.import_table[addr]
    #                    print("call", imp.name, f"({imp.dll})")
    #                else:
    #                    print("call", hex(addr))
    #            elif i.bytes[1] == 0xd7:
    #                pass

