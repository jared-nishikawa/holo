"""
http://sparksandflames.com/files/x86InstructionChart.html
http://www.c-jump.com/CIS77/CPU/x86/X77_0060_mod_reg_r_m_byte.htm
AL = 0 AX = 0 EAX = 0
CL = 1 CX = 1 ECX = 1
DL = 2 DX = 2 EDX = 2
BL = 3 BX = 3 EBX = 3
AH = 4 SP = 4 ESP = 4
CH = 5 BP = 5 EBP = 5
DH = 6 SI = 6 ESI = 6
BH = 7 DI = 7 EDI = 7

8b ec = mov ebp esp (copy value of esp to ebp)
8b = mov Gv Ev
ec is modr/m byte
ec = 11101100
11 101 100
11 = register addressing mode
101 = ebp
100 = esp

"""

from holo.const import *

import struct


class HandlerClass(dict):
    def get(self, i_bytes, default=lambda uc,i: None):
        size = len(i_bytes)
        for ib, sz in self.keys():
            if i_bytes.startswith(ib) and size == sz:
                return super().get((ib, sz), default)
        return default

InstructionHandler = HandlerClass()

def make_ih(i_bytes, size=-1):
    if size == -1:
        size = len(i_bytes)
    global InstructionHandler
    def wrapper_maker(inner):
        def wrapped(*args, **kwargs):
            return inner(*args, **kwargs)
        InstructionHandler[(i_bytes, size)] = wrapped
        return wrapped
    return wrapper_maker

@make_ih(b"\x8b", 2)
def mov_gv_ev(uc, i):
    assert len(i.bytes) == 2
    modrm = i.bytes[1]
    rm = modrm & 0b111
    reg = (modrm >> 3) & 0b111
    mod = (modrm >> 6) & 0b11
    if mod == 0b11:
        src = rm
        dst = reg
        val = uc.reg_read(src)
        uc.reg_write(dst, val)

@make_ih(b"\x68", 5)
def push_word(uc, i):
    assert len(i.bytes) == 5
    word_bytes = i.bytes[1:]
    word_num = struct.unpack("<I", word_bytes)[0]
    uc.stack_push(word_num)

@make_ih(b"\x6a", 2)
def push_byte(uc, i):
    assert len(i.bytes) == 2
    byte = i.bytes[1]
    uc.stack_push(byte, 1)

@make_ih(b"\x50")
def push_eax(uc, i):
    pass

@make_ih(b"\x51")
def push_ecx(uc, i):
    pass

@make_ih(b"\x52")
def push_edx(uc, i):
    pass

@make_ih(b"\x53")
def push_ebx(uc, i):
    pass

@make_ih(b"\x54")
def push_esp(uc, i):
    pass

@make_ih(b"\x55")
def push_ebp(uc, i):
    uc.stack_push(uc.registers[UC_X86_REG_EBP])

@make_ih(b"\x56")
def push_esi(uc, i):
    pass

@make_ih(b"\x57")
def push_edi(uc, i):
    pass

@make_ih(b"\x58")
def pop_eax(uc, i):
    pass

@make_ih(b"\x59")
def pop_ecx(uc, i):
    pass

@make_ih(b"\x5a")
def pop_edx(uc, i):
    pass

@make_ih(b"\x5b")
def pop_ebx(uc, i):
    pass

@make_ih(b"\x5c")
def pop_esp(uc, i):
    pass

@make_ih(b"\x5d")
def pop_ebp(uc, i):
    pass

@make_ih(b"\x5e")
def pop_esi(uc, i):
    pass

@make_ih(b"\x5f")
def pop_edi(uc, i):
    pass


#0x11d6:   ff 30                   push            dword ptr [eax]
#0x105e:   ff 76 08                push            dword ptr [esi + 8]
#0x116c:   ff 74 24 20             push            dword ptr [esp + 0x20]

