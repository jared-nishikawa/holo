from capstone import Cs
from holo.const import *
from holo.ihandler import InstructionHandler

from collections import OrderedDict

import struct


__all__ = [
        'UC_ARCH_X86',
        'UC_MODE_32',
        'UC_X86_REG_EAX',
        'UC_X86_REG_EBX',
        'UC_X86_REG_ECX',
        'UC_X86_REG_EDX',
        'UC_X86_REG_EBP',
        'UC_X86_REG_ESP',
        'UC_X86_REG_ESI',
        'UC_X86_REG_EDI',
        'UC_X86_REG_EIP',
        'UC_HOOK_CODE',
        'UcError',
        'Uc']


class StackError(Exception):
    pass

class Stack:
    def __init__(self, top, ptr_size, size):
        self.size = size
        self.mem = [0]*size
        self.top = top
        self.ptr = top + size
        self._ptr = -1
        self.ptr_size = ptr_size
        self.push(0, self.ptr_size)

    def push(self, value, size):
        for _ in range(size):
            self.ptr -= 1
            self._ptr += 1
            self.mem[self._ptr] = value%256
            value //= 256

    def pop(self):
        if self._ptr < 3:
            raise StackError("Bottom of stack")
        result = 0
        for i in range(self.ptr_size):
            result <<= 8 
            result += self.mem[self._ptr]
            self.ptr += 1
            self._ptr -= 1
        return result

    def peek(self, addr):
        _addr = self.top + self.size - addr

        if _addr < 4:
            raise StackError("Bottom of stack")
        return struct.unpack("<I", bytearray(self.mem[_addr-4:_addr]))[0]

    def set(self, addr):
        self.ptr = addr
        self._ptr = self.top + self.size - self.ptr - 1


class UcError(Exception):
    pass


class Uc:
    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode
        self.registers = {}
        self.registers[UC_X86_REG_EAX] = 0
        self.registers[UC_X86_REG_EBX] = 0
        self.registers[UC_X86_REG_ECX] = 0
        self.registers[UC_X86_REG_EDX] = 0
        self.registers[UC_X86_REG_EBP] = 0
        self.registers[UC_X86_REG_ESP] = 0
        self.registers[UC_X86_REG_ESI] = 0
        self.registers[UC_X86_REG_EDI] = 0
        self.registers[UC_X86_REG_EIP] = 0
        self.memory = []
        self.offset = 0
        self.instructions = OrderedDict()
        self.callbacks = []
        self.callback_output = []
        if arch != UC_ARCH_X86 or mode != UC_MODE_32:
            raise UcError("Unavailable arch or mode")
        if mode == UC_MODE_32:
            stack_top = 0xff000000
            ptr_size = 4
            size = 4*1024*1024
            self.stack = Stack(stack_top, ptr_size, size)
            self.ptr_size = ptr_size
            self.registers[UC_X86_REG_ESP] = self.stack.ptr
            self.stack_bot = stack_top + size
            self.stack_top = stack_top

    def _mem_map(self, size):
        self.memory = [0]*size

    def mem_map(self, addr, size):
        self.offset = addr
        self._mem_map(size)

    def _mem_write(self, addr, data):
        if addr < 0:
            raise UcError("Memory address is negative")
        for i,d in enumerate(data):
            if addr+i >= len(self.memory):
                raise UcError("Out of memory")
            self.memory[addr+i] = data[i]

    def mem_write(self, addr, data):
        addr -= self.offset
        self._mem_write(addr, data)

    def _mem_read(self, addr, size):
        return self.memory[addr:addr+size]

    def mem_read(self, addr, size):
        addr -= self.offset
        return self._mem_read(addr, size)

    def _mem_read_ptr(self, addr):
        if addr <= self.stack_bot and addr >= self.stack_top:
            return self.stack.peek(addr)
        read = self.memory[addr:addr+self.ptr_size]
        return struct.unpack("<I", bytearray(read))[0]

    def mem_read_ptr(self, addr):
        addr -= self.offset
        return self._mem_read_ptr(addr)

    def reg_write(self, reg, data):
        if reg == UC_X86_REG_ESP:
            self.stack.set(data)
        self.registers[reg] = data % (2**32)

    def reg_read(self, reg):
        return self.registers[reg]

    def stack_push(self, value, size=0):
        if not size:
            size = self.ptr_size
        self.stack.push(value, size)
        self.reg_write(UC_X86_REG_ESP, self.stack.ptr)

    def _pre_start(self, addr_start, addr_end):
        cs = Cs(self.arch, self.mode)
        cs.detail = True
        size = addr_end-addr_start
        text = bytearray(self.mem_read(addr_start, size))
        for i in cs.disasm(text, addr_start):
            addr = i.address
            self.instructions[addr] = i

        self.registers[UC_X86_REG_EIP] = addr_start

    def emu_start(self, addr_start, addr_end):
        self._pre_start(addr_start, addr_end)
        count = 0
        while 1:
            done = self.step()
            if done or count > 200:
                break
            count += 1

    def emu_start_gen(self, addr_start, addr_end):
        self._pre_start(addr_start, addr_end)
        count = 0
        yield
        while 1:
            done = self.step()
            if done or count > 200:
                break
            count += 1
            yield

    def current_instruction(self):
        # get eip
        eip = self.reg_read(UC_X86_REG_EIP)

        # read instruction
        return self.instructions.get(eip)

    def next_instruction(self, i):
        addr = i.address
        return self.instructions.get(addr + len(i.bytes))

    def step(self):
        # get eip
        eip = self.reg_read(UC_X86_REG_EIP)

        # read instruction
        i = self.instructions.get(eip)

        # run callbacks
        self.run_callbacks(i)

        # if no instruction read, halt execution
        if not i:
            return True

        # record eip
        self.reg_write(UC_X86_REG_EIP, eip+len(i.bytes))

        # handle instruction
        self.execute_instruction(i)

    def hook_add(self, htype, callback):
        self.callbacks.append(callback)

    def execute_instruction(self, i):
        fn = InstructionHandler.get(bytes(i.bytes))
        fn(self, i)
        esp = self.reg_read(UC_X86_REG_ESP)
        ebp = self.reg_read(UC_X86_REG_EBP)

    def run_callbacks(self, i):
        self.callback_output = []
        for cb in self.callbacks:
            self.callback_output.append(cb(self, i))
