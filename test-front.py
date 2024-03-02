from holo.winemulator import WinEmulator
from holo.const import *
from holo.util import fmt

import curses


def main(stdscr):
    path = 'exe/consoleapp.exe'
    mu = WinEmulator(UC_ARCH_X86, UC_MODE_32)
    mu.init_pe(path)
    callback_gen = mu.start_singlestep()

    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK) #linechange
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE) #oldline
    curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK) #instruction

    stdscr.clear()
    height,width = stdscr.getmaxyx()
    stdscr.refresh()

    reg_h, reg_w = 15, 40
    reg_y, reg_x = 0, width-reg_w
    reg_wrap = stdscr.subwin(reg_h, reg_w, reg_y, reg_x)
    reg_wrap.box()
    reg_wrap.addstr(0, 2, "Registers", curses.color_pair(2))
    reg_wrap.refresh()
    reg = reg_wrap.subwin(reg_h-2, reg_w-2, reg_y+1, reg_x+1)
    reg.refresh()

    ins_h, ins_w = height-2, 90
    ins_y, ins_x = 0, 0
    ins_wrap = stdscr.subwin(ins_h, ins_w, ins_y, ins_x)
    ins_wrap.box()
    ins_wrap.addstr(0, 2, "Instructions", curses.color_pair(2))
    ins_wrap.refresh()
    ins = ins_wrap.subwin(ins_h-2, ins_w-2, ins_y+1, ins_y+1)
    ins.refresh()

    stdscr.addstr(height-1, 0, ": ")

    # Cursor
    cur_y, cur_x = 0,0
    stdscr.move(cur_y, cur_x)

    while True:
        try:
            c = stdscr.getch()
        except KeyboardInterrupt:
            return

        if c == ord('j') or c == curses.KEY_DOWN:
            cur_y = min(cur_y+1, height-1)
        elif c == ord('k') or c == curses.KEY_UP:
            cur_y = max(cur_y-1, 0)
        elif c == ord('h') or c == curses.KEY_LEFT:
            cur_x = max(cur_x-1, 0)
        elif c == ord('l') or c == curses.KEY_RIGHT:
            cur_x = min(cur_x+1, width-1)


        if c == ord('\n'):
            try:
                uc = next(callback_gen)
            except StopIteration:
                return

            ins.erase()
            reg.erase()

            reg_output = mu.dump_regs(uc, None)
            for i,line in enumerate(reg_output.split('\n')):
                reg.addstr(2+i, 2, line)

            eip = uc.registers[UC_X86_REG_EIP]
            i = uc.current_instruction()

            count = 20
            for idx in range(count):
                ins_output = fmt(i)
                ins.addstr(2+idx, 4, ins_output)
                i = uc.next_instruction(i)

            ins.addstr(2, 1, "=>", curses.color_pair(1))

        stdscr.move(cur_y, cur_x)
        # Cursor
        #stdscr.move(height-1, 2)

        # Refresh
        ins.refresh()
        reg.refresh()
        stdscr.refresh()


if __name__ == "__main__":
    curses.wrapper(main)
