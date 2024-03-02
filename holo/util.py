import binascii


def prettify(bts):
    return b' '.join([binascii.hexlify(bytes([b])) for b in bts]).decode()

def extstr(s, l, pad=' '):
    if len(s) > l:
        return s[:l]
    while len(s) < l:
        s += pad
    return s

def fmt(i):
    addr = extstr("0x%x:"%i.address, 10)
    bts = extstr(prettify(i.bytes), 24)
    mne = extstr(i.mnemonic, 16)
    ostr = i.op_str
    return f"{addr}{bts}{mne}{ostr}"


