from fmtstr import fmtstr_payload
from pwn import *
context(arch='amd64')

def main():
    writes = {
        0x8048ae0: 0xdeadbeef
    }
    payload = fmtstr_payload(offset=6, write_size='byte')
    print(payload)

if __name__ == "__main__":
    main()