section .text
global _start
_start:
mov rax, 0x68732f6e69622f2f
push rax
xor rax, rax
mov al, 0x3b
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall
