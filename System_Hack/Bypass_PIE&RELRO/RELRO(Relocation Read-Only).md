# RELRO(Relocation Read-Only)

---

## 서론

- ELF는 GOT를 활용하여 반복되는 라이브러리 함수의 호출 비용을 줄인다고 했음
- GOT에 값을 채우는 방식은 다양함
    - Lazy Binding - 함수가 처음 호출될 때 함수의 주소를 구하고, 이를 GOT에 적는 방식
    - Lazy binding을 하는 바이너리는 실행 중에 GOT 테이블을 업데이트할 수 있어야 하므로 GOT에 쓰기 권한이 부여됨 → 바이너리를 취약하게 만드는 원인
- 또한, ELF의 데이터 세그먼트에는 프로세스의 **초기화 및 종료**와 관련된 `.init_array` , `.fini_array` 가 있음
    - 해당 영역들은 프로세스의 시작과 종료에 실행할 함수들의 주소를 저장하고 있음
    - 공격자가 임의로 값을 쓸 수 있다면, 프로세스의 실행 흐름이 조작될 수 있음
- **해당 문제를 해결하고자 RELocation Read-Only(RELRO)**을 개발
    - `RELRO` 는 쓰기 권한이 불필요한 데이터 세그먼트에 쓰기 권한을 제거함
    - `RELRO` 적용 범위에 따른 구분
        - Partial RELRO - 부분적으로 적용
        - Full RELRO - 가장 넓은 영역에 적용

## RELRO

### Partial RELRO

- relro 예제 코드
    - 자신의 메모리 맵을 출력하는 바이너리의 소스 코드

```python
// Name: relro.c
// Compile: gcc -o prelro relro.c -no-pie -fno-PIE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main() {
  FILE *fp;
  char ch;
  fp = fopen("/proc/self/maps", "r");
  while (1) {
    ch = fgetc(fp);
    if (ch == EOF) break;
    putchar(ch);
  }
  return 0;
}
```

### RELRO 검사

- gcc 는 Full RELRO를 기본 적용하며, PIE를 해제하면 Partial RELRO를 적용
- 바이너리의 RELRO 여부도 `checksec` 으로 검사할 수 있음

```python
$ gcc -o prelro -no-pie relro.c

$ checksec prelro
[*] '/home/dreamhack/prelro'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

### Partial RELRO 권한

- `prelro` 를 실행해보면, `0x404000` 부터 `0x405000` 까지의 주소에는 쓰기 권한이 있음을 확인
- **Partial RELRO 바이너리의 메모리 맵**

```bash
$ ./prelro
00400000-00401000 r--p 00000000 08:02 2886150                            /home/dreamhack/prelro
00401000-00402000 r-xp 00001000 08:02 2886150                            /home/dreamhack/prelro
00402000-00403000 r--p 00002000 08:02 2886150                            /home/dreamhack/prelro
00403000-00404000 r--p 00002000 08:02 2886150                            /home/dreamhack/prelro
00404000-00405000 rw-p 00003000 08:02 2886150                            /home/dreamhack/prelro
0130d000-0132e000 rw-p 00000000 00:00 0                                  [heap]
7f108632c000-7f108632f000 rw-p 00000000 00:00 0
7f108632f000-7f1086357000 r--p 00000000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086357000-7f10864ec000 r-xp 00028000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f10864ec000-7f1086544000 r--p 001bd000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086544000-7f1086548000 r--p 00214000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f1086548000-7f108654a000 rw-p 00218000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f108654a000-7f1086557000 rw-p 00000000 00:00 0
7f1086568000-7f108656a000 rw-p 00000000 00:00 0
7f108656a000-7f108656c000 r--p 00000000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f108656c000-7f1086596000 r-xp 00002000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f1086596000-7f10865a1000 r--p 0002c000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f10865a2000-7f10865a4000 r--p 00037000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f10865a4000-7f10865a6000 rw-p 00039000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffe55580000-7ffe555a1000 rw-p 00000000 00:00 0                          [stack]
7ffe555de000-7ffe555e2000 r--p 00000000 00:00 0                          [vvar]
7ffe555e2000-7ffe555e4000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

- 섹션 헤더를 참조해보면 해당 영역에는 `.got.plt` , `.data` , `.bss` 가 할당되어 있음
- 반면, `.init_array` 와 `.fini_array` 는 각각 `0x403e10` 과 `0x403e18` 에 할당되어 있는데 모두 쓰기 권한이 없는 `00403000-00404000` 사이에 존재하므로 쓰기가 불가능
- **Partial RELRO 바이너리의 섹션 헤더**

```python
$ objdump -h ./prelro

./prelro:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
...
 19 .init_array   00000008  0000000000403e10  0000000000403e10  00002e10  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 20 .fini_array   00000008  0000000000403e18  0000000000403e18  00002e18  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 21 .dynamic      000001d0  0000000000403e20  0000000000403e20  00002e20  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 22 .got          00000010  0000000000403ff0  0000000000403ff0  00002ff0  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .got.plt      00000030  0000000000404000  0000000000404000  00003000  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 24 .data         00000010  0000000000404030  0000000000404030  00003030  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 25 .bss          00000008  0000000000404040  0000000000404040  00003040  2**0
                  ALLOC
...
```

![Untitled](./RELRO(Relocation Read-Only).assets/Untitled.png)

### Full RELRO

- **Full RELRO 바이너리 checksec**

```python
$ gcc -o frelro relro.c

$ checksec frelro
[*] '/home/dreamhack/frelro'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- `frelro` 를 실행하여 메모리 맵을 확인하고, 이를 섹션 헤더 정보와 종합해보면 `got`에는 쓰기 권한이 제거되어 있으며 `data`와 `bss`에만 쓰기 권한이 있음

```python
$ ./frelro
563782c64000-563782c65000 r--p 00000000 08:02 2886178                    /home/dreamhack/frelro
563782c65000-563782c66000 r-xp 00001000 08:02 2886178                    /home/dreamhack/frelro
563782c66000-563782c67000 r--p 00002000 08:02 2886178                    /home/dreamhack/frelro
563782c67000-563782c68000 r--p 00002000 08:02 2886178                    /home/dreamhack/frelro
563782c68000-563782c69000 rw-p 00003000 08:02 2886178                    /home/dreamhack/frelro
563784631000-563784652000 rw-p 00000000 00:00 0                          [heap]
7f966f91f000-7f966f922000 rw-p 00000000 00:00 0
7f966f922000-7f966f94a000 r--p 00000000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966f94a000-7f966fadf000 r-xp 00028000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fadf000-7f966fb37000 r--p 001bd000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb37000-7f966fb3b000 r--p 00214000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb3b000-7f966fb3d000 rw-p 00218000 08:02 132492                     /usr/lib/x86_64-linux-gnu/libc.so.6
7f966fb3d000-7f966fb4a000 rw-p 00000000 00:00 0
7f966fb5b000-7f966fb5d000 rw-p 00000000 00:00 0
7f966fb5d000-7f966fb5f000 r--p 00000000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb5f000-7f966fb89000 r-xp 00002000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb89000-7f966fb94000 r--p 0002c000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb95000-7f966fb97000 r--p 00037000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f966fb97000-7f966fb99000 rw-p 00039000 08:02 132486                     /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffc1bace000-7ffc1baef000 rw-p 00000000 00:00 0                          [stack]
7ffc1bb22000-7ffc1bb26000 r--p 00000000 00:00 0                          [vvar]
7ffc1bb26000-7ffc1bb28000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

- 또한 `.data` 섹션의 오프셋은 `0x4000` 임
- 이를  `/home/dreamhack/frelro` 가 매핑된 `0x563782c64000` 에 더하면, `0x563782c68000` 이 되며, 이는 쓰기 권한이 있는 영역에 속함
- `.bss` 섹션 역시 동일한 방법으로 매핑된 주소를 계산해보면 `0x563782c68010` 가 나오며 마찬가지로 쓰기 권한이 존재하는 영역에 속함(`0x4010`)

```python
$ objdump -h ./frelro

./frelro:     file format elf64-x86-64

Sections:
Idx Name          Size      VMA               LMA               File off  Algn
...
 20 .init_array   00000008  0000000000003da8  0000000000003da8  00002da8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 21 .fini_array   00000008  0000000000003db0  0000000000003db0  00002db0  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 22 .dynamic      000001f0  0000000000003db8  0000000000003db8  00002db8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .got          00000058  0000000000003fa8  0000000000003fa8  00002fa8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 24 .data         00000010  0000000000004000  0000000000004000  00003000  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 25 .bss          00000008  0000000000004010  0000000000004010  00003010  2**0
                  ALLOC
...
```

- Full RELRO가 적용되면 라이브러리 함수들의 주소가 바이너리의 로딩 시점에 모두 바인딩 됨
- **따라서 GOT에는 쓰기 권한이 부여되지 않음**

## RELRO 우회

### RELRO 기법 우회

- Partial RELRO의 경우
    - `.init_array` 와 `.fini_array` 에 대한 쓰기 권한이 제거되어 두 영역을 덮어쓰는 공격을 수행하기 어려워짐
    - `.got.plt` 영역에 대한 쓰기 권한이 존재하므로 **GOT overwrite** 공격을 활용할 수 있음
- Full RELRO의 경우
    - `.init_array` , `.fini_array`뿐만 아니라 `.got` 영역에도 쓰기권한이 제거 됨 → 다른 함수 포인터를 찾다가 hook을 찾아냄
    - 라이브러리 함수의 대표적인 hook이 malloc hook과 free hook임
        - 원래 해당 함수 포인터는 동적 메모리의 할당과 해제 과정에서 발생하는 버그를 디버깅하기 쉽게 하려고 만들어짐
        - `malloc` 함수의 코드를 살펴보면, 함수의 시작 부분에서 `__malloc_hook` 이 존재하는지 검사하고, 존재하면 이를 호출함
        - `__malloc_hook` 은 [`libc.so`](http://libc.so) 에서 쓰기 가능한 영역에 위치함
        - 따라서 공격자는 libc가 매핑된 주소를 알 때, 이 변수를 조작하고 `malloc` 을 호출하여 실행 흐름을 조작할 수 있음
        - 이와 같은 공격 기법을 통틀어 **Hook Overwrite**라고 부름
- **glibc malloc 소스 코드**

```c
void *
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook); // read hook
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0)); // call hook
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes;
  checked_request2size (bytes, tbytes);
  size_t tc_idx = csize2tidx (tbytes);
  // ...
```