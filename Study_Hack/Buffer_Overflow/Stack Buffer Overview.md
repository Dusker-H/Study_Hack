# Stack Buffer Overview

---

## 스택 오버플로우와 스택 버퍼 오버플로우의 차이

- 스택 오버플로우는 스택 영역이 너무 확장되서 발생하는 버그
- 스택 버퍼 오버플로우는 스택에 위치한 버퍼에 버퍼의 크기보다 많은 데이터가 입력되어 발생하는 버그

## 스택 버퍼 오버플로우

- 스택에 버퍼에서 발생하는 오버플로우
    - 버퍼 - 데이터가 목적지로 이동하기 전에 보관되는 임시 저장소
- 버퍼 오버플로우 위협
    - 중요 데이터 변조
    - 데이터 유출
        - C언어에서 정상적인 문자열은 널바이트로 종결
            - 만약 어떤 버퍼에 오버플로우를 발생시켜 다른 버퍼와의 사이에 있는 널바이트를 모두 제거하면?
            - 해당 버퍼를 출력시켜 다른 버퍼의 데이터를 읽을 수 있음
    - 실행 흐름 조작
        - 함수의 반환 주소를 조작하여 프로세스의 실행 흐름을 변경

## 중요 데이터 변조

### 스택 버퍼 오버플로우 예제

- **Figure3**의 `main` 함수는 `argv[1]`을 `check_auth` 함수의 인자로 전달한 후, 반환 값을 받아옵니다. 이 때, 반환 값이 0이 아니라면 "Hello Admin!"을, 0이라면 "Access Denied!"라는 문자열을 출력합니다.
- `check_auth`함수에서는 16 바이트 크기의 `temp`버퍼에 입력받은 패스워드를 복사한 후, 이를 "SECRET_PASSWORD" 문자열과 비교합니다. 문자열이 같다면 `auth`를 1로 설정하고 반환합니다.
- 그런데 `check_auth`에서 `strncpy` 함수를 통해 `temp`버퍼를 복사할 때, `temp`의 크기인 16 바이트가 아닌 인자로 전달된 `password`의 크기만큼 복사합니다. 그러므로  `argv[1]`에 16 바이트가 넘는 문자열을 전달하면, 이들이 모두 복사되어 스택 버퍼 오버플로우가 발생하게 됩니다.
- `auth`는 `temp`버퍼의 뒤에 존재하므로, `temp`버퍼에 오버플로우를 발생시키면 `auth`의 값을 0이 아닌 임의의 값으로 바꿀 수 있습니다. 이 경우, 실제 인증 여부와는 상관없이 `main`함수의 `if(check_auth(argv[1]))` 는 항상 참이 됩니다

```c
// Name: sbof_auth.c
// Compile: gcc -o sbof_auth sbof_auth.c -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int check_auth(char *password) {
    int auth = 0;
    char temp[16];
    
    strncpy(temp, password, strlen(password));
    
    if(!strcmp(temp, "SECRET_PASSWORD"))
        auth = 1;
    
    return auth;
}
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: ./sbof_auth ADMIN_PASSWORD\n");
        exit(-1);
    }
    
    if (check_auth(argv[1]))
        printf("Hello Admin!\n");
    else
        printf("Access Denied!\n");
}
```

## 데이터 유출

### 스택 버퍼 오버플로우와 메모리 릭

- **Figure5**에서, 8바이트 크기의 `name` 버퍼에 12바이트의 입력을 받습니다.
- 읽고자 하는 데이터인 `secret`버퍼와의 사이에 `barrier`라는 4바이트의 널 배열이 존재하는데, 오버플로우를 이용하여 널 바이트를 모두 다른 값으로 변경하면 `secret`을 읽을 수 있습니다.

```c
// Name: sbof_leak.c
// Compile: gcc -o sbof_leak sbof_leak.c -fno-stack-protector
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(void) {
  char secret[16] = "secret message";
  char barrier[4] = {};
  char name[8] = {};
  memset(barrier, 0, 4);
  printf("Your name: ");
  read(0, name, 12);
  printf("Your name is %s.", name);
}
```

## 실행 흐름 조작

### 스택 버퍼 오버플로우를 통한 반환 주소 덮어쓰기

```c
// Name: sbof_ret_overwrite.c
// Compile: gcc -o sbof_ret_overwrite sbof_ret_overwrite.c -fno-stack-protector
#include <stdio.h>
#include <stdlib.h>
int main(void) {
    char buf[8];
    printf("Overwrite return address with 0x4141414141414141: ");
    gets(buf);
    return 0;
}
```

---