// Name: sigrt_call.c
// Compile: gcc -o sigrt_call sigrt_call.c 
#include <string.h>

int main()
{
        char buf[1024];
        memset(buf, 0x41, sizeof(buf));

        asm("mov $15, %rax;"
            "syscall");
}