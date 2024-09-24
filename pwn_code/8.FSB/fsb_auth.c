// fsb_auth.c
#include <stdio.h>

int main(void) {
    int auth = 0x42424242;
    char buf[32] = {0, };
    
    read(0, buf, 32);
    printf(buf);
    
    // make auth to 0xff
}