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