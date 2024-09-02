// Name: dfb.c
// Compile: gcc -o dfb dfb.c
#include <stdio.h>
#include <stdlib.h>
int main() {
  char *chunk;
  chunk = malloc(0x50);
  printf("Address of chunk: %p\n", chunk);
  free(chunk);
  free(chunk); // Free again
}