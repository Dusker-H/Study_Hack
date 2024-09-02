// Name: fsb_aar.c
// Compile: gcc -o fsb_aar fsb_aar.c
#include <stdio.h>
const char *secret = "THIS IS SECRET";
int main() {
  char format[0x100];
  printf("Address of `secret`: %p\n", secret);
  printf("Format: ");
  scanf("%[^\n]", format);
  printf(format);
  return 0;
}