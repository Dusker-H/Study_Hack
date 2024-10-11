// Name: fs.c
// Compile: gcc -o fs fs.c
#include <stdio.h>
int main() {
  int num;
  printf("%8d\n", 123);            // "     123"
  printf("%s\n", "Hello, world");  // "Hello, world"
  printf("%x\n", 0xdeadbeef);      // "deadbeef"
  printf("%p\n", &num);            // "0x7ffe6d1cb2c4"
  printf("%s%n: hi\n", "Alice", &num);  // "Alice: hi", num = 5
  printf("%*s: hello", num, "Bob");  // "  Bob: hello "
  printf("%s", "test");
  return 0;
}