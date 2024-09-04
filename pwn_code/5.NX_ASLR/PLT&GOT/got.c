// Name: got.c
// Compile: gcc -o got got.c -no-pie

#include <stdio.h>

int main() {
  puts("Resolving address of 'puts'.");
  puts("Get address from GOT");
}