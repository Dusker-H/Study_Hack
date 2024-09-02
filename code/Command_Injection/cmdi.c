// Name: cmdi.c
// Compile: gcc -o cmdi cmdi.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const int kMaxIpLen = 36;
const int kMaxCmdLen = 256;

int main() {
  char ip[kMaxIpLen];
  char cmd[kMaxCmdLen];

  // Initialize local vars
  memset(ip, '\0', kMaxIpLen);
  memset(cmd, '\0', kMaxCmdLen);
  strcpy(cmd, "ping -c 2 ");

  // Input IP
  printf("Health Check\n");
  printf("IP: ");
  fgets(ip, kMaxIpLen, stdin);

  // Construct command
  strncat(cmd, ip, kMaxCmdLen);
  printf("Execute: %s\n",cmd);

  // Do health-check
  system(cmd);

  return 0;
}