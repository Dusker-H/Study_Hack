// Name: strict_mode.c
// Compile: gcc -o strict_mode strict_mode.c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <unistd.h>
void init_filter() { prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT); }
int main() {
  char buf[256];
  int fd = 0;
  init_filter();
  write(1, "OPEN!\n", 6);
  fd = open("/bin/sh", O_RDONLY);
  write(1, "READ!\n", 6);
  read(fd, buf, sizeof(buf) - 1);
  write(1, buf, sizeof(buf));
  return 0;
}