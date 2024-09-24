// Name: bypass_secbpf.c
// Compile: gcc -o bypass_secbpf bypass_secbpf.c
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#define DENY_SYSCALL(name)                                \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##name, 0, 1), \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)
#define MAINTAIN_PROCESS BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
/* architecture x86_64 */
#define ARCH_NR AUDIT_ARCH_X86_64
void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}
int sandbox() {
  struct sock_filter filter[] = {
      /* Validate architecture. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, arch_nr),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARCH_NR, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
      /* Get system call number. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, syscall_nr),
      /* List allowed syscalls. */
      DENY_SYSCALL(open),
      DENY_SYSCALL(openat),
      DENY_SYSCALL(read),
      DENY_SYSCALL(write),
      DENY_SYSCALL(vfork),
      DENY_SYSCALL(fork),
      DENY_SYSCALL(clone),
      DENY_SYSCALL(execve),
      DENY_SYSCALL(execveat),
      MAINTAIN_PROCESS,
  };
  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    perror("prctl(PR_SET_NO_NEW_PRIVS)\n");
    return -1;
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("Seccomp filter error\n");
    return -1;
  }
  return 0;
}
int main(int argc, char *argv[]) {
  void *shellcode = mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  void (*sc)();
  init();
  memset(shellcode, 0, 0x1000);
  printf("shellcode: ");
  read(0, shellcode, 0x1000);
  sandbox();
  sc = (void *)shellcode;
  sc();
}