// File name: sh-skeleton.c
// Compile Option: gcc -o sh-skeleton sh-skeleton.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"

    "Input your shellcode here.\n"
    "Each line of your shellcode should be\n"
    "seperated by '\n'\n"

    "xor rdi, rdi   # rdi = 0\n"
    "mov rax, 0x3c	# rax = sys_exit\n"
    "syscall        # exit(0)");

void run_sh();

int main() { run_sh(); }