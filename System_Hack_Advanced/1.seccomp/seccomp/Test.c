// Test.c

# include <stdio.h>
# include <linux/seccomp.h>

int strict_mode = SECCOMP_MODE_STRICT;
int filter_mode = SECCOMP_MODE_FILTER;

int main(){
    printf("%d %d\n", strict_mode, filter_mode);
    return 0;
}
