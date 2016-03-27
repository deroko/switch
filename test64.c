#include	<stdio.h>
#include	<stdlib.h>
#include	<sys/ptrace.h>
#include	<asm/ptrace.h>
#include	<android/log.h>
#include	<inttypes.h>
#include	<elf.h>
#include	<linux/uio.h>
#include        <sys/syscall.h>
#include        <sys/wait.h>
#include        <sys/mman.h>
#include        <fcntl.h>
#include        <sys/stat.h>
#include	<signal.h>

void	testarm64();

typedef void (*testarm64fn)();
void    *export_testarm64(unsigned long *size);

int main(){

        testarm64fn     fn;
        void            *testarm64raw;
        unsigned long   testarm64_len;
                
                
        
        fn = (testarm64fn)mmap(0, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        memcpy((void *)fn, testarm64raw, testarm64_len);
        
        asm("brk #0\n");
        fn();
}
	
