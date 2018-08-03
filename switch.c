#include	<stdio.h>
#include	<stdlib.h>
#include	<signal.h>
#include	<sys/mman.h>
#include        <sys/syscall.h>

# define __get_tls() ({ void** __val; __asm__("mrc p15, 0, %0, c13, c0, 3" : "=r"(__val)); __val; })
void	*export_kill(unsigned int *size);
typedef int (*killfn)(int, int);

void saction(int signo, siginfo_t *siginfo, void *context){
	ucontext_t *pctx;
	mcontext_t *mctx;
	
	pctx = context;
	mctx = &pctx->uc_mcontext;
	mctx->arm_cpsr &= ~(1<<4);
	return;
}

int main(){
	struct	sigaction sa;
	struct	sigaction old;
	void	*killcode;
	killfn	fn;
	void	*buff;
	void	*raw_code;
	unsigned int raw_code_size;
	void    *tls;
	        
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = saction;

	sigaction(SIGUSR1, &sa, &old);
	
	buff = mmap(0, 0x100000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	raw_code = export_kill(&raw_code_size);
	memcpy(buff, raw_code, raw_code_size);
	
	syscall(__ARM_NR_cacheflush, buff, (unsigned long)buff + 0x100000, 0);
	tls = __get_tls();
	fn = (killfn)buff;        
	fn(getpid(), SIGUSR1);
	__set_tls(tls);
		
	printf("And I'm back baby...\n");
	return 0;
}
