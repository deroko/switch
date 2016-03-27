#include	<stdio.h>
#include	<stdlib.h>
#include	<signal.h>
#include	<sys/mman.h>

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

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = saction;

	sigaction(SIGUSR1, &sa, &old);
	buff = mmap(0, 0x100000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	raw_code = export_kill(&raw_code_size);
	memcpy(buff, raw_code, raw_code_size);
	fn = (killfn)buff;
	fn(getpid(), SIGUSR1);	
	printf("And I'm back baby...\n");
	return 0;
}
