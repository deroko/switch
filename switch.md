# From AArch32 to AArch64 and back

### deroko of ARTeam

I was thinking whether it was possible to call AArch64 (64-bit ARM architecture) syscalls from AArch32 (32-bit ARM architecture). While looking through code and reading specs it seemed it was. The specs were claiming it could be done only on exception level, eg. from `EL0` to `EL1` and viceversa. Looking at the specs, it turns out that if `CPSR` has the `M[4]` bit set it's AArch32, and if it's `0` in `PSTATE` we are AArch64. `PSTATE` or `Process State` is the `flags` register for AArch64, while `CPSR` is the `Current Program Status Register`, or `flags` register in AArch32.

The only way as it seems is to change `M[4]` bit when we are coming back from `EL1` to `EL0`, so we can do that through raising a signal and modifying `ucontext_t`. Another way would be to `fork` and `ptrace` to change `CPSR`, but in this article I'll focus on switching mode within the same process.

First I've looked at `rt_sigreturn` in the kernel source code. `rt_sigreturn` is used to restore context after signal is being handled. It's held in `VDSO` (virtual dynamic shared object which is mapped in every user process), and when delivering the signal, kernel will point `PC` to installed handler, but return address (`LR` or `X30`) will be pointing at `sys_rt_sigreturn` in `VDSO`, which will restore registers from `ucontext_t` and continue.
*arch/arm64/kernel/signal.c* and *signal32.c*:

`sys_rt_sigreturn` at some point calls `restore_sig_frame`:

```C
  if (restore_sigframe(regs, frame))
    goto badframe;
...
	for (i = 0; i < 31; i++)
			__get_user_error(regs->regs[i], &sf->uc.uc_mcontext.regs[i],err);
		__get_user_error(regs->sp, &sf->uc.uc_mcontext.sp, err);
		__get_user_error(regs->pc, &sf->uc.uc_mcontext.pc, err);
		__get_user_error(regs->pstate, &sf->uc.uc_mcontext.pstate, err);
```

Copies what is in `ucontext` to the registers saved on the stack, similar code we can see in *signal32.c* where the 32bit version is called `compat_sys_rt_sigreturn`:

```C
	if (compat_restore_sigframe(regs, &frame->sig))
		goto badframe;
...
	__get_user_error(regs->regs[0], &sf->uc.uc_mcontext.arm_r0, err);
	__get_user_error(regs->regs[1], &sf->uc.uc_mcontext.arm_r1, err);
	__get_user_error(regs->regs[2], &sf->uc.uc_mcontext.arm_r2, err);
	__get_user_error(regs->regs[3], &sf->uc.uc_mcontext.arm_r3, err);
	__get_user_error(regs->regs[4], &sf->uc.uc_mcontext.arm_r4, err);
	__get_user_error(regs->regs[5], &sf->uc.uc_mcontext.arm_r5, err);
	__get_user_error(regs->regs[6], &sf->uc.uc_mcontext.arm_r6, err);
	__get_user_error(regs->regs[7], &sf->uc.uc_mcontext.arm_r7, err);
	__get_user_error(regs->regs[8], &sf->uc.uc_mcontext.arm_r8, err);
	__get_user_error(regs->regs[9], &sf->uc.uc_mcontext.arm_r9, err);
	__get_user_error(regs->regs[10], &sf->uc.uc_mcontext.arm_r10, err);
	__get_user_error(regs->regs[11], &sf->uc.uc_mcontext.arm_fp, err);
	__get_user_error(regs->regs[12], &sf->uc.uc_mcontext.arm_ip, err);
	__get_user_error(regs->compat_sp, &sf->uc.uc_mcontext.arm_sp, err);
	__get_user_error(regs->compat_lr, &sf->uc.uc_mcontext.arm_lr, err);
	__get_user_error(regs->pc, &sf->uc.uc_mcontext.arm_pc, err);
	__get_user_error(regs->pstate, &sf->uc.uc_mcontext.arm_cpsr, err);
```
As seen here, there is no sanity check on `M[4]` in `CPSR` or `PSTATE`, so we can set the saved pstate to whatever we want and alter the mode of execution on return from the user mode signal handler.
Let's put this to practice.

```C
void saction(int signo, siginfo_t *siginfo, void *context){
	ucontext_t *pctx;
	mcontext_t *mctx;

	pctx = context;
	mctx = &pctx->uc_mcontext;
	mctx->arm_cpsr &= ~(1<<4);              <--- wipe M[4]
	fflush(stdout);
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
	kill(getpid(), SIGUSR1);
	return 0;
}
```

What happens is that we will end up right after `SVC` in `kill()`, but running as AArch64. `SVC` is way of executing syscalls on ARM or AArch64, and here is example from *libc.so* and `kill()`:

```
.text:00041C04 kill                                   
.text:00041C04                 MOV             R12, R7
.text:00041C08                 MOV             R7, #0x25        <--- syscall number in R7
.text:00041C0C                 SVC             0                <--- call into kernel
.text:00041C10                 MOV             R7, R12          <--- return after signal
                                               if PC in not modified
```

Good. But how can we verify that we are actually running 64-bit code?

We can write AArch64 assembly to print something to the shell and we'll find out:

```asm
		adr	x0, msg
		bl	__strlen
		mov	x2, x0
		adr	x1, msg
		eor	x0, x0, x0
		add	x0, x0, 1
		mov	x8, 64		<--- __NR_write
		svc	0
		dbg:  b dbg		<--- hang program or call exit()

__strlen:
		mov	x1, x0
		mov	x2, x0
__looplen:
		ldrb	w0, [x1],#1
		cbnz    w0, __looplen
		sub	x0, x1, x2
		ret
msg:  .asciz	"tada - executed as AArch64 from AArch32\n"		
```

Hopefully, we will be greeted with this message, but how do we go back to the AArch32 mode? We need to setup another signal handler, call `kill()`, and we will again have access to our `ucontext_t`, but this time from AArch64 code.

What I was expecting (without having read the source code) was that the signal delivered would be for AArch64, but I was wrong, we get a signal delivered for the AArch32 handler.

Code from *signal.c/handle_signal*:

```C
	if (is_compat_task()) {
		if (ka->sa.sa_flags & SA_SIGINFO)
			ret = compat_setup_rt_frame(usig, ka, info, oldset, regs);
		else
			ret = compat_setup_frame(usig, ka, oldset, regs);
	} else {
		ret = setup_rt_frame(usig, ka, info, oldset, regs);
	}
```
where `is_compat_task()` is defined as:
```C
static inline int is_compat_task(void)
{
	return test_thread_flag(TIF_32BIT);
}
```

Even if we are running as AArch64, every signal delivered to this program will set up a stack frame, and registers as if we are still in AArch32 program. This comes from fact that `TIF_32BIT` flag is set in the thread flags which indicates that we are running as a 32-bit program.

Here we can see `LR` while we are in AArch64 code during signal handling, and indeed it is pointing to `sys_rt_sigreturn` in AArch32 `VDSO` (the instructions displayed in the disassembly are wrong, since we are executing AArch64 code)

```
--------------------------------------------------------------------------[regs]
R0:  0x00000010  R1: 0x46508001  R2:  0x00000210  R3:  0xFFFEC860
R4:  0x00000000  R5: 0xF7480000  R6:  0x00000001  R7:  0x00000025
R8:  0x00000081  R9: 0x00000000  R10: 0x00000000  R11: 0xFFFEF88C
R12: 0xAAE483B8  SP: 0xFFFEF478  LR:  0xFFFF050C  PC:  0xF7480168  n z c v q j e a i f t
--------------------------------------------------------------------------[code]
=> 0xf7480168:	strne	r0, [r0], #-0
0xf748016c:	addle	r1, r0, #26
0xf7480170:	strle	r0, [r0], #-1
0xf7480174:	ldrble	r0, [pc], -r0, asr #7
0xf7480178:	addle	r1, r0, #200, 0	; 0xc8
0xf748017c:	strle	r0, [r0], #-1
0xf7480180:	ldrble	r0, [pc], -r0, asr #7
0xf7480184:	addle	r1, r0, #136, 10	; 0x22000000
--------------------------------------------------------------------------------
0xf7480168 in ?? ()
gdb$ x/10i $lr
0xffff050c:	mov	r7, #173, 0	; 0xad  <--- rt_sigreturn for AArch32
0xffff0510:	svc	0x000000ad
0xffff0514:	svcle	0x00ad27ad
0xffff0518:	andeq	r0, r0, r0
```

Since we are now executing AArch64 code, obviously we can't simply return from the signal handler, nor can we use `LR` or `X14` to to return to `sys_rt_sigreturn` code. If we would use a AArch64 `RET` to return from the signal handler where `LR` is `X30`, we would probably end up in a loop since `X30` is holding the address of our last call from AArch64 (if we made any).

What needs to be done is to rebuild the complete `rt_sigframe` as defined in *arch/arm64/kernel/signal.c* and directly invoke `rt_sigreturn` for AArch64. What is important to note here is that `X13` has our AArch32 `SP`, so accessing `SP` via AArch64 is wrong, you don't end up with the same register! The same is true for `LR` which in AArch32 is an alias for the register `X14`, while on AArch64 it's an alias for `X30`.

So let's look at `rt_sigreturn` from *arch/arm64/kernel/entry.s*:

```C
/*
* Special system call wrappers.
*/
ENTRY(sys_rt_sigreturn_wrapper)
mov	x0, sp
b	sys_rt_sigreturn
ENDPROC(sys_rt_sigreturn_wrapper)
```
...

```C
asmlinkage long sys_rt_sigreturn(struct pt_regs *regs)
{
struct rt_sigframe __user *frame;

/* Always make any pending restarted system calls return -EINTR */
current_thread_info()->restart_block.fn = do_no_restart_syscall;

/*
* Since we stacked the signal on a 128-bit boundary, then 'sp' should
* be word aligned here.
*/
if (regs->sp & 15)
goto badframe;

frame = (struct rt_sigframe __user *)regs->sp;

...
}
```

and `rt_sigframe` is:

```C
struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
	u64 fp;
	u64 lr;
};
```

What needs to be done here is to make sure that before calling `rt_sigreturn` `SP` points to `rt_sigframe` which we will build on stack. In this case we can ignore `siginfo`, as the kernel doesn't care about it, so we won't either.

*include/asm/ucontext.h*
```C
struct ucontext {
	unsigned long		uc_flags;
	struct ucontext		*uc_link;
	stack_t				uc_stack;     <--- handled by do_sigaltstack in kernel/signal.c
	sigset_t			uc_sigmask;
	// glibc uses a 1024-bit sigset_t
	__u8				__unused[1024 / 8 - sizeof(sigset_t)];
	//last for future expansion
	struct sigcontext uc_mcontext;
}
```

*include/uapi/asm/sigcontext.h*
```C
struct sigcontext {
	__u64 fault_address;
	//AArch64 registers
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;
	// 4K reserved for FP/SIMD state and future expansion
	__u8 __reserved[4096] __attribute__((__aligned__(16)));
}
```

Now that we know all of this, we can rebuild our `rt_sigframe`. First, we need to borrow `uc_stack`, as it will be checked by `do_sigaltstack`. We can do this by simply taking old data from the AArch32 `uc_stack`. We have to do this as during the `rt_sigreturn` we will end up in `do_sigaltstack` from *kernel/signal.c* which uses `uc_stack`, so we try to make it valid. Or we could set `us_stack.ss_flags` to `SS_DISABLED` and don't care about `uc_stack` at all, but I tried to make it as flexible as it could be.

*kernel/signal.c*

```C
...
		if (ss_flags != SS_DISABLE && ss_flags != SS_ONSTACK && ss_flags != 0)
			goto out;

		if (ss_flags == SS_DISABLE) {
			ss_size = 0;
			ss_sp = NULL;
		} else {
			error = -ENOMEM;
			if (ss_size < MINSIGSTKSZ)
				goto out;
		}
...
```

`sa_sigaction` prototype:
```C
void sa_sigaction(int signo, siginfo *psiginfo, void *ctx);
		signo     = x0 or r0
		psiginfo  = x1 or r1
		ctx       = x2 or r2  <-- ucontext_t

		ldr     w0, [x2, #8]		//uc_stack.ss_sp
		ldr     w1, [x2, #16]		//uc_stack.ss_size
									//at offset 12 we have ss_flags but we keep
									//them 0
```

The next thing is that we will get AArch32 `SP` and use it as our own `SP` pointer as `SP` in AArch64 is not the same as our `SP`. Note that we shouldn't touch `X13` during code execution in AArch64 mode to preserve AArch32 `SP`, and to enable easy transition from AArch64 to AArch32, as on AArch32 `SP` we can save registers prior to the switch to AArch64 code. Of course, AArch32 `SP` can be saved in a global variable and restored, while we could allocate the AArch64 stack using the `mmap` syscall.

Later on we can just fill in all registers in `ucontext_t`:
```asm
                mov     x4, 31
__store_gen_regs:
                str     xzr, [x19], #8          //all registers to 0
                cmp     x4, 31-13               
                bne     __cntloop
                str     x2, [x19, #-8]          //fill in sp for aarch32 or X13
__cntloop:
				subs    x4, x4, 1
                bne     __store_gen_regs
                
                str     xzr, [x19], #8          //store sp, this will not be really used
                                                //but good to have it for later...
                adr     x0, testarm64_end
                str     x0, [x19], #8           //store pc after kill()
                mov     x0, 0x10                //set AArch32 M[4] bit in pstate
				str     x0, [x19], #8 
```

Ok, everything seems to be fine: we run the code, return from the signal and we return to the correct AArch32 instruction, but why do we get a `SIGSEGV`?

If any function called by `sys_rt_sigreturn` returns error, `sys_rt_sigreturn` will always result in a `SIGSEGV`:

```C
badframe:
	if (show_unhandled_signals)
		pr_info_ratelimited("%s[%d]: bad frame in %s: pc=%08llx sp=%08llx\n",
				    current->comm, task_pid_nr(current), __func__,
				    regs->pc, regs->sp);
	force_sig(SIGSEGV, current);
	return 0;
}
```

Because of this code which is called from `sys_rt_sigreturn` -> `restore_sigframe` from *arch/arm64/kernel/signal.c* we need to work more with the context:

```C
static int restore_sigframe(struct pt_regs *regs,
      struct rt_sigframe __user *sf)
{
	sigset_t set;
	int i, err;
	void *aux = sf->uc.uc_mcontext.__reserved;

	err = __copy_from_user(&set, &sf->uc.uc_sigmask, sizeof(set));
	if (err == 0)
		set_current_blocked(&set);

	for (i = 0; i < 31; i++)
		__get_user_error(regs->regs[i], &sf->uc.uc_mcontext.regs[i],
				 err);
	__get_user_error(regs->sp, &sf->uc.uc_mcontext.sp, err);
	__get_user_error(regs->pc, &sf->uc.uc_mcontext.pc, err);
	__get_user_error(regs->pstate, &sf->uc.uc_mcontext.pstate, err);

	/*
	 * Avoid sys_rt_sigreturn() restarting.
	 */
	regs->syscallno = ~0UL;

	err |= !valid_user_regs(&regs->user_regs);

	if (err == 0) {
		struct fpsimd_context *fpsimd_ctx =
			container_of(aux, struct fpsimd_context, head);
		err |= restore_fpsimd_context(fpsimd_ctx);      <--- will give us ERROR
	}

	return err;
}
```

and from `restore_fpsimd_context`:

```C
	__get_user_error(magic, &ctx->head.magic, err);
	__get_user_error(size, &ctx->head.size, err);
	if (err)
		return -EFAULT;
	if (magic != FPSIMD_MAGIC || size != sizeof(struct fpsimd_context))
		return -EINVAL;

	/* copy the FP and status/control registers */
	err = __copy_from_user(fpsimd.vregs, ctx->vregs,
			       sizeof(fpsimd.vregs));
	__get_user_error(fpsimd.fpsr, &ctx->fpsr, err);
	__get_user_error(fpsimd.fpcr, &ctx->fpcr, err);
```

where `FPSIMD_MAGIC` is defined as:

```C
struct _aarch64_ctx {
	__u32 magic;
	__u32 size;
};

#define FPSIMD_MAGIC	0x46508001

struct fpsimd_context {
	struct _aarch64_ctx head;
	__u32 fpsr;
	__u32 fpcr;
	___uint128_t vregs[32];
};
```

Our job is easy: set magic and size, fill the rest of the struct with 0s and execute
`rt_sigreturn`:

```asm
			mov     w1, 0x8001
			movk    w1, 0x4650, lsl #16
			mov     w2, 0x210
			stp     w1, w2, [x19], #8         //magic/size
			str     xzr,[x19], #8             //fpsr, fpcr
			mov     x4, 32
__store_vregs:
			stp     xzr, xzr, [x19], #16
			subs    x4, x4, 1
			bne     __store_vregs
			//execute __kernel_rt_sigreturn
			mov     x8, 0x8b
			svc     0x0
```

The code should now successfully switch back to AArch32 from AArch64.

I wondered: what if I call AArch64 syscalls from AArch64, will it end up in a AArch64 syscall or in `compat_syscall` which is the name for the syscall table reserved for AArch32 code. I wondered because at one point during signal delivery we had a call for `is_compat_task()` and a check for `TIF_32BIT`. If the flag was checked, we would endup in AArch32 bit code, so I started looking at *entry.S* from *arch/arm64/kernel/*

```asm
el0_sync:
	kernel_entry 0				<--- saves all regs and makes pt_regs
	mrs	x25, esr_el1			// read the syndrome register
	lsr	x24, x25, #ESR_EL1_EC_SHIFT	// exception class
	cmp	x24, #ESR_EL1_EC_SVC64	// SVC in 64-bit state
	b.eq	el0_svc
```

In the so called exception syndrom register or `ESR_EL1`, during the switch from `EL0(user)` to `EL1(kernel)` bits will be updated to show if an exception was thrown from AArch32 or AArch64. Based on that information, the kernel will call the proper syscall handler. Taken from AArch64 specs we can see this:

```
[31:26]	EC
Exception Class:
0b100000
Instruction Abort that caused entry from a lower Exception level in AArch32 or AArch64.
0b100001
Instruction Abort that caused entry from a current Exception level in AArch64.         
```

Also it is important to note that Exception Table for AArch64 is extended a bit to also include entries for AArch32 excptions and CPU decides which one would be called based on CPU state.

Ok, we are now sure that all syscalls executed from AArch64 will actually be AArch64 syscalls. Of course, it would also be possible to switch from AArch64 to AArch32 and do basically the same by preparing `rt_sigreturn` for AArch32, but that is left as an exercise to the reader.

What do we gain from this? Not much, we can execute AArch64 syscalls with 64bit parameters from an AArch32 program, and make it difficult to debug our program for people trying to reverse engineer it.

That's all.

**deroko of ARTeam**

*Special tnx goes to Daniel Pistelli for proofreading and correcting errors*
*Special tnx goes to upiter for making markdown version of this document*
