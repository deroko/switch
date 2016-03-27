#include <asm-generic/mman.h>
#define AT_FDCWD -100
#define O_RDWR 00000002

.global export_testarm64
export_testarm64:
                mov     x1, testarm64_end - testarm64
                str     x1, [x0]
                adr     x0, testarm64
                ret
                
.global testarm64
testarm64:	
		adr	x0, msg
		bl	__strlen
		mov	x2, x0
		adr	x1, msg
		eor	x0, x0, x0
		add	x0, x0, 1
		mov	x8, 64
		svc	0
                
		
		mov     x0, x13                 //use x13 which was sp in AArch32
		sub     x0, x0, 0x2000
		and     x0, x0, 0xFFFFFFF0
		mov     sp, x0

		//on x64 libc sigaction is diff from kernel one, diff is:
		//libc:
		//      sa_flags
		//      sa_handler
		//kernel on x64
		//      sa_handler
		//      sa_flags
		
		mov     w1, 4
		str	x1, [sp, #8]            //sa_flags
                adr     x1, sigactionfn
		str	x1, [sp, #0]            //sa_handler
		stp     xzr, xzr, [sp, #16]     //sa_restorer/sa_mask to 0
		
	
		eor	x2, x2, x2
		mov	x1, sp
		mov	x0, 10
		bl      sigaction
		b	__execute_kill 

__strlen:	mov	x1, x0
		mov	x2, x0
__looplen:
		ldrb	w0, [x1],#1
		cbnz    w0, __looplen
		sub	x0, x1, x2
		ret		
msg:		.asciz	"tada - executed as AArch64 from AArch32\n"
		.align  3

sigaction:      mov     x3, 8                   //sizeof sigset_t
                b       __rt_sigaction          //just branch without updating lr aka x30...
                

memcpy:         ldrb    w3, [x1], #1
                strb    w3, [x0], #1
                subs    x2, x2, 1
                bne     memcpy
                ret

//sigactionfn will be called as if we are aarch32 even when it's
//setup from aarch64, thus we need to update offsets accordingly...  
//this is coming from arch/arm64/kernel/signal.c:handle_signal
sigactionfn:	ldr     w0, [x2, #8]            //uc_stack.ss_sp
                ldr     w1, [x2, #16]           //uc_stack.ss_size
                ldr     w2, [x2, #0x54]         //uc_context.ARM_sp -- actually x13
                                                //                     so that's one of regs we shouldn't mess
                                                //                     during aarch64 transition

                //now build new stack for us, and soon we are out of this mess...
                mov     x19, sp                 
                sub     x19, x19, 0x1000
                and     x19, x19, 0xFFFFFFF0    //align stack to 16 as that's expected by rt_sigreturn...
                mov     sp, x19   
                
                add     x19, sp, 0x80           //skip over siginfo... 
                mov     x3, x19                 //for debugging purposes only...
                
                str     xzr,[x19, #0]           //uc_flags
                str     xzr,[x19, #8]           //uc_link
                
                str     x0, [x19, #16]          //uc_stack.ss_sp        for aarch64
                str     xzr,[x19, #24]          //uc_stack.ss_flags     for aarch64
                str     x1, [x19, #32]          //uc_stack.ss_size      for aarch64                         
                
                str     xzr,[x19, #40]          //uc_sigmask            for aarch64

                add     x19, x19, 0xB8          //advance to ucontext_t
                //fill all regs with xzr        //sp and pc will be filled separately...
                //note that sp eg. x13 must be filled with proper value...

                mov     x4, 31
__store_gen_regs:
                str     xzr, [x19], #8          //all registers to 0
                cmp     x4, 31-13               
                bne     __cntloop
                str     x2, [x19, #-8]          //fill in sp for aarch32
__cntloop:      subs    x4, x4, 1
                bne     __store_gen_regs
                                
                str     xzr, [x19], #8          //store aarch64 sp, this will not be really used
                                                //but good to have it for later...
                adr     x0, testarm64_end
                str     x0, [x19], #8           //store pc after kill
                mov     x0, 0x10                //set AArch32 flag...
		str     x0, [x19], #8          
		
		//we are now at 0x1c8 in ucontext_t advance extra 8 bytes to reach
		//fpsimd_context
		str     xzr, [x19], #8
		
		mov     w1, 0x8001                //FPSIMD_MAGIC
		movk    w1, 0x4650, lsl #16
		mov     w2, 0x210
		stp     w1, w2, [x19], #8         //magic/size
		str     xzr,[x19], #8             //fpsr, fpcr
		mov     x4, 32
__store_vregs:  stp     xzr, xzr, [x19], #16
                subs    x4, x4, 1
                bne     __store_vregs
                
		//execute __kernel_rt_sigreturn
		mov     x8, 0x8b
                svc     0x0
		
__rt_sigaction:
                mov     x8, 0x86
                svc     0
                ret
                
__execute_kill:	mov     x8, 172
                svc     0               //getpid()
                mov	x1, 10          //SIGUSR1
		mov	x8, 129         //kill
		svc	0
testarm64_end:				//now we are aarch32
