#ifndef __PTRACE_H__
#define __PTRACE_H__
#ifdef ARM
	#define REG_TYPE user_regs
#else
#ifdef PPC
	typedef struct _pt_regs {
	    unsigned long gpr[32];
	    unsigned long nip;
	    unsigned long msr;
	    unsigned long orig_gpr3;        /* Used for restarting system calls */
	    unsigned long ctr;
	    unsigned long link;
	    unsigned long xer;
	    unsigned long ccr;
#ifdef __powerpc64__
	    unsigned long softe;            /* Soft enabled/disabled */
#else
	    unsigned long mq;               /* 601 only (not used at present) */
	    /* Used on APUS to hold IPL value. */
#endif
	    unsigned long trap;             /* Reason for being here */
	    /* N.B. for critical exceptions on 4xx, the dar and dsisr
	     *            fields are overloaded to hold srr0 and srr1. */
	    unsigned long dar;              /* Fault registers */
	    unsigned long dsisr;            /* on 4xx/Book-E used for ESR */
	    unsigned long result;           /* Result of a system call */
	} pt_regs;

	#define REG_TYPE pt_regs
#else
	#define REG_TYPE user_regs_struct
#endif
#endif

void ptrace_attach(pid_t target);
void ptrace_detach(pid_t target);
void ptrace_getregs(pid_t target, struct REG_TYPE* regs);
void ptrace_cont(pid_t target);
void ptrace_setregs(pid_t target, struct REG_TYPE* regs);
siginfo_t ptrace_getsiginfo(pid_t target);
void ptrace_read(int pid, unsigned long addr, void *vptr, int len);
void ptrace_write(int pid, unsigned long addr, void *vptr, int len);
void checktargetsig(int pid);
void restoreStateAndDetach(pid_t target, unsigned long addr, void* backup, int datasize, struct REG_TYPE oldregs);
#endif
