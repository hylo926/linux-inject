#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/user.h>
#include <wait.h>

#include "utils.h"
#include "ptrace.h"

#define DEBUG 1

#if DEBUG                                                                  
#define dprintf(...) do{printf(__VA_ARGS__);}while(0)      
#else                                                                      
#define dprintf(...)                                                       
#endif                                                                     

/*
 * injectSharedLibrary()
 *
 * This is the code that will actually be injected into the target process.
 * This code is responsible for loading the shared library into the target
 * process' address space.  First, it calls malloc() to allocate a buffer to
 * hold the filename of the library to be loaded. Then, it calls
 * __libc_dlopen_mode(), libc's implementation of dlopen(), to load the desired
 * shared library. Finally, it calls free() to free the buffer containing the
 * library name. Each time it needs to give control back to the injector
 * process, it breaks back in by calling raise() to produce a SIGTRAP signal.
 * See the comments below for more details on how this works.
 *
 */

void injectSharedLibrary(long mallocaddr, long freeaddr, long dlopenaddr)
{
	// r3 = address of raise()
	// r4 = address of malloc()
	// r5 = address of __libc_dlopen_mode()
	// r6 = address of free()
	// r7 = size of the path to the shared library we want to load
	//
	// unfortunately, each function call we make will wipe out these
	// register values, so in order to avoid losing the function addresses,
	// we need to save them on the stack.
	//
	// here's the sequence of calls we're going to make:
	//
	// * malloc() - allocate a buffer to store the path to the shared
	//   library we're injecting
	//
	// * raise() - raise a SIGTRAP signal to break into the target process
	//   so that we can check the return value of malloc() in order to know
	//   where to copy the shared library path to
	//
	// * __libc_dlopen_mode() - load the shared library
	//
	// * raise() - raise a SIGTRAP signal to break into the target process
	//   to check the return value of __libc_dlopen_mode() in order to see
	//   whether it succeeded
	//
	// * free() - free the buffer containing the path to the shared library
	//
	// * raise() - raise a SIGTRAP signal to break into the target process
	//   so that we can restore the parts of memory that we overwrote
	//
	// we need to push the addresses of the functions we want to call in
	// the reverse of the order we want to call them in (except for the
	// first call):

	asm("addi r1, r1, -120");
	asm("stw     r3,20(r1)");	// raise()
	asm("stw     r6,24(r1)");	// free()
	asm("stw     r5,28(r1)");	// __libc_dlopen_mode()
	asm("stw     r3,32(r1)");	// raise()

//	asm("push {r1}");	// raise()
//	asm("push {r4}");	// free()
//	asm("push {r1}");	// raise()
//	asm("push {r3}");	// __libc_dlopen_mode()
//	asm("push {r1}");	// raise()

	// call malloc() to allocate a buffer to store the path to the shared
	// library to inject.
	asm(
		// choose the amount of memory to allocate with malloc() based
		// on the size of the path to the shared library passed via r5
		"mr r3, r7 \n"
		// call malloc(), whose address is already in r2
		"mtctr r4 \n"
		"bctrl \n"
		// copy the return value (which is in r0) into r5 so that it
		// doesn't get wiped out later
		"mr r14, r3"
//		"stw r3,36(r1)"
	);

	// call raise(SIGTRAP) to get back control of the target.
	asm(
		// pop off the stack to get the address of raise()
		"lwz r0,20(r1) \n"
		// specify SIGTRAP as the first argument
		"li r3,5 \n"
		// call raise()
		"mtctr r0 \n"
		"bctrl "
	);

	// call __libc_dlopen_mode() to actually load the shared library.
	asm(
		// pop off the stack to get the address of __libc_dlopen_mode()
		"lwz r0,28(r1) \n"
		// copy r5 (the address of the malloc'd buffer) into r0 to make
		// it the first argument to __libc_dlopen_mode()
		"mr r3, r14 \n"
		// set the second argument to RTLD_LAZY
		"li r4, 1 \n"
		// call __libc_dlopen_mode()
		"mtctr r0 \n"
		"bctrl \n"
		// copy the return value (which is in r0) into r4 so that it
		// doesn't get wiped out later
		"mr r15, r3"
	);

	// call raise(SIGTRAP) to get back control of the target.
	asm(
		// pop off the stack to get the address of raise()
		"lwz r0,20(r1) \n"
		// specify SIGTRAP as the first argument
		"li r3,5 \n"
		// call raise()
		"mtctr r0 \n"
		"bctrl "
	);

	// call free() in order to free the buffer containing the path to the
	// shared library.
	asm(
		// pop off the stack to get the address of free()
		"lwz r0,24(r1) \n"
		// copy r5 (the malloc'd buffer) into r0 to make it the first
		// argument to free()
		"mr r3, r14 \n"
		// call free()
		"mtctr r0 \n"
		"bctrl \n"
		// copy return value r0 into r4 so that it doesn't get wiped
		// out later
		"mr r16, r3"
	);

	// call raise(SIGTRAP) to get back control of the target.
	asm(
		// pop off the stack to get the address of raise()
		"lwz r0,20(r1) \n"
		// specify SIGTRAP as the first argument
		"li r3,5 \n"
		// call raise()
		"mtctr r0 \n"
		"bctrl "
	);

	// restore stack pointer
	asm("addi r1, r1, 120");
}

/*
 * injectSharedLibrary_end()
 *
 * This function's only purpose is to be contiguous to injectSharedLibrary(),
 * so that we can use its address to more precisely figure out how long
 * injectSharedLibrary() is.
 *
 */

void injectSharedLibrary_end()
{
}

int main(int argc, char** argv)
{
	if(argc < 4)
	{
		usage(argv[0]);
		return 1;
	}

	char* command = argv[1];
	char* commandArg = argv[2];
	char* libname = argv[3];
	char* libPath = realpath(libname, NULL);

	char* processName = NULL;
	char temp[256] = {0,};
	pid_t target = 0;

	if(!libPath)
	{
		fprintf(stderr, "can't find file \"%s\"\n", libname);
		return 1;
	}

	if(!strcmp(command, "-n"))
	{
		processName = commandArg;
		target = findProcessByName(processName);
		if(target == -1)
		{
			fprintf(stderr, "doesn't look like a process named \"%s\" is running right now\n", processName);
			return 1;
		}

		dprintf("targeting process \"%s\" with pid %d\n", processName, target);
	}
	else if(!strcmp(command, "-p"))
	{
		target = atoi(commandArg);
		dprintf("targeting process with pid %d\n", target);
	}
	else
	{
		usage(argv[0]);
		return 1;
	}

	int libPathLength = strlen(libPath) + 1;

	int mypid = getpid();
	long mylibcaddr = getlibcaddr(mypid);

	// find the addresses of the syscalls that we'd like to use inside the
	// target, as loaded inside THIS process (i.e. NOT the target process)
	long mallocAddr = getFunctionAddress("malloc");
	long freeAddr = getFunctionAddress("free");
	long dlopenAddr = getFunctionAddress("__libc_dlopen_mode");
	long raiseAddr = getFunctionAddress("raise");

	dprintf("mallocAddr = %08x\n", (unsigned int)mallocAddr);
	dprintf("freeAddr = %08x\n", (unsigned int)freeAddr);
	dprintf("dlopenAddr = %08x\n", (unsigned int)dlopenAddr);
	dprintf("raiseAddr = %08x\n", (unsigned int)raiseAddr);

	// use the base address of libc to calculate offsets for the syscalls
	// we want to use
	long mallocOffset = mallocAddr - mylibcaddr;
	long freeOffset = freeAddr - mylibcaddr;
	long dlopenOffset = dlopenAddr - mylibcaddr;
	long raiseOffset = raiseAddr - mylibcaddr;

	// get the target process' libc address and use it to find the
	// addresses of the syscalls we want to use inside the target process
	long targetLibcAddr = getlibcaddr(target);
	long targetMallocAddr = targetLibcAddr + mallocOffset;
	long targetFreeAddr = targetLibcAddr + freeOffset;
	long targetDlopenAddr = targetLibcAddr + dlopenOffset;
	long targetRaiseAddr = targetLibcAddr + raiseOffset;

	struct REG_TYPE oldregs, regs;
	memset(&oldregs, 0, sizeof(struct REG_TYPE));
	memset(&regs, 0, sizeof(struct REG_TYPE));

	ptrace_attach(target);
	dprintf("ptrace attached\n");

	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct REG_TYPE));

	// find a good address to copy code to
	long addr = freespaceaddr(target) + sizeof(long);
	dprintf("addr=0x%08x\n", (unsigned int)addr);

	// now that we have an address to copy code to, set the target's
	// program counter to it.
	//
	// subtract 4 bytes from the actual address, because ARM's PC actually
	// refers to the next instruction rather than the current instruction.
//	regs.uregs[15] = addr - 4;  // ARM r15: PC
	regs.nip = addr;	    // PPC nip: PC

	// pass arguments to my function injectSharedLibrary() by loading them
	// into the right registers. see comments in injectSharedLibrary() for
	// more details.
//	regs.uregs[1] = targetRaiseAddr; // ARM argument: r0-r3 variable: r4-r8
//	regs.uregs[2] = targetMallocAddr;
//	regs.uregs[3] = targetDlopenAddr;
//	regs.uregs[4] = targetFreeAddr;
//	regs.uregs[5] = libPathLength;

	regs.gpr[3] = targetRaiseAddr;
	regs.gpr[4] = targetMallocAddr;
	regs.gpr[5] = targetDlopenAddr;
	regs.gpr[6] = targetFreeAddr;
	regs.gpr[7] = libPathLength;
	ptrace_setregs(target, &regs);

	// figure out the size of injectSharedLibrary() so we know how big of a buffer to allocate. 
	size_t injectSharedLibrary_size = (intptr_t)injectSharedLibrary_end - (intptr_t)injectSharedLibrary;
	dprintf("injectSharedLibrary_size=0x%08x\n", (unsigned int)injectSharedLibrary_size);

	// back up whatever data used to be at the address we want to modify.
	char* backup = malloc(injectSharedLibrary_size * sizeof(char));
	ptrace_read(target, addr, backup, injectSharedLibrary_size);
	dprintf("\nbackup\n");
	printHex8(backup, 24);

//	ptrace_detach(target);
//	dprintf("ptrace detached\n");
//	return;

	// set up a buffer containing the code that we'll inject into the target process.
	char* newcode = malloc(injectSharedLibrary_size * sizeof(char));
	memset(newcode, 0, injectSharedLibrary_size * sizeof(char));

	// copy the code of injectSharedLibrary() to the buffer.
	memcpy(newcode, injectSharedLibrary, injectSharedLibrary_size);

	// copy injectSharedLibrary()'s code to the target address inside the
	// target process' address space.
	dprintf("\npthread write\n");
	ptrace_write(target, addr, newcode, injectSharedLibrary_size);

	// now that the new code is in place, let the target run our injected code.
	dprintf("\npthread cont\n");
	ptrace_cont(target);

	// at this point, the target should have run malloc(). check its return
	// value to see if it succeeded, and bail out cleanly if it didn't.
	struct REG_TYPE malloc_regs;
	memset(&malloc_regs, 0, sizeof(struct REG_TYPE));
	dprintf("\npthread getregs\n");
	ptrace_getregs(target, &malloc_regs);
	unsigned int targetBuf = malloc_regs.gpr[14];
	dprintf("targetBuf=0x%08x\n", (unsigned int)targetBuf);

	// if r5 is 0 here, then malloc failed, and we should bail out cleanly.
	if(targetBuf == 0)
	{
		fprintf(stderr, "malloc() failed to allocate memory\n");
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	// if we get here, then malloc likely succeeded, so now we need to copy
	// the path to the shared library we want to inject into the buffer
	// that the target process just malloc'd. this is needed so that it can
	// be passed as an argument to __libc_dlopen_mode later on.

	// read the buffer returned by malloc() and copy the name of our shared
	// library to that address inside the target process.
	dprintf("\npthread write2\n");
	ptrace_write(target, targetBuf, libPath, libPathLength);
	ptrace_read(target, targetBuf, temp, libPathLength);
	temp[libPathLength] = 0;
	dprintf("Contents of targetBuf=%s\n", temp);

	// continue the target's execution again in order to call
	// __libc_dlopen_mode.
	dprintf("\npthread cont2\n");
	ptrace_cont(target);

	// check out what the registers look like after calling
	// __libc_dlopen_mode.
	struct REG_TYPE dlopen_regs;
	memset(&dlopen_regs, 0, sizeof(struct REG_TYPE));
	dprintf("\npthread getregs2\n");
	ptrace_getregs(target, &dlopen_regs);
	unsigned long libAddr = dlopen_regs.gpr[15];
	dprintf("libAddr=%s\n", (char*)libAddr);

	// if r4 is 0 here, then __libc_dlopen_mode() failed, and we should
	// bail out cleanly.
	if(libAddr == 0)
	{
		fprintf(stderr, "__libc_dlopen_mode() failed to load %s\n", libname);
		restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
		free(backup);
		free(newcode);
		return 1;
	}

	// now check /proc/pid/maps to see whether injection was successful.
	if(checkloaded(target, libname))
	{
		dprintf("\"%s\" successfully injected\n", libname);
	}
	else
	{
		fprintf(stderr, "could not inject \"%s\"\n", libname);
	}

	// as a courtesy, free the buffer that we allocated inside the target
	// process. we don't really care whether this succeeds, so don't
	// bother checking the return value.
	ptrace_cont(target);

	// at this point, if everything went according to plan, we've loaded
	// the shared library inside the target process, so we're done. restore
	// the old state and detach from the target.
	restoreStateAndDetach(target, addr, backup, injectSharedLibrary_size, oldregs);
	free(backup);
	free(newcode);
	return 0;
}
