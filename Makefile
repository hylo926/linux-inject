CC	= clang
CFLAGS	= -std=gnu99 -ggdb 
# Use your own ppc compiler here because clang doesn't fully support ppc
PPC_CC  = $(PPC_ROOT)/powerpc-none-linux-gnuspe-gcc
PPC_CFLAGS = -ggdb -fPIC -Wall -Wextra -O2 -g -Wa,-mregnames
UNAME_M := $(shell uname -m)

.PHONY: x86 x86_64 arm ppc

all:
ifeq ($(UNAME_M),x86_64)
	$(MAKE) x86_64
endif
ifeq ($(UNAME_M),x86)
	$(MAKE) x64
endif
ifneq (,$(findstring arm,$(UNAME_M)))
	$(MAKE) arm
endif
ifeq ($(UNAME_M),ppc)
	$(MAKE) ppc
endif


arm: sample-target sample-library.so
	$(CC) -marm $(CFLAGS) -DARM -o inject utils.c ptrace.c inject-arm.c -ldl

x86: sample-target sample-library.so
	$(CC) $(CFLAGS) -o inject utils.c ptrace.c inject-x86.c -ldl

ppc: CC=$(PPC_CC) 
ppc: CFLAGS=$(PPC_CFLAGS)
ppc: sample-target sample-library.so
	$(CC) -DPPC $(CFLAGS) -o inject utils.c ptrace.c inject-ppc.c -ldl
	
x86_64:
	$(CC) $(CFLAGS) -o inject utils.c ptrace.c inject-x86_64.c -ldl
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o sample-library.so -fPIC sample-library.c
	$(CC) $(CFLAGS) -o sample-target sample-target.c
	$(CC) -m32 $(CFLAGS) -o inject32 utils.c ptrace.c inject-x86.c -ldl
	$(CC) -m32 $(CFLAGS) -D_GNU_SOURCE -shared -o sample-library32.so -fPIC sample-library.c
	$(CC) -m32 $(CFLAGS) -o sample-target32 sample-target.c

sample-library.so: sample-library.c
	$(CC) $(CFLAGS) -D_GNU_SOURCE -shared -o sample-library.so -fPIC sample-library.c

sample-target: sample-target.c
	$(CC) $(CFLAGS) -o sample-target sample-target.c

clean:
	rm -f sample-library.so
	rm -f sample-target
	rm -f inject
	rm -f sample-library32.so
	rm -f sample-target32
	rm -f inject32
