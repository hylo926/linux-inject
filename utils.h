#ifndef __INJECTSO_UTILS_H__
#define __INJECTSO_UTILS_H__

#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

#define DEBUG 0

#if DEBUG                                                                  
#define dprintf(...) do{printf(__VA_ARGS__);}while(0)      
#else                                                                      
#define dprintf(...)                                                       
#endif                                                                     
void printHex4(char* prefix, int32_t instr);
void printHex8(char* addr, int loop);
pid_t findProcessByName(char* processName);
long freespaceaddr(pid_t pid);
long getlibcaddr(pid_t pid);
int checkloaded(pid_t pid, char* libname);
long getFunctionAddress(char* funcName);
unsigned char* findRet(void* endAddr);
void usage(char* name);
#endif
