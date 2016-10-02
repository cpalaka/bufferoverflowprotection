#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <malloc.h>
#include <unistd.h>
#include <limits.h>

#define DEBUG 0
#define CALLSTACK_MAXLEN 64

#define BT(X) {                                                         \
        case X:                                                         \
                if (!__builtin_frame_address(X)) {                      \
                        return X;                                       \
                }                                                       \
                addrs[X] = __builtin_frame_address(X);                  \
                break;                                                  \
}

static void * addrs[CALLSTACK_MAXLEN];
static int stackdepth;
static void * heapStart= (void*)UINT_MAX;

static int get_bt(int depth);
static int isInHeap(char * ptr);
static inline int getStrLen(const char * src);
static int availableHeapSpace(char * ptr);
static int availableStackSpace(char * ptr);

char *
strcpy(char * dest, const char * src)
{
	int srclen = getStrLen(src);
	int overflowdetected = 0;

#if DEBUG
	printf("Inside custom strcpy:\n");
	printf("srclen:%d\n",srclen);
#endif
	
	//first check if dest points to memory on stack or heap
	//if dest is on heap, check that available size is compatible with src length

	int _isInHeap = isInHeap(dest);
	if(_isInHeap==1) {
	//heap
		int bytes = availableHeapSpace(dest);

#if DEBUG
		printf("In the heap.\n");
		printf("bytes til next chunk: %d\n", bytes);
#endif

		if(bytes >= srclen) overflowdetected = 0;
		else 				overflowdetected = 1;

	} else 
	if(_isInHeap==0) {
	//stack
		int bytes = availableStackSpace(dest);

#if DEBUG
		printf("In the stack.\n");
		printf("bytes free: %d\n", bytes);
#endif
		if(bytes >= srclen) overflowdetected = 0;
		else 				overflowdetected = 1;

	} else
	if(_isInHeap==2) {
	//global (data segment)
#if DEBUG
		printf("In data segment.\n");
#endif
		overflowdetected=0;
	} else {
		//undefined memory location
		overflowdetected=1;
	}
	
	//call original strcpy if no overflow detected, otherwise shut down process
	if(overflowdetected) {
		printf("WARNING:Possible buffer overflow detected in strcpy. Shutting down process.\n");
		exit(1);
	} else {	
		char *(*original)(char* d,const char* s);
		original = dlsym(RTLD_NEXT, "strcpy");
		return original(dest,src);
	}
}

char *
strcat(char *dest, const char *src)
{
	int srclen = getStrLen(src);
	int overflowdetected = 0;

#if DEBUG
	printf("Inside custom strcat:\n");
	printf("srclen:%d\n",srclen);
#endif

	int _isInHeap = isInHeap(dest);
	if(_isInHeap==1) {
	//heap
		int bytes = availableHeapSpace(dest);
		int destlen = getStrLen(dest);

#if DEBUG
		printf("In the heap.\n");
		printf("bytes til next chunk:%d\n",bytes);
		printf("strlen(dest):%d\n", destlen);
#endif
		//strcat copies memory starting from the end of dest (minus null char), not the beginning of dest
		//so we take that into account here
		if(bytes-destlen >= srclen) overflowdetected=0;
		else						overflowdetected=1;

	} else
	if(_isInHeap==0) {
	//stack
		int bytes = availableStackSpace(dest);
		int destlen = getStrLen(dest);

#if DEBUG
		printf("In the stack.\n");
		printf("bytes til next chunk:%d\n",bytes);
		printf("strlen(dest):%d\n", destlen);
#endif

		if(bytes-destlen >= srclen) overflowdetected=0;
		else						overflowdetected=1;

	} else
	if(_isInHeap==2) {
	//global (data segment)
#if DEBUG
		printf("In the data segment.\n");
#endif
		overflowdetected=0;
	} else {
	//undefined memory location
		overflowdetected=1;
	}

	//call original strcat if no overflow detected, otherwise shut down process
	if(overflowdetected) {
		printf("WARNING:Possible buffer overflow detected in strcat. Shutting down process.\n");
		exit(1);
	} else {	
		char *(*original)(char* d,const char* s);
		original = dlsym(RTLD_NEXT, "strcat");
		return original(dest,src);
	}
}

//gets is so vulnerable to buffer overflow attacks, that we might as well remove its use entirely
//as there are plenty of other safer functions with similar functionality
char *
gets(char* s)
{
	printf("WARNING:Possible buffer overflow detected. Please remove call to 'gets'. Shutting down process.\n");
	exit(1);
}

//preload malloc to get the starting address of the heap
void *
malloc(size_t size)
{	
	//the brk location for heap will increase as more memory is allocated using malloc.
	//by hijacking every malloc call and keeping track of the lowest brk location, we can
	//effectively find the starting address of the heap
	void * brkloc = sbrk(0);
	if(brkloc < heapStart) heapStart = brkloc;

	//call original malloc
	void *(*original)(size_t size);
	original = dlsym(RTLD_NEXT, "malloc");
	return original(size);
}

//calculates how much free space there is on the heap after ptr.
//if ptr is at the start of a used chunk, it returns the full size
//if ptr is in the middle of a used chunk, we see how far back we 
//need to go (in increments of 4) and subtract the full size of chunk with that size to get
//the approximate free space in the chunk after ptr
static int
availableHeapSpace(char * ptr)
{
	int n,i=0;
	while((n = malloc_usable_size(ptr-i)) <=0 ) {
		i+=4;
	}
	return n-i;
}

//calculates how much free space there is in the stack buffer pointed to by ptr.
//we do this by finding between which stack frames the buffer exists, and then finding
//the distance in bytes between the buffer and its function frame.
static int
availableStackSpace(char * ptr)
{
	int i;
	for(i=0; i<stackdepth-1;++i) {
		if(ptr>(char*)addrs[i] && ptr<(char*)addrs[i+1]) break;
	}
	//frame pointer will point right above the eip (return) location
	//which we specifically want to protect, so subtract 4 bytes from
	//distance between ptr and frame pointer
	return ((int*)addrs[i+1]-(int*)ptr)*sizeof(int) /*-4*/ ; 
}

//gets length of string pointed to by src. this assumes that the string is null terminated.
//if the string is not null terminated, expect undefined behavior
static inline int
getStrLen(const char * src)
{
	int cnt=0;
	while(src[cnt++] != '\0') {}
	return cnt;
}

//will return whether ptr lies in the heap or stack by seeing if ptr is located
//between the calculated stack range. if its not, its on the heap (or undefined)
static int
isInHeap(char * ptr)
{
	int currentdepth;
	currentdepth = get_bt(CALLSTACK_MAXLEN);
	stackdepth = currentdepth;
#if DEBUG
	/* uncomment to see addresses of stack frames in debug info
	int i;
	for(i = 0; i < currentdepth; ++i) {
		printf("lev %d: %p\n",i,addrs[i]);
	}
	printf("ptr location: %p\n", ptr);
	*/
#endif

	if(ptr>(char*)addrs[0] && ptr<(char*)addrs[currentdepth-1]) {
		return 0;//on the stack
	} else 
	if(ptr<(char*)addrs[0] && ptr>(char*)heapStart) {
		return 1;//on the heap
	} else 
	if(ptr<(char*)heapStart) {
		return 2;//in global memory (data segment)
	}
	return -1;//undefined pointer location (control should never reach here)
}

//do a backtrace of the call stack and save frame addresses in addrs array
//the reason we are using the BT macro is because __builtin_frame_address
//only takes constant values, not variables
static int
get_bt(int depth)
{
	int i;
	for (i = 0; i < depth; i++) {
        switch (i) {
            BT(  0);  
            BT(  1);
            BT(  2);
            BT(  3);
            BT(  4);
            BT(  5);
            BT(  6);
            BT(  7);
            BT(  8);
            BT(  9);
            BT( 10);
            BT( 11);
            BT( 12);
            BT( 13);
            BT( 14);
            BT( 15);
            BT( 16);
            BT( 17);
            BT( 18);
            BT( 19);
            BT( 20);
            BT( 21);
            BT( 22);
            BT( 23);
            BT( 24);
            BT( 25);
            BT( 26);
            BT( 27);
            BT( 28);
            BT( 29);
            BT( 30);
            BT( 31);
            BT( 32);
            default:  return i;
        }
    }
   return i;
}