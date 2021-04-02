#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#define PAGE_SIZE 4096

int main(int argc, char *argv[])
{
	unsigned long *case1, *case2, *case3, *case4, *case5, *case6;
	pid_t child;

	printf("Allocating heap memory but not using it:\n");
	case1 = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	printf("Memory address: %#014lx\n", (unsigned long) case1);
	getchar();

	printf("Write-fault:\n");
	case2 = (unsigned long *) mmap(NULL, PAGE_SIZE, PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	printf("Memory address: %#014lx", (unsigned long) case2);
	getchar();
	*case2 = 1;
	printf("After writing something at %#014lx\n", (unsigned long) case2);
	getchar();

	printf("Read-fault:\n");
	case3 = (unsigned long *)  mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	printf("Memory address: %#014lx\n", (unsigned long) case3);
	getchar();

	printf("Read-fault followed by a write:\n");
	case4 = (unsigned long *)  mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	printf("Memory address: %#014lx", (unsigned long) case4);
	getchar();
	*case4 = 1;
	printf("After writing something at %#014lx\n", (unsigned long) case4);
	getchar();

	printf("write (without fault):\n");
	case5 = (unsigned long *)  mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*case5 = 1;
	printf("Memory address: %#014lx\n", (unsigned long) case5);
	getchar();

	printf("copy-on-write:\n");
	case6 = (unsigned long *)  mmap(NULL, PAGE_SIZE, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	printf("Memory address: %#014lx", (unsigned long) case6);
	*case6 = 1;
	printf("Parent write: %#02lx at %#014lx", *case6, (unsigned long) case6);
	getchar();

	child = fork();
	if (child == 0) {
		sleep(5);
		*case6 = 2;
		printf("Child write: %#02lx at %#014lx\n", *case6, (unsigned long) case6);
		sleep(10);
	} else {
		printf("pid of child %d\n", child);
		getchar();
	}

	return 0;
}
