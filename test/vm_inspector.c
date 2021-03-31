#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>

#define __get_pagetable_layout  436
#define __expose_page_table 437
#define PAGE_SIZE 4096
#define ADDR_SIZE sizeof(unsigned long)
#define pgd_index(address) (((address) >> 39) & (512 - 1))

static inline unsigned long pud_index(unsigned long address)
{
	return (address >> 30) & (512 - 1);
}

static inline unsigned long pmd_index(unsigned long address)
{
	return (address >> 21) & (512 - 1);
}

static inline unsigned long pte_index(unsigned long address)
{
	return (address >> 12) & (512- 1);
}

struct n_pg {
	unsigned long num_page;
	unsigned long num_pmd;
	unsigned long num_pud;
	unsigned long num_p4d;
	unsigned long num_pgd;
};

// a rounded-up version
struct n_pg calculate_pg(unsigned long start, unsigned long end)
{
	struct n_pg ret;
	ret.num_page = ((end >> 12) - (start >> 21 << 21 >> 12));
	ret.num_pmd  = ((end >> 21) - (start >> 30 << 30 >> 21));
	ret.num_pud  = ((end >> 30) - (start >> 39 << 39 >> 30));
	ret.num_p4d  = ((end >> 39) - (start >> 39));
	ret.num_pgd  = 512;
	if (end % (1 << 21))
		ret.num_pmd++;
	if (end % (1 << 30))
		ret.num_pud++;
	if (end % ((unsigned long)1 << 39))
		ret.num_p4d++;

	return ret;
}

struct pagetable_layout_info {
	uint32_t pgdir_shift;
	uint32_t p4d_shift;
	uint32_t pud_shift;
	uint32_t pmd_shift;
	uint32_t page_shift;
};

struct expose_pgtbl_args {
	unsigned long fake_pgd;
	unsigned long fake_p4ds;
	unsigned long fake_puds;
	unsigned long fake_pmds;
	unsigned long page_table_addr;
	unsigned long begin_vaddr;
	unsigned long end_vaddr;
};


long get_pagetable_layout_syscall(struct pagetable_layout_info *pgtbl_info)
{
	return syscall(__get_pagetable_layout, pgtbl_info);
}


long expose_page_table_syscall(pid_t pid, struct expose_pgtbl_args *args)
{
	return syscall(__expose_page_table, pid, args);
}


static inline unsigned long get_phys_addr(unsigned long pte_entry)
{
	return (((1UL << 52) - 1) & pte_entry) >> 12 << 12;
}


static inline int young_bit(unsigned long pte_entry)
{
	return 1UL << 5 & pte_entry ? 1 : 0;
}


static inline int dirty_bit(unsigned long pte_entry)
{
	return 1UL << 6 & pte_entry ? 1 : 0;
}


static inline int write_bit(unsigned long pte_entry)
{
	return 1UL << 1 & pte_entry ? 1 : 0;
}


static inline int user_bit(unsigned long pte_entry)
{
	return 1UL << 2 & pte_entry ? 1 : 0;
}

void show_layout()
{
	char c[1000];
	char *status;
	FILE *fptr;
	if ((fptr = fopen("/proc/self/maps", "r")) == NULL) {
		printf("Error! opening file");
		// Program exits if file pointer returns NULL.
		exit(1);
	}
	
	do {
		status = fscanf(fptr, "%s", &c);
		printf("%s\n", c);
	} while (status != -1);
	fclose(fptr);
}

int main(int argc, char *argv[])
{
	struct expose_pgtbl_args args;
	size_t addr_len;
        unsigned long *fake_pgd;
        unsigned long *fake_p4ds;
        unsigned long *fake_puds;
        unsigned long *fake_pmds;
        unsigned long *page_table_addr;
	struct n_pg spaces;

	get_pagetable_layout_syscall(NULL);
	show_layout();
	printf("Enter begin_vaddr in hex:");
	scanf("%lx", &(args.begin_vaddr));
	printf("Your input is:%lx\n", args.begin_vaddr);
	printf("Enter end_vaddr in hex:");
	scanf("%lx", &(args.end_vaddr));
	printf("Your input is:%lx\n", args.end_vaddr);
	spaces = calculate_pg(args.begin_vaddr, args.end_vaddr);

	page_table_addr = mmap(NULL, spaces.num_page * ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	fake_pmds = mmap(NULL, spaces.num_pmd * ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	fake_puds = mmap(NULL, spaces.num_pud * ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	fake_p4ds = mmap(NULL, spaces.num_p4d * ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	fake_pgd = mmap(NULL, spaces.num_pgd * ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	args.fake_pgd = (unsigned long) fake_pgd;
	args.fake_p4ds = (unsigned long) fake_p4ds;
	args.fake_puds = (unsigned long) fake_puds;
	args.fake_pmds = (unsigned long) fake_pmds;
	args.page_table_addr = (unsigned long) page_table_addr;

	printf("fake_pgd: %lx \n", args.fake_pgd);
	printf("fake_p4ds: %lx \n", args.fake_p4ds);
	printf("fake_puds: %lx \n", args.fake_puds);
	printf("fake_pmds: %lx \n", args.fake_pmds);
	printf("page_table_addr: %lx \n", args.page_table_addr);

	if (expose_page_table_syscall(-1, &args))
		perror("Error:");
	//unsigned long test;
	//unsigned long *test_ptr = &test;
	//test_ptr = (unsigned long *) args.fake_pgd;
	//*test_ptr = 0x556713b7e000;
	//printf("%lx\n", test);
	unsigned long *tmp, *pte;
	int iters = (args.end_vaddr - args.begin_vaddr) >> 12;
	tmp = fake_pgd + pgd_index(args.begin_vaddr);
	printf("pgd ptr, pud ptr: %lx, %lx\n", tmp, *tmp);
	tmp = (unsigned long *)*tmp + pud_index(args.begin_vaddr);
	printf("pud ptr, pmd ptr: %lx, %lx\n", tmp, *tmp);
	tmp = (unsigned long *)*tmp + pmd_index(args.begin_vaddr);
	printf("pmd ptr, pte ptr: %lx, %lx\n", tmp, *tmp);
	tmp = (unsigned long *)*tmp + pte_index(args.begin_vaddr); 
	printf("pte ptr, pte val: %lx, %lx\n", tmp, *tmp);

	for (int i=0; i<iters; i++) {
		tmp++;
		printf("pte ptr, pte val: %lx, %lx\n", tmp, *tmp);

	}
	//unsigned long *test = (unsigned long *) args.fake_pgd;
	//test[0] = 0x556713b7dead;
	//test[1] = 0x5567deaddead;
	//test[2] = 0xdeaddeaddead;

	//printf("\n");
	//printf("fake_p4ds[0]: %lx\n", fake_p4ds);
	//printf("%lx %lx\n", fake_pgd, *fake_pgd);
	//printf("%lx\n", fake_puds);
	//printf("\n");
	//printf("fake_pgd[1]: %lx\n", test[1]);
	//printf("fake_pgd[2]: %lx\n", test[2]);
	//printf("fake_pgd[3]: %lx\n", test[3]);

	//munmap(fake_pgd, pgd_size);
	//munmap(fake_p4ds, p4d_size);
	//munmap(fake_puds, pud_size);
	//munmap(fake_pmds, pmd_size);
	//munmap(page_table_addr, pte_size);

	return 0;
}
