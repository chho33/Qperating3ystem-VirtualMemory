#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

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


struct n_pg {
	unsigned long num_page;
	unsigned long num_pmd;
	unsigned long num_pud;
	unsigned long num_p4d;
	unsigned long num_pgd;
};

struct n_pg calculate_pg(unsigned long start, unsigned long end, struct pagetable_layout_info *pt_info)
{
	struct n_pg ret;
	//ret.num_page = ((end >> 12) - (start >> 21 << 21 >> 12));
	//printf("(end >> %d) - (start >> %d << %d >> %d)\n", pt_info->page_shift, pt_info->pmd_shift, pt_info->pmd_shift, pt_info->page_shift);
	ret.num_page = ((end >> pt_info->page_shift) - (start >> pt_info->pmd_shift << pt_info->pmd_shift >> pt_info->page_shift));
	//ret.num_pmd  = ((end >> 21) - (start >> 30 << 30 >> 21));
	//printf("(end >> %d) - (start >> %d << %d >> %d)\n", pt_info->pmd_shift, pt_info->pud_shift, pt_info->pud_shift, pt_info->pmd_shift);
	ret.num_pmd  = ((end >> pt_info->pmd_shift) - (start >> pt_info->pud_shift << pt_info->pud_shift >> pt_info->pmd_shift));
	//ret.num_pud  = ((end >> 30) - (start >> 39 << 39 >> 30));
	//printf("(end >> %d) - (start >> %d << %d >> %d)\n", pt_info->pud_shift, pt_info->p4d_shift, pt_info->p4d_shift,  pt_info->pud_shift);
	ret.num_pud  = ((end >> pt_info->pud_shift) - (start >> pt_info->p4d_shift << pt_info->p4d_shift >> pt_info->pud_shift));
	//ret.num_p4d  = ((end >> 39) - (start >> 39));
	//printf("(end >> %d) - (start >> %d)\n", pt_info->p4d_shift, pt_info->p4d_shift);
	ret.num_p4d  = ((end >> pt_info->p4d_shift) - (start >> pt_info->p4d_shift));
	ret.num_pgd  = 512;
	//if (end % (1 << 21))
	if (end % (1 << pt_info->pmd_shift))
		ret.num_pmd++;
	//if (end % (1 << 30))
	if (end % (1 << pt_info->pud_shift))
		ret.num_pud++;
	//if (end % ((unsigned long)1 << 39))
	if (end % ((unsigned long)1 << pt_info->p4d_shift))
		ret.num_p4d++;

	return ret;
}

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
	FILE *fptr;

	if ((fptr = fopen("/proc/self/maps", "r")) == NULL) {
		printf("Error! opening file");
		// Program exits if file pointer returns NULL.
		exit(1);
	}

	while (fscanf(fptr, "%s", c)!=EOF) {
		printf("%s\n", c);
	}

	fclose(fptr);
}

int main(int argc, char *argv[])
{
	struct pagetable_layout_info pt_info;
	struct expose_pgtbl_args args;
	pid_t pid;
        unsigned long *fake_pgd;
        unsigned long *fake_p4ds;
        unsigned long *fake_puds;
        unsigned long *fake_pmds;
        unsigned long *page_table_addr;
        unsigned long curr_vaddr, print_vaddr, curr_phys_addr, *curr_ptr;
	struct n_pg spaces;
	int verbose = 0;
	int ybit, dbit, wbit, ubit;

	if (argc < 4) {
		if (argc == 2 && !strcmp(argv[1], "-h")) {
			show_layout();
			printf("Enter begin_vaddr in hex:");
			scanf("%lx", &(args.begin_vaddr));
			printf("Enter end_vaddr in hex:");
			scanf("%lx", &(args.end_vaddr));
			pid = -1;
		} else {
			fprintf(stderr, "[Error] Please follow the usage: ./vm_inspector [-v] pid va_begin va_end\n");
			exit(-1);
		}
	} else if (argc == 4) {
		// check all param are valid;
		pid = (pid_t) atoi(argv[1]);
		args.begin_vaddr = (unsigned long) strtoul(argv[2], NULL, 16);
		args.end_vaddr = (unsigned long) strtoul(argv[3], NULL, 16);
	} else if (argc == 5) {
		// check all param are valid;
		pid = (pid_t) atoi(argv[2]);
		args.begin_vaddr = (unsigned long) strtoul(argv[3], NULL, 16);
		args.end_vaddr = (unsigned long) strtoul(argv[4], NULL, 16);
		if (!strcmp(argv[1], "-v"))
			verbose = 1;
	}

	if (get_pagetable_layout_syscall(&pt_info)) {
		fprintf(stderr, "get_pagetable_layout syscall error: %s\n", strerror(errno));
		exit(-1);
	}

	printf("pid %d\n", pid);
	printf("args.begin_vaddr: %lx\n", args.begin_vaddr);
	printf("args.end_vaddr: %lx\n", args.end_vaddr);

	spaces = calculate_pg(args.begin_vaddr, args.end_vaddr, &pt_info);

	printf("spaces.num_page: %ld\n", spaces.num_page);
	printf("spaces.num_pmd: %ld\n", spaces.num_pmd);
	printf("spaces.num_pud: %ld\n", spaces.num_pud);
	printf("spaces.num_p4d: %ld\n", spaces.num_p4d);
	printf("spaces.num_pgd: %ld\n", spaces.num_pgd);

	page_table_addr = mmap(NULL, spaces.num_page * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (page_table_addr == (void *) -1) {
		fprintf(stderr, "mmap error: %s\n", strerror(errno));
		exit(-1);
	}
	fake_pmds = mmap(NULL, spaces.num_pmd * ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (fake_pmds == (void *) -1) {
		munmap(page_table_addr, spaces.num_page * PAGE_SIZE);
		fprintf(stderr, "mmap error: %s\n", strerror(errno));
		exit(-1);
	}
	fake_puds = mmap(NULL, spaces.num_pud * ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (fake_puds == (void *) -1) {
		munmap(fake_pmds, spaces.num_pmd * ADDR_SIZE);
		munmap(page_table_addr, spaces.num_page * PAGE_SIZE);
		fprintf(stderr, "mmap error: %s\n", strerror(errno));
		exit(-1);
	}
	fake_p4ds = mmap(NULL, spaces.num_p4d * ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (fake_p4ds == (void *) -1) {
		munmap(fake_puds, spaces.num_pud * ADDR_SIZE);
		munmap(fake_pmds, spaces.num_pmd * ADDR_SIZE);
		munmap(page_table_addr, spaces.num_page * PAGE_SIZE);
		fprintf(stderr, "mmap error: %s\n", strerror(errno));
		exit(-1);
	}
	fake_pgd = mmap(NULL, spaces.num_pgd * ADDR_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (fake_pgd == (void *) -1) {
		munmap(fake_p4ds, spaces.num_p4d * ADDR_SIZE);
		munmap(fake_puds, spaces.num_pud * ADDR_SIZE);
		munmap(fake_pmds, spaces.num_pmd * ADDR_SIZE);
		munmap(page_table_addr, spaces.num_page * PAGE_SIZE);
		fprintf(stderr, "mmap error: %s\n", strerror(errno));
		exit(-1);
	}

	args.fake_pgd = (unsigned long) fake_pgd;
	args.fake_p4ds = (unsigned long) fake_p4ds;
	args.fake_puds = (unsigned long) fake_puds;
	args.fake_pmds = (unsigned long) fake_pmds;
	args.page_table_addr = (unsigned long) page_table_addr;

	//printf("fake_pgd: %lx \n", args.fake_pgd);
	//printf("fake_p4ds: %lx \n", args.fake_p4ds);
	//printf("fake_puds: %lx \n", args.fake_puds);
	//printf("fake_pmds: %lx \n", args.fake_pmds);
	//printf("page_table_addr: %lx \n", args.page_table_addr);

	if (expose_page_table_syscall(pid, &args)) {
		fprintf(stderr, "expose_page_table syscall error: %s\n", strerror(errno));
		munmap(fake_pgd, spaces.num_pgd * ADDR_SIZE);
		munmap(fake_p4ds, spaces.num_p4d * ADDR_SIZE);
		munmap(fake_puds, spaces.num_pud * ADDR_SIZE);
		munmap(fake_pmds, spaces.num_pmd * ADDR_SIZE);
		munmap(page_table_addr, spaces.num_page * PAGE_SIZE);
		exit(-1);
	}

	//unsigned long *tmp;
	//int iters = (args.end_vaddr - args.begin_vaddr) >> 12;

	//tmp = fake_pgd + pgd_index(args.begin_vaddr);
	//printf("pgd ptr, pud ptr: %lx, %lx\n", tmp, *tmp);
	//tmp = (unsigned long *)*tmp + pud_index(args.begin_vaddr);
	//printf("pud ptr, pmd ptr: %lx, %lx\n", tmp, *tmp);
	//tmp = (unsigned long *)*tmp + pmd_index(args.begin_vaddr);
	//printf("pmd ptr, pte ptr: %lx, %lx\n", tmp, *tmp);
	//tmp = (unsigned long *)*tmp + pte_index(args.begin_vaddr); 
	//printf("pte ptr, pte val: %lx, %lx\n", tmp, *tmp);

	//while(iters--) {
	//	printf("pte ptr, pte val: %#014lx %#013lx %d %d %d %d\n", tmp, get_phys_addr(*tmp), young_bit((unsigned long)tmp), dirty_bit((unsigned long)tmp), write_bit((unsigned long)tmp), user_bit((unsigned long)tmp));
	//	tmp++;
	//}

	curr_vaddr = args.begin_vaddr;
	do {
		curr_ptr = fake_pgd + pgd_index(curr_vaddr);
		if (*curr_ptr == 0) {
			if (!verbose) {
				curr_vaddr += PAGE_SIZE;
				continue;
			} else {
				print_vaddr = 0xdead00000000;
				curr_phys_addr = 0;
				ybit = 0;
				dbit = 0;
				wbit = 0;
				ubit = 0;
				goto print_info;
			}
		}
		curr_ptr = (unsigned long *)*curr_ptr + pud_index(curr_vaddr);
		curr_ptr = (unsigned long *)*curr_ptr + pmd_index(curr_vaddr);
		curr_ptr = (unsigned long *)*curr_ptr + pte_index(curr_vaddr); 
		curr_phys_addr = get_phys_addr(*curr_ptr);

		if (curr_phys_addr == 0) {
			if (!verbose) {
				curr_vaddr += PAGE_SIZE;
				continue;
			}
			print_vaddr = 0xdead00000000;
			ybit = 0;
			dbit = 0;
			wbit = 0;
			ubit = 0;

		} else {
			print_vaddr = curr_vaddr;
			ybit = young_bit((unsigned long)curr_ptr);
			dbit = dirty_bit((unsigned long)curr_ptr);
			wbit = write_bit((unsigned long)curr_ptr);
			ubit = user_bit((unsigned long)curr_ptr);
		}

print_info:
		printf("%#014lx %#013lx %d %d %d %d\n",
				print_vaddr,
				curr_phys_addr,
				ybit,
				dbit,
				wbit,
				ubit
		);
		curr_vaddr += PAGE_SIZE;
	} while(curr_vaddr < args.end_vaddr);

	munmap(fake_pgd, spaces.num_pgd * ADDR_SIZE);
	munmap(fake_p4ds, spaces.num_p4d * ADDR_SIZE);
	munmap(fake_puds, spaces.num_pud * ADDR_SIZE);
	munmap(fake_pmds, spaces.num_pmd * ADDR_SIZE);
	munmap(page_table_addr, spaces.num_page * PAGE_SIZE);

	return 0;
}
