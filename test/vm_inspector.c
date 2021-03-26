#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdio.h>

#define __get_pagetable_layout  436
#define __expose_page_table 437
#define PAGE_SIZE 4096
#define ADDR_SIZE sizeof(unsigned long)

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
	return (((1UL << 46) - 1) & pte_entry) >> 12 << 12;
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


int main(int argc, char *argv[])
{
	struct expose_pgtbl_args args;
	size_t addr_len;
	size_t pte_size, pmd_size, pud_size, p4d_size, pgd_size;
        unsigned long *fake_pgd;
        unsigned long *fake_p4ds;
        unsigned long *fake_puds;
        unsigned long *fake_pmds;
        unsigned long *page_table_addr;

	get_pagetable_layout_syscall(NULL);

	args.begin_vaddr = 0x55671297e000;
	args.end_vaddr = 0x556713b7e000; // 4608 pages;
	//addr_len = (args.end_vaddr - args.begin_vaddr); // maximum bytes we need;
	//ptes_size = addr_len / PAGE_SIZE;
	pgd_size = 25 * ADDR_SIZE;
	p4d_size = 25 * ADDR_SIZE;
	pud_size = 25 * ADDR_SIZE;
	pmd_size = 25 * ADDR_SIZE;
	pte_size = 1200 * ADDR_SIZE;

	//fake_pgd = mmap(NULL, pgd_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	////fake_pgd = mmap((void *) args.begin_vaddr, pgd_size + p4d_size + pud_size + pmd_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	////fake_p4ds = mmap((void *) fake_pgd - PAGE_SIZE, p4d_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	//fake_p4ds = mmap((void *) fake_pgd + pgd_size, p4d_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	//fake_puds = mmap((void *) fake_p4ds + p4d_size, pud_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	//fake_pmds = mmap((void *) fake_puds + pud_size, pmd_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	//page_table_addr = mmap((void *) fake_pmds + pmd_size, pte_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	//page_table_addr = mmap((void *) args.begin_vaddr, pte_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	page_table_addr = mmap(NULL, pte_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	fake_pmds = mmap((void *) page_table_addr - pmd_size, pmd_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	fake_puds = mmap((void *) fake_pmds - pud_size, pud_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	fake_p4ds = mmap((void *) fake_puds - p4d_size, p4d_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	fake_pgd = mmap((void *) fake_p4ds - pgd_size, pgd_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	args.fake_pgd = (unsigned long) fake_pgd;
	args.fake_p4ds = (unsigned long) fake_p4ds;
	args.fake_puds = (unsigned long) fake_puds;
	args.fake_pmds = (unsigned long) fake_pmds;
	args.page_table_addr = (unsigned long) page_table_addr;

	printf("%lx \n", args.fake_pgd);
	printf("%lx \n", args.fake_pgd + pgd_size);
	printf("%lx \n", args.fake_p4ds);
	printf("%lx \n", args.fake_puds);
	printf("%lx \n", args.fake_pmds);
	printf("%lx \n", args.page_table_addr);

	expose_page_table_syscall(-1, &args);

	//unsigned long test;
	//unsigned long *test_ptr = &test;
	//test_ptr = (unsigned long *) args.fake_pgd;
	//*test_ptr = 0x556713b7e000;
	//printf("%lx\n", test);

	unsigned long *test = (unsigned long *) args.fake_pgd;
	//test[0] = 0x556713b7dead;
	//test[1] = 0x5567deaddead;
	//test[2] = 0xdeaddeaddead;

	printf("\n");
	printf("%lx\n", test[0]);
	printf("%lx\n", fake_p4ds);
	printf("\n");
	printf("%lx\n", test[1]);
	printf("%lx\n", test[2]);
	printf("%lx\n", test[3]);

	munmap(fake_pgd, pgd_size);
	munmap(fake_p4ds, p4d_size);
	munmap(fake_puds, pud_size);
	munmap(fake_pmds, pmd_size);
	munmap(page_table_addr, pte_size);

	return 0;
}
