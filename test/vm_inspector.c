#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>

#define __get_pagetable_layout  436
#define __expose_page_table 437

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
	get_pagetable_layout_syscall(NULL);
	expose_page_table_syscall(-1, NULL);
	return 0;
}
