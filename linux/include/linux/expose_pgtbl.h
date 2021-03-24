/* SPDX-License-Identifier: MIT */
#ifndef _EXPOSE_PGTBL_H_
#define _EXPOSE_PGTBL_H_
#include <linux/types.h>
#include <linux/pagewalk.h>

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

struct my_mm_walk;

struct my_mm_walk_ops {
	int (*pgd_entry)(pgd_t *pgd, unsigned long addr,
			 unsigned long next, struct my_mm_walk *walk);
	int (*p4d_entry)(p4d_t *p4d, unsigned long addr,
			 unsigned long next, struct my_mm_walk *walk);
	int (*pmd_entry)(pmd_t *pmd, unsigned long addr,
			 unsigned long next, struct my_mm_walk *walk);
	int (*pud_entry)(pud_t *pud, unsigned long addr,
			 unsigned long next, struct my_mm_walk *walk);
	int (*pte_entry)(pte_t *pte, unsigned long addr,
			 unsigned long next, struct my_mm_walk *walk);
};

struct my_mm_walk {
	const struct my_mm_walk_ops *ops;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	void *private;
};

#endif /* _EXPOSE_PGTBL_H_ */
