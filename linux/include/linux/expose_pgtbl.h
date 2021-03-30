/* SPDX-License-Identifier: MIT */
#ifndef _EXPOSE_PGTBL_H_
#define _EXPOSE_PGTBL_H_
#include <linux/types.h>
#include <linux/pagewalk.h>

#define ADDR_SIZE sizeof(unsigned long)
#define RUN_PGD 0
#define RUN_P4D 1
#define RUN_PUD 2
#define RUN_PMD 3
#define RUN_PTE 4

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
	int (*pgd_entry)(struct my_mm_walk *walk, unsigned long addr, bool do_copy);
	int (*p4d_entry)(struct my_mm_walk *walk, unsigned long addr, bool do_copy);
	int (*pud_entry)(struct my_mm_walk *walk, unsigned long addr, bool do_copy);
	int (*pmd_entry)(struct my_mm_walk *walk, unsigned long addr, bool do_copy);
	int (*pte_entry)(struct my_mm_walk *walk, unsigned long addr, bool do_copy);
};


struct map_linked_list {
	unsigned long *store;
	unsigned long goods;
	struct map_linked_list *next;
};

struct remap_linked_list {
	unsigned long kaddr;
	unsigned long uaddr;
};

struct to_do {
	struct expose_pgtbl_args kargs;
	struct expose_pgtbl_args ptrs;
	struct map_linked_list *map_list;
	struct remap_linked_list *remap_list;
};

struct my_mm_walk {
	const struct my_mm_walk_ops *ops;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	struct to_do *private;
};

#endif /* _EXPOSE_PGTBL_H_ */
