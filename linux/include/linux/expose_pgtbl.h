/* SPDX-License-Identifier: MIT */
#ifndef _EXPOSE_PGTBL_H_
#define _EXPOSE_PGTBL_H_
#include <linux/types.h>

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

#endif /* _EXPOSE_PGTBL_H_ */
