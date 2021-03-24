#include <linux/expose_pgtbl.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE1(get_pagetable_layout, struct pagetable_layout_info __user *, pgtbl_info)
{
	printk(KERN_INFO "PAGE_OFFSET = 0x%lx\n", PAGE_OFFSET);
	printk(KERN_INFO "PGDIR_SHIFT = %d\n", PGDIR_SHIFT);
	printk(KERN_INFO "P4D_SHIFT = %d\n", PGDIR_SHIFT);
	printk(KERN_INFO "PUD_SHIFT = %d\n", PUD_SHIFT);
	printk(KERN_INFO "PMD_SHIFT = %d\n", PMD_SHIFT);
	printk(KERN_INFO "PAGE_SHIFT = %d\n", PAGE_SHIFT);

	printk(KERN_INFO "PTRS_PER_PGD = %d\n", PTRS_PER_PGD);
	printk(KERN_INFO "PTRS_PER_PUD = %d\n", PTRS_PER_PUD);
	printk(KERN_INFO "PTRS_PER_PMD = %d\n", PTRS_PER_PMD);
	printk(KERN_INFO "PTRS_PER_PTE = %d\n", PTRS_PER_PTE);

	printk(KERN_INFO "PAGE_MASK = 0x%lx\n", PAGE_MASK);
	return 0;
}

static struct task_struct *get_root(int root_pid)
{
	if (root_pid == 0)
		return &init_task;

	return find_task_by_vpid(root_pid);
}

static int walk_pte_range(pmd_t *pmd, unsigned long addr, unsigned long end,
			  struct my_mm_walk *walk)
{
	pte_t *pte;
	int err = 0;
	const struct my_mm_walk_ops *ops = walk->ops;
	unsigned long paddr = 0;
	unsigned long page_addr = 0;
	unsigned long page_offset = 0;

	pte = pte_offset_map(pmd, addr);
	for (;;) {
		page_addr = pte_val(*pte) & PAGE_MASK;
		page_offset = addr & ~PAGE_MASK;
		paddr = page_addr | page_offset;
		pr_info("                    pte: %lx, %lx", &addr, addr);
		printk("                    page_addr = %lx, page_offset = %lx\n", page_addr, page_offset);
		printk("                    vaddr = %lx, paddr = %lx\n", addr, paddr);
		err = ops->pte_entry(pte, addr, addr + PAGE_SIZE, walk);
		if (err)
		       break;
		addr += PAGE_SIZE;
		if (addr == end)
			break;
		pte++;
	}

	pte_unmap(pte);
	return err;
}

static int walk_pmd_range(pud_t *pud, unsigned long addr, unsigned long end,
			  struct my_mm_walk *walk)
{
	pmd_t *pmd;
	unsigned long next;
	const struct my_mm_walk_ops *ops = walk->ops;
	int err = 0;

	pmd = pmd_offset(pud, addr);
	do {
again:
		next = pmd_addr_end(addr, end);
		pr_info("                pmd: %lx, %lx", &addr, addr);
		//if (pmd_none(*pmd) || !walk->vma) {
		//	if (ops->pte_hole)
		//		err = ops->pte_hole(addr, next, walk);
		//	if (err)
		//		break;
		//	continue;
		//}
		/*
		 * This implies that each ->pmd_entry() handler
		 * needs to know about pmd_trans_huge() pmds
		 */
		if (ops->pmd_entry)
			err = ops->pmd_entry(pmd, addr, next, walk);
		if (err)
			break;

		/*
		 * Check this here so we only break down trans_huge
		 * pages when we _need_ to
		 */
		if (!ops->pte_entry)
			continue;

		split_huge_pmd(walk->vma, pmd, addr);
		if (pmd_trans_unstable(pmd))
			goto again;
		err = walk_pte_range(pmd, addr, next, walk);
		if (err)
			break;
	} while (pmd++, addr = next, addr != end);

	return err;
}

static int walk_pud_range(p4d_t *p4d, unsigned long addr, unsigned long end,
			  struct my_mm_walk *walk)
{
	pud_t *pud;
	unsigned long next;
	const struct my_mm_walk_ops *ops = walk->ops;
	int err = 0;

	pud = pud_offset(p4d, addr);
	do {
 again:
		next = pud_addr_end(addr, end);
		pr_info("            pud: %lx, %lx", &addr, addr);
		//if (pud_none(*pud) || !walk->vma) {
		//	if (ops->pte_hole)
		//		err = ops->pte_hole(addr, next, walk);
		//	if (err)
		//		break;
		//	continue;
		//}

		if (ops->pud_entry) {
			spinlock_t *ptl = pud_trans_huge_lock(pud, walk->vma);

			if (ptl) {
				err = ops->pud_entry(pud, addr, next, walk);
				spin_unlock(ptl);
				if (err)
					break;
				continue;
			}
		}

		split_huge_pud(walk->vma, pud, addr);
		if (pud_none(*pud))
			goto again;

		if (ops->pmd_entry || ops->pte_entry)
			err = walk_pmd_range(pud, addr, next, walk);
		if (err)
			break;
	} while (pud++, addr = next, addr != end);

	return err;
}

static int walk_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
			  struct my_mm_walk *walk)
{
	p4d_t *p4d;
	unsigned long next;
	const struct my_mm_walk_ops *ops = walk->ops;
	int err = 0;

	p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		pr_info("        p4d: %lx, %lx", &addr, addr);
		//if (p4d_none_or_clear_bad(p4d)) {
		//	if (ops->pte_hole)
		//		err = ops->pte_hole(addr, next, walk);
		//	if (err)
		//		break;
		//	continue;
		//}
		if (ops->pmd_entry || ops->pte_entry)
			err = walk_pud_range(p4d, addr, next, walk);
		if (err)
			break;
	} while (p4d++, addr = next, addr != end);

	return err;
}


static int walk_pgd_range(unsigned long addr, unsigned long end,
			  struct my_mm_walk *walk)
{
	pgd_t *pgd;
	unsigned long next;
	const struct my_mm_walk_ops *ops = walk->ops;
	int err = 0;

	pgd = pgd_offset(walk->mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		pr_info("    pgd: %lx, %lx\n", &addr, addr);
		//if (pgd_none_or_clear_bad(pgd)) {
		//	if (ops->pte_hole)
		//		err = ops->pte_hole(addr, next, walk);
		//	if (err)
		//		break;
		//	continue;
		//}
		if (ops->pmd_entry || ops->pte_entry)
			err = walk_p4d_range(pgd, addr, next, walk);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	return err;
}

static int walk_page_test(unsigned long start, unsigned long end,
			struct my_mm_walk *walk)
{
	struct vm_area_struct *vma = walk->vma;
	const struct my_mm_walk_ops *ops = walk->ops;

	//if (ops->test_walk)
	//	return ops->test_walk(start, end, walk);

	/*
	 * vma(VM_PFNMAP) doesn't have any valid struct pages behind VM_PFNMAP
	 * range, so we don't walk over it as we do for normal vmas. However,
	 * Some callers are interested in handling hole range and they don't
	 * want to just ignore any single address range. Such users certainly
	 * define their ->pte_hole() callbacks, so let's delegate them to handle
	 * vma(VM_PFNMAP).
	 */
	if (vma->vm_flags & VM_PFNMAP) {
		int err = 1;
		//if (ops->pte_hole)
		//	err = ops->pte_hole(start, end, walk);
		return err ? err : 1;
	}
	return 0;
}

static int _walk_page_vma(struct vm_area_struct *vma, const struct my_mm_walk_ops *ops,
			void *private)
{
	struct my_mm_walk walk = {
		.ops		= ops,
		.mm		= vma->vm_mm,
		.vma	    	= vma,
		.private	= private,
	};
	int err;

	if (!walk.mm)
		return -EINVAL;

	lockdep_assert_held(&walk.mm->mmap_sem);

	err = walk_page_test(vma->vm_start, vma->vm_end, &walk);
	if (err > 0)
		return 0;
	if (err < 0)
		return err;
	return walk_pgd_range(vma->vm_start, vma->vm_end, &walk);
}

static int vma_walk_pte(pte_t *pte, unsigned long addr,
		unsigned long next, struct my_mm_walk *walk)
{
	return 0;
}

static int vma_walk_pud(pud_t *pud, unsigned long addr,
		unsigned long next, struct my_mm_walk *walk)
{
	return 0;
}

static int vma_walk_pmd(pmd_t *pmd, unsigned long addr,
		unsigned long next, struct my_mm_walk *walk)
{
	return 0;
}

static int vma_walk_p4d(p4d_t *p4d, unsigned long addr,
		unsigned long next, struct my_mm_walk *walk)
{
	return 0;
}

static int vma_walk_pgd(pgd_t *pgd, unsigned long addr,
		unsigned long next, struct my_mm_walk *walk)
{
	return 0;
}

SYSCALL_DEFINE2(expose_page_table, pid_t, pid, struct expose_pgtbl_args __user *, args)
{
	struct task_struct *protagonist;
	struct mm_struct *src_mm;
	struct vm_area_struct *mpnt;
	struct expose_pgtbl_args kargs;
	static const struct my_mm_walk_ops ops = {
		.pte_entry = vma_walk_pte,
		.pmd_entry = vma_walk_pmd,
		.pud_entry = vma_walk_pud,
		.p4d_entry = vma_walk_p4d,
		.pgd_entry = vma_walk_pgd,
	};

	read_lock(&tasklist_lock);
	if (pid == -1)
		protagonist = current;
	else {
		protagonist = get_root(pid);
		if (!protagonist) {
			read_unlock(&tasklist_lock);
			return -EINVAL;
		}
	}
	read_unlock(&tasklist_lock);

	src_mm = protagonist->mm;
	for (mpnt = src_mm->mmap; mpnt; mpnt = mpnt->vm_next) {
		printk(KERN_INFO "vma range: 0x%lx, 0x%lx\n", mpnt->vm_start, mpnt->vm_end);
		down_write(&src_mm->mmap_sem);
		_walk_page_vma(mpnt, &ops, &kargs);
		up_write(&src_mm->mmap_sem);
	}

	return 0;
}

