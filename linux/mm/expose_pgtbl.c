#include <linux/expose_pgtbl.h>
#include <linux/syscalls.h>
#include <asm/io.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <linux/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>
#include <asm/pgtable_64.h>

int size = 1, pgd_size = 1, p4d_size = 1, pud_size = 1, pmd_size = 1, pte_size = 1;

SYSCALL_DEFINE1(get_pagetable_layout, struct pagetable_layout_info __user *, pgtbl_info)
{
	struct pagetable_layout_info kinfo;

	kinfo.pgdir_shift = PGDIR_SHIFT;
	kinfo.p4d_shift = P4D_SHIFT;
	kinfo.pud_shift = PUD_SHIFT;
	kinfo.pmd_shift = PMD_SHIFT;
	kinfo.page_shift = PAGE_SHIFT;

	printk(KERN_INFO "PAGE_OFFSET = 0x%lx\n", PAGE_OFFSET);
	printk(KERN_INFO "PGDIR_SHIFT = %d\n", PGDIR_SHIFT);
	printk(KERN_INFO "P4D_SHIFT = %d\n", P4D_SHIFT);
	printk(KERN_INFO "PUD_SHIFT = %d\n", PUD_SHIFT);
	printk(KERN_INFO "PMD_SHIFT = %d\n", PMD_SHIFT);
	printk(KERN_INFO "PAGE_SHIFT = %d\n", PAGE_SHIFT);

	printk(KERN_INFO "PTRS_PER_PGD = %d\n", PTRS_PER_PGD);
	printk(KERN_INFO "PTRS_PER_P4D = %d\n", PTRS_PER_P4D);
	printk(KERN_INFO "PTRS_PER_PUD = %d\n", PTRS_PER_PUD);
	printk(KERN_INFO "PTRS_PER_PMD = %d\n", PTRS_PER_PMD);
	printk(KERN_INFO "PTRS_PER_PTE = %d\n", PTRS_PER_PTE);

	printk(KERN_INFO "PAGE_MASK = 0x%lx\n", PAGE_MASK);

	if (copy_to_user(pgtbl_info, &kinfo, sizeof(struct pagetable_layout_info)))
		return -EFAULT;

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
	err = ops->pte_entry(walk);
	if (err)
		return err;

	for (;;) {
		pr_info("                    pte: %lx, %lx, %lx\n", pte, addr, (((1UL << 46) - 1) & pte->pte) >> 12 << 12);
		//page_addr = pte_val(*pte) & PAGE_MASK;
		//page_offset = addr & ~PAGE_MASK;
		//paddr = page_addr | page_offset;
		//pr_info("                    pte: %lx, %lx", &addr, addr);
		//printk("                    page_addr = %lx, page_offset = %lx\n", page_addr, page_offset);
		//printk("                    vaddr = %lx, paddr = %lx\n", addr, paddr);
		//err = ops->pte_entry(walk);
		//if (err)
		//       break;
		addr += PAGE_SIZE;
		pte_size++;
		if (addr == end)
			break;
		err = ops->pte_entry(walk);
		if (err)
		       break;
		pte++;
	}
// try xxx_val() ??
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
	err = ops->pmd_entry(walk);
	if (err)
		return err;
	do {
again:
		next = pmd_addr_end(addr, end);
		pr_info("                pmd: %lx, %lx", pmd, pte_offset_map(pmd, addr));
		//pr_info("                pmd: %lx, %lx", &addr, addr);
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
		if (ops->pmd_entry)
			err = ops->pmd_entry(walk);
		if (err)
			break;
		pmd_size++;
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
	err = ops->pud_entry(walk);
	if (err)
		return err;
	do {
 again:
		next = pud_addr_end(addr, end);
		pr_info("            pud: %lx, %lx", pud, pmd_offset(pud, addr));
		//pr_info("            pud: %lx, %lx", &addr, addr);
		//if (pud_none(*pud) || !walk->vma) {
		//	if (ops->pte_hole)
		//		err = ops->pte_hole(addr, next, walk);
		//	if (err)
		//		break;
		//	continue;
		//}

		//if (ops->pud_entry) {
		//	spinlock_t *ptl = pud_trans_huge_lock(pud, walk->vma);

		//	if (ptl) {
		//		err = ops->pud_entry(walk);
		//		spin_unlock(ptl);
		//		if (err)
		//			break;
		//		continue;
		//	}
		//}

		split_huge_pud(walk->vma, pud, addr);
		if (pud_none(*pud))
			goto again;

		if (ops->pmd_entry || ops->pte_entry)
			err = walk_pmd_range(pud, addr, next, walk);
		if (err)
			break;
		err = ops->pud_entry(walk);
		if(err)
			break;
		pud_size++;
	} while (pud++, addr = next, addr != end);

	return err;
}

static int walk_p4d_range(pgd_t *pgd, unsigned long addr, unsigned long end,
			  struct my_mm_walk *walk)
{
	p4d_t *p4d;
	unsigned long next, *base;
	const struct my_mm_walk_ops *ops = walk->ops;
	int err = 0;

	p4d = p4d_offset(pgd, addr);
	err = ops->p4d_entry(walk);
	if (err)
		return err;

	do {
		next = p4d_addr_end(addr, end);
		pr_info("        p4d: %lx, %lx\n", p4d, pud_offset(p4d, addr));
		//pr_info("        p4d: %lx, %lx", &addr, addr);
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
		err = ops->p4d_entry(walk);
		if (err)
			break;
		p4d_size++;
	} while (p4d++, addr = next, addr != end);

	return err;
}


static int walk_pgd_range(unsigned long addr, unsigned long end,
			  struct my_mm_walk *walk)
{
	pgd_t *pgd;
	unsigned long next;
	const struct my_mm_walk_ops *ops = walk->ops;
	struct to_do *to_do = walk->private;
	int err = 0;

	pgd = pgd_offset(walk->mm, addr);

	err = ops->pgd_entry(walk);
	if(err)
		return err;

	do {
		next = pgd_addr_end(addr, end);
		//err = ops->pgd_entry(walk);
		//if(err)
		//	return;

		pr_info("    pgd: %lx, %lx\n", pgd, p4d_offset(pgd, addr));
		//pr_info("    pgd: %lx, %lx\n", &addr, addr);
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

		err = ops->pgd_entry(walk);
		if (err)
			break;

		pgd_size++;
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

static int vma_walk(struct my_mm_walk *walk, int run_tag)
{
	struct to_do *to_do = walk->private;
	unsigned long *store;
	unsigned long goods;

	switch(run_tag) {
		case RUN_PGD:
			store = to_do->kargs.fake_pgd;
			goods = to_do->kargs.fake_p4ds;
			to_do->map_list->next = kmalloc(sizeof(struct map_linked_list), GFP_KERNEL);
			if(!to_do->map_list->next)
				return -ENOMEM;

			to_do->map_list = to_do->map_list->next;
			to_do->map_list->store = (unsigned long *) store;
			to_do->map_list->goods = goods;
			break;
		case RUN_P4D:
			store = to_do->kargs.fake_p4ds;
			goods = to_do->kargs.fake_puds;
			break;
		case RUN_PUD:
			store = to_do->kargs.fake_puds;
			goods = to_do->kargs.fake_pmds;
			break;
		case RUN_PMD:
			store = to_do->kargs.fake_pmds;
			goods = to_do->kargs.page_table_addr;
			break;
		default:
			break;
	}

	//to_do->map_list->next = kmalloc(sizeof(struct map_linked_list), GFP_KERNEL);
	//if(!to_do->map_list->next)
	//	return -ENOMEM;

	//to_do->map_list = to_do->map_list->next;
	//to_do->map_list->store = (unsigned long *) store;
	//to_do->map_list->goods = goods;

	switch(run_tag) {
		case RUN_PGD:
			to_do->kargs.fake_pgd += ADDR_SIZE;
			break;
		case RUN_P4D:
			to_do->kargs.fake_p4ds += ADDR_SIZE;
			break;
		case RUN_PUD:
			to_do->kargs.fake_puds += ADDR_SIZE;
			break;
		case RUN_PMD:
			to_do->kargs.fake_pmds += ADDR_SIZE;
			break;
		default:
			break;
	}

	return 0;
}

static inline int vma_walk_pgd(struct my_mm_walk *walk)
{
	return vma_walk(walk, RUN_PGD);
}

static inline int vma_walk_p4d(struct my_mm_walk *walk)
{
	return vma_walk(walk, RUN_P4D);
}

static inline int vma_walk_pud(struct my_mm_walk *walk)
{
	return vma_walk(walk, RUN_PUD);
}

static inline int vma_walk_pmd(struct my_mm_walk *walk)
{
	return vma_walk(walk, RUN_PMD);
}

static inline int vma_walk_pte(struct my_mm_walk *walk)
{
	return 0;
	return vma_walk(walk, RUN_PTE);
}

SYSCALL_DEFINE2(expose_page_table, pid_t, pid, struct expose_pgtbl_args __user *, args)
{
	struct task_struct *protagonist;
	struct mm_struct *src_mm;
	struct vm_area_struct *mpnt;
	struct expose_pgtbl_args kargs;
	static const struct my_mm_walk_ops ops = {
		.pgd_entry = vma_walk_pgd,
		.p4d_entry = vma_walk_p4d,
		.pud_entry = vma_walk_pud,
		.pmd_entry = vma_walk_pmd,
		.pte_entry = vma_walk_pte,
	};
	struct to_do node;
	struct map_linked_list map_list, *head;
	int size = 0;

	if (copy_from_user(&kargs, args, sizeof(struct expose_pgtbl_args)))
		return -EFAULT;

	node.kargs = kargs;
	node.map_list = &map_list;
	head = &map_list;

	// 1. go through the page table tree and get the size of each layer
	// 2. mmap()
	// 3. build the fake layers.
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
		printk(KERN_INFO "vma range: 0x%lx, 0x%lx, %d\n", mpnt->vm_start, mpnt->vm_end, (mpnt->vm_end - mpnt->vm_start) / PAGE_SIZE);
		size += (mpnt->vm_end - mpnt->vm_start) / PAGE_SIZE;
		down_write(&src_mm->mmap_sem);
		_walk_page_vma(mpnt, &ops, &node);
		up_write(&src_mm->mmap_sem);
		//printk("map_list: %lx, %lx\n", node.map_list->store, node.map_list->goods);
		//printk("head->next: %lx, %lx\n", head->next->store, head->next->goods);
	}

	head = head->next;
	while(head) {
		printk("copy %lx to %lx\n", head->goods, head->store);
		//if (copy_to_user(head->store, &head->goods, sizeof(unsigned long))) {
		//	return -EFAULT;
		//}
		head = head->next;
	}

	printk("size: %d\n", size);
	printk("pgd_size: %d\n", pgd_size);
	printk("p4d_size: %d\n", p4d_size);
	printk("pud_size: %d\n", pud_size);
	printk("pmd_size: %d\n", pmd_size);
	printk("pte_size: %d\n", pte_size);
	size = 1;
	pgd_size = 1;
	p4d_size = 1;
	pud_size = 1;
	pmd_size = 1;
	pte_size = 1;

	if (copy_to_user(args, &kargs, sizeof(struct expose_pgtbl_args)))
		return -EFAULT;

	return 0;
}
