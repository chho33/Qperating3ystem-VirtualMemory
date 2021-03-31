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

int pgd_size, p4d_size, pud_size, pmd_size, pte_size;
pgd_t *pgd_check;
p4d_t *p4d_check;
pud_t *pud_check;
pmd_t *pmd_check;
pte_t *pte_check;

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
	bool do_copy = true;

	pte = pte_offset_map(pmd, addr);
	//err = ops->pte_entry(walk);
	//if (err)
	//	return err;

	for (;;) {
		pr_info("                    pte: %lx, %lx, %lx, %lx\n", pte, __pa(pte), addr, (((1UL << 52) - 1) & pte->pte));
		//page_addr = pte_val(*pte) & PAGE_MASK;
		//page_offset = addr & ~PAGE_MASK;
		//paddr = page_addr | page_offset;
		//pr_info("                    pte: %lx, %lx", &addr, addr);
		//printk("                    page_addr = %lx, page_offset = %lx\n", page_addr, page_offset);
		//printk("                    vaddr = %lx, paddr = %lx\n", addr, paddr);

		if (pte == pte_check)
			do_copy = false;
		else
			pte_check = pte;
		//err = ops->pte_entry(walk, addr, do_copy, pte);
		do_copy = true;
		//if(err)
		//	break;

		addr += PAGE_SIZE;
		pte_size++;
		if (addr == end)
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
	bool do_copy = true;

	pmd = pmd_offset(pud, addr);
	//err = ops->pmd_entry(walk);
	//if (err)
	//	return err;
	do {
again:
		next = pmd_addr_end(addr, end);
		pr_info("                pmd: %lx, %lx %lx, %lx, %lx\n", pmd, pte_offset_map(pmd, addr), (pte_t *)pmd_page_vaddr(*pmd), pte_index(addr), native_pmd_val(*pmd));
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

		if (pmd == pmd_check)
			do_copy = false;
		else
			pmd_check = pmd;
		if (ops->pmd_entry)
			err = ops->pmd_entry(walk, addr, do_copy,
					pte_offset_map(pmd, addr));
		do_copy = true;
		if(err)
			break;

		//split_huge_pmd(walk->vma, pmd, addr);
		//if (pmd_trans_unstable(pmd))
		//	goto again;
		err = walk_pte_range(pmd, addr, next, walk);
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
	bool do_copy = true;

	pud = pud_offset(p4d, addr);
	//err = ops->pud_entry(walk);
	//if (err)
	//	return err;
	do {
 again:
		next = pud_addr_end(addr, end);
		pr_info("            pud: %lx, %lx, %lx, %lx, %lx\n", pud, pmd_offset(pud, addr), (pmd_t *)pud_page_vaddr(*pud), pmd_index(addr), native_pud_val(*pud));
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

		if (pud == pud_check)
			do_copy = false;
		else
			pud_check = pud;
		err = ops->pud_entry(walk, addr, do_copy);
		do_copy = true;
		if(err)
			break;

		//split_huge_pud(walk->vma, pud, addr);
		//if (pud_none(*pud))
		//	goto again;

		if (ops->pmd_entry || ops->pte_entry)
			err = walk_pmd_range(pud, addr, next, walk);
		if (err)
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
	bool do_copy = true;

	p4d = p4d_offset(pgd, addr);
	//err = ops->p4d_entry(walk);
	//if (err)
	//	return err;

	do {
		next = p4d_addr_end(addr, end);
		pr_info("        p4d: %lx, %lx, %lx, %lx, %lx, %lx\n", p4d, pud_offset(p4d, addr), (pud_t *)p4d_page_vaddr(*p4d), pud_index(addr), (pud_t *)p4d_page_vaddr(*p4d)+pud_index(addr), native_p4d_val(*p4d));
		//pr_info("        p4d: %lx, %lx", &addr, addr);
		//if (p4d_none_or_clear_bad(p4d)) {
		//	if (ops->pte_hole)
		//		err = ops->pte_hole(addr, next, walk);
		//	if (err)
		//		break;
		//	continue;
		//}
		
		if (p4d == p4d_check)
			do_copy = false;
		else
			p4d_check = p4d;
		err = ops->p4d_entry(walk, addr, do_copy);
		do_copy = true;
		if (err)
			break;
		if (ops->pmd_entry || ops->pte_entry)
			err = walk_pud_range(p4d, addr, next, walk);
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
	bool do_copy = true;

	pgd = pgd_offset(walk->mm, addr);
	pr_info("    mm->pgd: %lx; addr: %lx\n", walk->mm->pgd, addr);

	//err = ops->pgd_entry(walk);
	//if(err)
	//	return err;

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

		if (pgd == pgd_check)
			do_copy = false;
		else
			pgd_check = pgd;
		err = ops->pgd_entry(walk, addr, do_copy);
		do_copy = true;
		if (err)
			break;

		if ((ops->pmd_entry || ops->pte_entry))
			err = walk_p4d_range(pgd, addr, next, walk);
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

static int _walk_page_vma(struct vm_area_struct *vma,
		const struct my_mm_walk_ops *ops, struct to_do *private)
{
	unsigned long addr;
	unsigned long end;

	struct my_mm_walk walk = {
		.ops		= ops,
		.mm		= vma->vm_mm,
		.vma	    	= vma,
		.private	= private,
	};
	int err;

	//return walk_pgd_range(vma->vm_start, vma->vm_end, &walk);

	if (vma->vm_start >= private->kargs.end_vaddr ||
		vma->vm_end <= private->kargs.begin_vaddr)
		return 0;

	addr = vma->vm_start > private->kargs.begin_vaddr ?
		vma->vm_start : private->kargs.begin_vaddr;

	end = vma->vm_end < private->kargs.end_vaddr ?
		vma->vm_end : private->kargs.end_vaddr;

	if (!walk.mm)
		return -EINVAL;

	lockdep_assert_held(&walk.mm->mmap_sem);

	err = walk_page_test(addr, end, &walk);
	if (err > 0)
		return 0;
	if (err < 0)
		return err;

	return walk_pgd_range(addr, end, &walk);
}

static int vma_walk(struct my_mm_walk *walk, int run_tag, unsigned long addr, bool do_copy, pte_t *pte)
{
	struct to_do *to_do = walk->private;
	unsigned long *store;
	unsigned long goods;

	//TODO if the upper level entry is already built,
	//     don't add a new entry but just return.
	

	switch(run_tag) {
		case RUN_PGD:
			if (PGDIR_SHIFT == P4D_SHIFT | !do_copy)
				return 0;
			store = to_do->kargs.fake_pgd +
				pgd_index(addr) * ADDR_SIZE;
			goods = to_do->ptrs.fake_p4ds -
				p4d_index(addr) * ADDR_SIZE;
			pr_info("    store: %lx; goods: %lx; fake_p4ds: %lx", store, goods, to_do->ptrs.fake_p4ds);
			break;
		case RUN_P4D:
			if (!do_copy)
				return 0;
			if (PGDIR_SHIFT == P4D_SHIFT){
				store = to_do->kargs.fake_pgd +
					pgd_index(addr) * ADDR_SIZE;
			} else {
				store = to_do->ptrs.fake_p4ds;
			}
			goods = to_do->ptrs.fake_puds -
				pud_index(addr) * ADDR_SIZE;
			pr_info("        store: %lx; goods: %lx; fake_puds: %lx", store, goods, to_do->ptrs.fake_puds);
			break;
		case RUN_PUD:
			if (!do_copy)
				return 0;
			store = to_do->ptrs.fake_puds;
			goods = to_do->ptrs.fake_pmds -
				pmd_index(addr) * ADDR_SIZE;
			pr_info("            store: %lx; goods: %lx; fake_pmds: %lx", store, goods, to_do->ptrs.fake_pmds);
			break;
		case RUN_PMD:
			if (!do_copy)
				return 0;
			store = to_do->ptrs.fake_pmds;
			goods = to_do->ptrs.page_table_addr;
			pr_info("                store: %lx; goods: %lx; page_table_addr: %lx", store, goods, to_do->ptrs.page_table_addr);
			to_do->remap_list->next = kmalloc(sizeof(struct remap_linked_list), GFP_KERNEL);
			to_do->remap_list = to_do->remap_list->next;
			to_do->remap_list->kaddr = (unsigned long)pte;
			to_do->remap_list->uaddr = to_do->ptrs.page_table_addr;
			to_do->remap_list->next = NULL;

			break;
		default:
			break;
	}

	to_do->map_list->next = kmalloc(sizeof(struct map_linked_list), GFP_KERNEL);
	if(!to_do->map_list->next)
		return -ENOMEM;

	to_do->map_list = to_do->map_list->next;
	to_do->map_list->store = (unsigned long *) store;
	to_do->map_list->goods = goods;
	to_do->map_list->next = NULL;
	//pr_info("store: %lx, goods: %lx\n", store, goods);

go_next:
	switch(run_tag) {
		case RUN_PGD:
			to_do->ptrs.fake_pgd += ADDR_SIZE;
			break;
		case RUN_P4D:
			if (PGDIR_SHIFT == P4D_SHIFT) {
				to_do->ptrs.fake_pgd += ADDR_SIZE;
				break;
			}
			to_do->ptrs.fake_p4ds += ADDR_SIZE;
			break;
		case RUN_PUD:
			to_do->ptrs.fake_puds += ADDR_SIZE;
			break;
		case RUN_PMD:
			to_do->ptrs.fake_pmds += ADDR_SIZE;
			to_do->ptrs.page_table_addr += 1 << PAGE_SHIFT;
			break;
		case RUN_PTE:
			to_do->ptrs.page_table_addr += ADDR_SIZE;
			break;
		default:
			break;
	}
	return 0;
}

static inline int vma_walk_pgd(struct my_mm_walk *walk, unsigned long addr, bool do_copy)
{
	return vma_walk(walk, RUN_PGD, addr, do_copy, NULL);
}

static inline int vma_walk_p4d(struct my_mm_walk *walk, unsigned long addr, bool do_copy)
{
	return vma_walk(walk, RUN_P4D, addr, do_copy, NULL);
}

static inline int vma_walk_pud(struct my_mm_walk *walk, unsigned long addr, bool do_copy)
{
	return vma_walk(walk, RUN_PUD, addr, do_copy, NULL);
}

static inline int vma_walk_pmd(struct my_mm_walk *walk, unsigned long addr, bool do_copy, pte_t *pte)
{
	return vma_walk(walk, RUN_PMD, addr, do_copy, pte);
}

static inline int vma_walk_pte(struct my_mm_walk *walk, unsigned long addr, bool do_copy, pte_t *pte)
{
	return vma_walk(walk, RUN_PTE, addr, do_copy, pte);
}

static inline bool is_cow_mapping(vm_flags_t flags)
{
	return (flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE;
}

static int remap_pte_range(struct mm_struct *mm, pmd_t *pmd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pte_t *pte;
	spinlock_t *ptl;
	int err = 0;

	pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
	if (!pte)
		return -ENOMEM;
	arch_enter_lazy_mmu_mode();
	do {
		BUG_ON(!pte_none(*pte));
		if (!pfn_modify_allowed(pfn, prot)) {
			err = -EACCES;
			break;
		}
		set_pte_at(mm, addr, pte, pte_mkspecial(pfn_pte(pfn, prot)));
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
	arch_leave_lazy_mmu_mode();
	pte_unmap_unlock(pte - 1, ptl);
	return err;
}

static inline int remap_pmd_range(struct mm_struct *mm, pud_t *pud,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;
	int err;

	pfn -= addr >> PAGE_SHIFT;
	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return -ENOMEM;
	VM_BUG_ON(pmd_trans_huge(*pmd));
	do {
		next = pmd_addr_end(addr, end);
		err = remap_pte_range(mm, pmd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			return err;
	} while (pmd++, addr = next, addr != end);
	return 0;
}

static inline int remap_pud_range(struct mm_struct *mm, p4d_t *p4d,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;
	int err;

	pfn -= addr >> PAGE_SHIFT;
	pud = pud_alloc(mm, p4d, addr);
	if (!pud)
		return -ENOMEM;
	do {
		next = pud_addr_end(addr, end);
		err = remap_pmd_range(mm, pud, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			return err;
	} while (pud++, addr = next, addr != end);
	return 0;
}

static inline int remap_p4d_range(struct mm_struct *mm, pgd_t *pgd,
			unsigned long addr, unsigned long end,
			unsigned long pfn, pgprot_t prot)
{
	p4d_t *p4d;
	unsigned long next;
	int err;

	pfn -= addr >> PAGE_SHIFT;
	p4d = p4d_alloc(mm, pgd, addr);
	if (!p4d)
		return -ENOMEM;
	do {
		next = p4d_addr_end(addr, end);
		err = remap_pud_range(mm, p4d, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			return err;
	} while (p4d++, addr = next, addr != end);
	return 0;
}

int test_remap_pfn_range(struct vm_area_struct *vma, unsigned long addr,
		    unsigned long pfn, unsigned long size, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long end = addr + PAGE_ALIGN(size);
	struct mm_struct *mm = vma->vm_mm;
	unsigned long remap_pfn = pfn;
	int err;

	if (is_cow_mapping(vma->vm_flags)) {
		if (addr != vma->vm_start || end != vma->vm_end)
			return -EINVAL;
		vma->vm_pgoff = pfn;
	}

	err = track_pfn_remap(vma, &prot, remap_pfn, addr, PAGE_ALIGN(size));
	if (err)
		return -EINVAL;

	//vma->vm_flags |= VM_READ | VM_SHARED;
	//vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP; 
	vma->vm_flags |= VM_READ | VM_SHARED | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP; 

	BUG_ON(addr >= end);
	pfn -= addr >> PAGE_SHIFT;
	pgd = pgd_offset(mm, addr);
	flush_cache_range(vma, addr, end);
	do {
		next = pgd_addr_end(addr, end);
		err = remap_p4d_range(mm, pgd, addr, next,
				pfn + (addr >> PAGE_SHIFT), prot);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);

	if (err)
		untrack_pfn(vma, remap_pfn, PAGE_ALIGN(size));

	return err;
}

SYSCALL_DEFINE2(expose_page_table, pid_t, pid, struct expose_pgtbl_args __user *, args)
{
	struct task_struct *protagonist;
	struct mm_struct *src_mm;
	struct vm_area_struct *mpnt, *vma_pte;
	struct expose_pgtbl_args kargs;
	static const struct my_mm_walk_ops ops = {
		.pgd_entry = vma_walk_pgd,
		.p4d_entry = vma_walk_p4d,
		.pud_entry = vma_walk_pud,
		.pmd_entry = vma_walk_pmd,
		.pte_entry = vma_walk_pte,
	};
	struct to_do node;
	struct map_linked_list map_list, *head, *dummy;
	struct remap_linked_list remap_list, *remap_head, *remap_dummy;
	unsigned long pfn;
	int size = 0;

	pgd_size = 0;
	p4d_size = 0;
	pud_size = 0;
	pmd_size = 0;
	pte_size = 0;
        pgd_check = NULL;
	p4d_check = NULL;
	pud_check = NULL;
	pmd_check = NULL;
	pte_check = NULL;

	if (copy_from_user(&kargs, args, sizeof(struct expose_pgtbl_args)))
		return -EFAULT;

	node.kargs = kargs;
	node.ptrs = kargs;
	node.map_list = &map_list;
	//node.curr_pte_base = 1;
	dummy = &map_list;
	head = &map_list;
	node.remap_list = &remap_list;
	remap_dummy = &remap_list;
	remap_head = &remap_list;

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
	down_write(&src_mm->mmap_sem);
	for (mpnt = src_mm->mmap; mpnt; mpnt = mpnt->vm_next) {
		printk(KERN_INFO "vma range: 0x%lx, 0x%lx, %d\n", mpnt->vm_start, mpnt->vm_end, (mpnt->vm_end - mpnt->vm_start) / PAGE_SIZE);
		size += (mpnt->vm_end - mpnt->vm_start) / PAGE_SIZE;
		_walk_page_vma(mpnt, &ops, &node);
		//printk("map_list: %lx, %lx\n", node.map_list->store, node.map_list->goods);
		//printk("head->next: %lx, %lx\n", head->next->store, head->next->goods);
	}
	up_write(&src_mm->mmap_sem);

	head = head->next;
	while(head) {
		printk("copy %lx to %lx\n", head->goods, head->store);
		if (copy_to_user(head->store, &head->goods, sizeof(unsigned long))) {
			return -EFAULT;
		}
		head = head->next;
	}

	vma_pte = find_vma(src_mm, kargs.page_table_addr);
	remap_head = remap_head->next;
	while(remap_head) {
		//printk("remap %lx to %lx\n", remap_head->kaddr, remap_head->uaddr);
		pfn = __pa(remap_head->kaddr) >> PAGE_SHIFT;
		printk("remap %lx (pfn: %lx) to %lx\n", remap_head->kaddr, pfn, remap_head->uaddr);
		//if (remap_pfn_range(vma_pte, remap_head->uaddr, pfn, PAGE_SIZE, vma_pte->vm_page_prot))
		if (test_remap_pfn_range(vma_pte, remap_head->uaddr, pfn, PAGE_SIZE, vma_pte->vm_page_prot))
			return -EFAULT;
		remap_head = remap_head->next;
		//break;
	}

	pr_info("kfree-ing...\n");
	if(dummy->next)
		kfree(dummy->next);
	if(remap_dummy->next)
		kfree(remap_dummy->next);
	pr_info("==================\n");

	printk("size: %d\n", size);
	printk("pgd_size: %d\n", pgd_size);
	printk("p4d_size: %d\n", p4d_size);
	printk("pud_size: %d\n", pud_size);
	printk("pmd_size: %d\n", pmd_size);
	printk("pte_size: %d\n", pte_size);

	//if (copy_to_user(args, &kargs, sizeof(struct expose_pgtbl_args)))
	//	return -EFAULT;

	return 0;
}
