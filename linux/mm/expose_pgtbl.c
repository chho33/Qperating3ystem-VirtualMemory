#include <linux/expose_pgtbl.h>
#include <linux/syscalls.h>
#include <linux/io.h>
#include <linux/mmu_context.h>
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

SYSCALL_DEFINE1(get_pagetable_layout,
		struct pagetable_layout_info __user *, pgtbl_info)
{
	struct pagetable_layout_info kinfo;

	kinfo.pgdir_shift = PGDIR_SHIFT;
	#ifndef P4D_SHIFT
	#define P4D_SHIFT PGDIR_SHIFT
	#endif
	kinfo.p4d_shift = P4D_SHIFT;
	#ifndef PUD_SHIFT
	#define PUD_SHIFT P4D_SHIFT
	#endif
	kinfo.pud_shift = PUD_SHIFT;
	#ifndef PMD_SHIFT
	#define PMD_SHIFT PUD_SHIFT
	#endif
	kinfo.pmd_shift = PMD_SHIFT;
	kinfo.page_shift = PAGE_SHIFT;

	//pr_info("PAGE_OFFSET = 0x%lx\n", PAGE_OFFSET);
	pr_info("PGDIR_SHIFT = %d\n", PGDIR_SHIFT);
	pr_info("P4D_SHIFT = %d\n", P4D_SHIFT);
	pr_info("PUD_SHIFT = %d\n", PUD_SHIFT);
	pr_info("PMD_SHIFT = %d\n", PMD_SHIFT);
	pr_info("PAGE_SHIFT = %d\n", PAGE_SHIFT);

	pr_info("PTRS_PER_PGD = %d\n", PTRS_PER_PGD);
	pr_info("PTRS_PER_P4D = %d\n", PTRS_PER_P4D);
	pr_info("PTRS_PER_PUD = %d\n", PTRS_PER_PUD);
	pr_info("PTRS_PER_PMD = %d\n", PTRS_PER_PMD);
	pr_info("PTRS_PER_PTE = %d\n", PTRS_PER_PTE);

	//pr_info("PAGE_MASK = 0x%lx\n", PAGE_MASK);

	if (copy_to_user(pgtbl_info, &kinfo,
		sizeof(struct pagetable_layout_info)))
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
	bool do_copy = true;

	pte = pte_offset_map(pmd, addr);

	for (;;) {
		//pr_info("\t\t  pte: %lx, %lx, %lx, %lx\n",
		//		pte, __pa(pte), addr,
		//		(((1UL << 52) - 1) & pte->pte));

		if (pte == pte_check)
			do_copy = false;
		else
			pte_check = pte;
		do_copy = true;

		addr += PAGE_SIZE;
		pte_size++;
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
	bool do_copy = true;

	pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		//pr_info("\t\tpmd: %lx, %lx %lx, %lx\n",
		//	pmd,
		//	pte_offset_map(pmd, addr),
		//	(pte_t *)pmd_page_vaddr(*pmd),
		//	pte_index(addr));
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
		if (err)
			break;
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
	do {
		next = pud_addr_end(addr, end);
		//pr_info("\t    pud: %lx, %lx, %lx, %lx\n",
		//		pud, pmd_offset(pud, addr),
		//		(pmd_t *)pud_page_vaddr(*pud),
		//		pmd_index(addr));

		if (pud == pud_check)
			do_copy = false;
		else
			pud_check = pud;
		err = ops->pud_entry(walk, addr, do_copy);
		do_copy = true;
		if (err)
			break;

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
	unsigned long next;
	const struct my_mm_walk_ops *ops = walk->ops;
	int err = 0;
	bool do_copy = true;

	p4d = p4d_offset(pgd, addr);

	do {
		next = p4d_addr_end(addr, end);
		//pr_info("\tp4d: %lx, %lx, %lx, %lx, %lx, %lx\n",
		//	p4d, pud_offset(p4d, addr),
		//	(pud_t *)p4d_page_vaddr(*p4d),
		//	pud_index(addr),
		//	(pud_t *)p4d_page_vaddr(*p4d)+pud_index(addr),
		//	native_p4d_val(*p4d));

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
	int err = 0;
	bool do_copy = true;

	pgd = pgd_offset(walk->mm, addr);
	//pr_info("    mm->pgd: %lx; addr: %lx\n", walk->mm->pgd, addr);

	do {
		next = pgd_addr_end(addr, end);

		//pr_info("    pgd: %lx, %lx\n", pgd,
		//	p4d_offset(pgd, addr));
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

	if (vma->vm_flags & VM_PFNMAP) {
		int err = 1;

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
		.ops = ops,
		.mm = vma->vm_mm,
		.vma = vma,
		.private = private,
	};
	int err;

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

static int vma_walk(struct my_mm_walk *walk, int run_tag,
		unsigned long addr, bool do_copy, pte_t *pte)
{
	struct to_do *to_do = walk->private;
	unsigned long *store = NULL;
	unsigned long goods = 0;

	switch (run_tag) {
	case RUN_PGD:
		if ((PGDIR_SHIFT == P4D_SHIFT) | !do_copy)
			return 0;
		store = (unsigned long *) (to_do->kargs.fake_pgd +
			pgd_index(addr) * ADDR_SIZE);
		goods = to_do->ptrs.fake_p4ds -
			p4d_index(addr) * ADDR_SIZE;
		//pr_info("    store: %lx; goods: %lx; fake_p4ds: %lx",
		//	store, goods, to_do->ptrs.fake_p4ds);
		break;
	case RUN_P4D:
		if (!do_copy)
			return 0;
		if (PGDIR_SHIFT == P4D_SHIFT) {
			store = (unsigned long *) (to_do->kargs.fake_pgd +
				pgd_index(addr) * ADDR_SIZE);
		} else {
			store = (unsigned long *) to_do->ptrs.fake_p4ds;
		}
		goods = to_do->ptrs.fake_puds -
			pud_index(addr) * ADDR_SIZE;
		//pr_info("\tstore: %lx; goods: %lx; fake_puds: %lx",
		//	store, goods, to_do->ptrs.fake_puds);
		break;
	case RUN_PUD:
		if (!do_copy)
			return 0;
		if (PGDIR_SHIFT == PUD_SHIFT) {
			store = (unsigned long *) (to_do->kargs.fake_pgd +
				pgd_index(addr) * ADDR_SIZE);
		} else if (P4D_SHIFT == PUD_SHIFT) {
			store = (unsigned long *) to_do->ptrs.fake_p4ds;
		} else {
			store = (unsigned long *) to_do->ptrs.fake_puds;
		}
		store = (unsigned long *) to_do->ptrs.fake_puds;
		goods = to_do->ptrs.fake_pmds -
			pmd_index(addr) * ADDR_SIZE;
		//pr_info("\t    store: %lx; goods: %lx; fake_pmds: %lx",
		//	store, goods, to_do->ptrs.fake_pmds);
		break;
	case RUN_PMD:
		if (!do_copy)
			return 0;
		if (PGDIR_SHIFT == PMD_SHIFT) {
			store = (unsigned long *) (to_do->kargs.fake_pgd +
				pgd_index(addr) * ADDR_SIZE);
		} else if (P4D_SHIFT == PMD_SHIFT) {
			store = (unsigned long *) to_do->ptrs.fake_p4ds;
		} else if (PUD_SHIFT == PMD_SHIFT) {
			store = (unsigned long *) to_do->ptrs.fake_puds;
		} else {
			store = (unsigned long *) to_do->ptrs.fake_pmds;
		}
		store = (unsigned long *) to_do->ptrs.fake_pmds;
		goods = to_do->ptrs.page_table_addr;
		//pr_info("\t\tstore: %lx; goods: %lx; pt_addr: %lx",
		//	store, goods, to_do->ptrs.page_table_addr);
		to_do->remap_list->next = kmalloc(
				sizeof(struct remap_linked_list),
				GFP_KERNEL);
		to_do->remap_list = to_do->remap_list->next;
		to_do->remap_list->kaddr = (unsigned long)pte;
		to_do->remap_list->uaddr = to_do->ptrs.page_table_addr;
		to_do->remap_list->next = NULL;

		break;
	default:
		break;
	}

	to_do->map_list->next = kmalloc(sizeof(struct map_linked_list),
			GFP_KERNEL);
	if (!to_do->map_list->next)
		return -ENOMEM;

	to_do->map_list = to_do->map_list->next;
	to_do->map_list->store = (unsigned long *) store;
	to_do->map_list->goods = goods;
	to_do->map_list->next = NULL;

	switch (run_tag) {
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

static inline int vma_walk_pgd(struct my_mm_walk *walk, unsigned long addr,
		bool do_copy)
{
	return vma_walk(walk, RUN_PGD, addr, do_copy, NULL);
}

static inline int vma_walk_p4d(struct my_mm_walk *walk, unsigned long addr,
		bool do_copy)
{
	return vma_walk(walk, RUN_P4D, addr, do_copy, NULL);
}

static inline int vma_walk_pud(struct my_mm_walk *walk, unsigned long addr,
		bool do_copy)
{
	return vma_walk(walk, RUN_PUD, addr, do_copy, NULL);
}

static inline int vma_walk_pmd(struct my_mm_walk *walk, unsigned long addr,
		bool do_copy, pte_t *pte)
{
	return vma_walk(walk, RUN_PMD, addr, do_copy, pte);
}

static inline int vma_walk_pte(struct my_mm_walk *walk, unsigned long addr,
		bool do_copy, pte_t *pte)
{
	return vma_walk(walk, RUN_PTE, addr, do_copy, pte);
}

SYSCALL_DEFINE2(expose_page_table, pid_t, pid,
		struct expose_pgtbl_args __user *, args)
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
	node.remap_list = &remap_list;
	head = &map_list;
	dummy = &map_list;
	remap_head = &remap_list;
	remap_dummy = &remap_list;

	head->next = NULL;
	dummy->next = NULL;
	remap_head->next = NULL;
	remap_dummy->next = NULL;

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
		//pr_info("vma range: 0x%lx, 0x%lx, %d\n",
		//		mpnt->vm_start, mpnt->vm_end,
		//		(mpnt->vm_end - mpnt->vm_start) / PAGE_SIZE);
		size += (mpnt->vm_end - mpnt->vm_start) / PAGE_SIZE;
		_walk_page_vma(mpnt, &ops, &node);
	}
	up_write(&src_mm->mmap_sem);

	head = head->next;
	while (head) {
		//pr_info("copy %lx to %lx\n", head->goods, head->store);
		if (copy_to_user(head->store, &head->goods,
					sizeof(unsigned long))) {
			return -EFAULT;
		}
		head = head->next;
	}

	vma_pte = find_vma(current->mm, kargs.page_table_addr);
	remap_head = remap_head->next;
	down_write(&(vma_pte->vm_mm->mmap_sem));
	while (remap_head) {
		pfn = __pa(remap_head->kaddr) >> PAGE_SHIFT;
		//pr_info("remap %lx (pfn: %lx) to %lx\n",
		//	remap_head->kaddr, pfn, remap_head->uaddr);
		if (remap_pfn_range(vma_pte, remap_head->uaddr, pfn,
					PAGE_SIZE, vma_pte->vm_page_prot))
			return -EFAULT;
		remap_head = remap_head->next;
	}
	up_write(&(vma_pte->vm_mm->mmap_sem));

	pr_info("kfree-ing...\n");
	kfree(dummy->next);
	kfree(remap_dummy->next);
	pr_info("==================\n");

	pr_info("size: %d\n", size);
	pr_info("pgd_size: %d\n", pgd_size);
	pr_info("p4d_size: %d\n", p4d_size);
	pr_info("pud_size: %d\n", pud_size);
	pr_info("pmd_size: %d\n", pmd_size);
	pr_info("pte_size: %d\n", pte_size);

	return 0;
}
