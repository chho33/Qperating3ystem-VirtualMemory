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
int _printpgd(struct mm_struct *src_mm, pgd_t *src_pgd,
		struct vm_area_struct *vma, unsigned long addr, unsigned long end)
{
	p4d_t *src_p4d;
	unsigned long next;
	src_p4d = p4d_offset(src_pgd, addr);
	pr_info("%lx, %lx", &src_p4d, src_p4d);
	do {
		next = p4d_addr_end(addr, end);
	} while (src_p4d++, addr = next, addr != end);

	return 0;
}

int printpgd(struct mm_struct *src_mm, struct vm_area_struct *vma)
{
	pgd_t *src_pgd;
	unsigned long next;
	unsigned long addr = vma->vm_start;
	unsigned long end = vma->vm_end;
	src_pgd = pgd_offset(src_mm, addr);
	//pr_info("    %lx\n", src_pgd);
	do {
		next = pgd_addr_end(addr, end);
		pr_info("    %lx\n", addr);
		_printpgd(src_mm, src_pgd, vma, addr, next);
	} while (src_pgd++, addr = next, addr !=end);

	return 0;
}

static struct task_struct *get_root(int root_pid)
{
	if (root_pid == 0)
		return &init_task;

	return find_task_by_vpid(root_pid);
}

SYSCALL_DEFINE2(expose_page_table, pid_t, pid, struct expose_pgtbl_args __user *, args)
{
	struct task_struct *protagonist;
	struct mm_struct *src_mm;
	struct vm_area_struct *mpnt;

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
		printk(KERN_INFO "0x%lx, 0x%lx\n", mpnt->vm_start, mpnt->vm_end);
		printpgd(src_mm, mpnt);
	}

	return 0;
}

