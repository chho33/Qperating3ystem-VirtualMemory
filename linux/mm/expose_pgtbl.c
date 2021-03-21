#include <linux/expose_pgtbl.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE1(get_pagetable_layout, struct pagetable_layout_info __user *, pgtbl_info)
{
        return 0;
}


SYSCALL_DEFINE2(expose_page_table, pid_t, pid, struct expose_pgtbl_args __user *, args)
{
        return 0;
}

