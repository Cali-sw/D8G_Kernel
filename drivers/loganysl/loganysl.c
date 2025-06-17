// loganysl.c - Memory R/W Kernel Module for Android

#include <linux/module.h> #include <linux/kernel.h> #include <linux/init.h> #include <linux/fs.h> #include <linux/proc_fs.h> #include <linux/uaccess.h> #include <linux/sched.h> #include <linux/mm.h> #include <linux/pid.h> #include <linux/slab.h>

#define PROC_NAME "loganysl"

struct mem_op { pid_t pid; unsigned long addr; size_t size; char buffer[256]; int write; // 0 = read, 1 = write };

static ssize_t loganysl_write(struct file *file, const char __user *ubuf, size_t len, loff_t *off) { struct mem_op op; struct task_struct *task; struct mm_struct *mm; struct vm_area_struct *vma; int ret;

if (len != sizeof(struct mem_op))
    return -EINVAL;

if (copy_from_user(&op, ubuf, len))
    return -EFAULT;

rcu_read_lock();
task = pid_task(find_vpid(op.pid), PIDTYPE_PID);
if (!task) {
    rcu_read_unlock();
    return -ESRCH;
}

mm = get_task_mm(task);
rcu_read_unlock();
if (!mm)
    return -EFAULT;

down_read(&mm->mmap_sem);
vma = find_vma(mm, op.addr);
if (!vma || op.addr < vma->vm_start) {
    up_read(&mm->mmap_sem);
    mmput(mm);
    return -EFAULT;
}

if (op.write)
    ret = copy_to_user((void __user *)op.addr, op.buffer, op.size);
else
    ret = copy_from_user(op.buffer, (void __user *)op.addr, op.size);

up_read(&mm->mmap_sem);
mmput(mm);

return ret ? -EFAULT : len;

}

static const struct proc_ops loganysl_ops = { .proc_write = loganysl_write, };

static int __init loganysl_init(void) { proc_create(PROC_NAME, 0666, NULL, &loganysl_ops); pr_info("loganysl module loaded\n"); return 0; }

static void __exit loganysl_exit(void) { remove_proc_entry(PROC_NAME, NULL); pr_info("loganysl module unloaded\n"); }

MODULE_LICENSE("GPL"); module_init(loganysl_init); module_exit(loganysl_exit);

