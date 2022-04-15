#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/init_task.h>
#include <linux/sched.h>
#include <linux/list.h>

#define _AUTHOR "zhangm"
#define _DESC "module_linux"

static __init int print_pid(void)
{
	struct task_struct *task,*p;
	struct list_head *pos;
	int count=0;
	printk("Hello,let begin\n");
	task=&init_task;
	list_for_each(pos, &task->tasks)
	{
		p = list_entry(pos, struct task_struct, tasks);
		count++;
		printk("%d---->%s\n", p->pid, p->comm);
	}
	printk("the number of process is:%d\n", count);
	return 0;
}
static __exit void print_exit(void)
{
	printk("pid end!\n");
}

module_init(print_pid);
module_exit(print_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(_AUTHOR);
MODULE_DESCRIPTION(_DESC);
