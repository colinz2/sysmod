#include <linux/timer.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <net/netlink.h>
#include <linux/module.h>
#include "sys_usage.h"


static struct timer_list s_timer;

typedef struct stat_cputime_t
{
	uint64_t user;			/* normal processes executing in user mode */      
	uint64_t nice;			/* niced processes executing in user mode */
	uint64_t system;		/* processes executing in kernel mode */   
	uint64_t idle;         
	uint64_t iowait;		/* waiting for I/O to complete */   
	uint64_t irq;			/* servicing interrupts */ 
	uint64_t softirq;		/* servicing softirqs */   
	uint64_t steal;			/* involuntary wait */	   
	uint64_t guest;			/* running a normal guest */  
	uint64_t guest_nice;	/* running a niced guest */
	uint64_t timestamp;		/* time timestamp when read those value */
} stat_cputime_t;

struct cpu_usage_time
{
	uint64_t load;
	uint64_t total;
} cpu_usage_time;

struct cputime_rb
{
	stat_cputime_t *data;
	int size;
	int maxsize;
	int curr;
};

struct cputime_rb *cputimeRB = NULL;

static inline uint64_t 
cputime_get_total(stat_cputime_t *time) 
{ 
	return time->user + time->nice + time->system      
			+ time->idle + time->iowait + time->irq + time->softirq      
				+ time->steal + time->guest + time->guest_nice;
}

static inline uint64_t 
cputime_get_load(stat_cputime_t *time) 
{
	return time->user + time->nice + time->system      
			+ time->irq + time->softirq     
				+ time->steal + time->guest + time->guest_nice;
}
static inline uint64_t 
cputime_get_idle(stat_cputime_t *time) 
{
	return time->idle + time->iowait;
}

static inline uint64_t 
cputime_get_iowait(stat_cputime_t *time) 
{
	return time->iowait;
}

static inline uint64_t 
cputime_get_system(stat_cputime_t *time) 
{
	return time->system;
}

static inline uint64_t 
cputime_get_user(stat_cputime_t *time) 
{
	return time->user + time->nice;
}

static inline uint64_t 
cputime_get_irq(stat_cputime_t *time)
{
	return time->irq + time->softirq;
}
	
static inline uint64_t 
cputime_get_guest(stat_cputime_t *time)
{
	return time->guest + time->guest_nice;
}

struct cputime_rb *
cputime_rb_create(uint32_t size)
{
	struct cputime_rb *rb = kzalloc(sizeof(struct cputime_rb), GFP_KERNEL);
	rb->size = 0;
	rb->curr = 0;
	rb->maxsize = size + 1;
	rb->data = kzalloc(sizeof(stat_cputime_t) * (size + 1), GFP_KERNEL); 
	return rb;
}

void 
cputime_rb_free(struct cputime_rb *rb) 
{
	if (rb->data != NULL) {
		kfree(rb->data);
		kfree(rb);
	}
}

int
cputime_rb_isfull(struct cputime_rb *rb)
{
	return rb->maxsize == rb->size;
}

void
cputime_rb_push(struct cputime_rb *rb, stat_cputime_t *v)
{
	if (!cputime_rb_isfull(rb)) {
		rb->size++;
	}

	if (rb->curr == rb->maxsize - 1) {
		rb->curr = 0;
	} else {
		rb->curr++;
	}

	memcpy(rb->data + rb->curr, v, sizeof(stat_cputime_t));
}

int
cputime_rb_read(struct cputime_rb *rb, int offset, stat_cputime_t *v)
{
	int where = 0;
	if (rb->size <= offset) {
		return -1;
	}

	if (rb->curr < offset) {
		where = rb->maxsize + rb->curr - offset;  
	} else {
		where = rb->curr - offset;
	}
	memcpy(v, rb->data + where, sizeof(stat_cputime_t));
	return 0;
}


static uint32_t
read_cpu_stat(stat_cputime_t *cpu) 
{
	struct file *fp;
	mm_segment_t fs;
	loff_t pos = 0;
	char line[256] = {0};
	fp = filp_open("/proc/stat", O_RDONLY, 0);
	if (IS_ERR(fp)) {
		printk("open file /proc/stat error\n");
		return -1;
	} 

	fs =get_fs();
	set_fs(KERNEL_DS);

	vfs_read(fp, line, sizeof(line), &pos);
	filp_close(fp, NULL);
	set_fs(fs);

	if (sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
		&cpu->user,
		&cpu->nice,
		&cpu->system,
		&cpu->idle,
		&cpu->iowait,
		&cpu->irq,
		&cpu->softirq,
		&cpu->steal,
		&cpu->guest,
		&cpu->guest_nice) < 5) {
		return -1;
	}
	return 0;
}


static void 
cal_cpu_usage_result(stat_cputime_t *b, stat_cputime_t *a, char *buf, int delay) 
{
	//uint64_t usage;
	uint64_t total  = cputime_get_total(a) - cputime_get_total(b);
	uint64_t load   = cputime_get_load(a)  - cputime_get_load(b);
	uint64_t idle   = cputime_get_idle(a)  - cputime_get_idle(b);
	uint64_t iowait = cputime_get_iowait(a) - cputime_get_iowait(b);
	uint64_t system = cputime_get_system(a) - cputime_get_system(b);
	uint64_t user   = cputime_get_user(a) - cputime_get_user(b);
	uint64_t irq    = cputime_get_irq(a) - cputime_get_irq(b);
	uint64_t guest  = cputime_get_guest(a) - cputime_get_guest(b);
	if (total == 0) {
		total = 1;
	}
	//usage = (float) load * 100 / total;
	//sprintf(buf, "%-4lu)\n", guest);
	sprintf(buf, "in last %3ds (total:%-6lu idle:%-6lu io:%-5lu system:%-4lu user:%-5lu irq:%-5lu guest:%-4lu)\n", 
					delay, total, idle, iowait, system, user, irq, guest);
}

static uint32_t 
cpu_usge_analyse(struct cputime_rb *rb, stat_cputime_t *cur)
{
	stat_cputime_t bf;
	char buf[256] = {0};
	struct file *fp;
	mm_segment_t fs;
	loff_t pos = 0;
	int len = 0;

	fp = filp_open("/tmp/cpu_usage_0", O_RDWR | O_CREAT, 0);
		if (IS_ERR(fp)) {
		printk("create file /tmp/cpu_usage_0 error/n");
		return -1;
	}
	fs =get_fs();
	set_fs(KERNEL_DS);

	if (!cputime_rb_read(rb, 5, &bf)) {
		cal_cpu_usage_result(&bf, cur, buf, 5);  
		len = strlen(buf);
		pos += len;
		vfs_write(fp, buf, len, &pos);
	}

	if (!cputime_rb_read(rb, 60, &bf)) {
		cal_cpu_usage_result(&bf, cur, buf, 60); 
		len = strlen(buf);
		pos += len;
		vfs_write(fp, buf, len, &pos);
	}

	if (!cputime_rb_read(rb, 300, &bf)) {
		cal_cpu_usage_result(&bf, cur, buf, 300); 
		len = strlen(buf);
		pos += len;
		vfs_write(fp, buf, len, &pos);
	}

	filp_close(fp, NULL);
	set_fs(fs);
	return 0;
}

static void sys_usage_timer_handle(unsigned long arg)
{
	stat_cputime_t curr;
	int ret;

	mod_timer(&s_timer, jiffies + HZ);
	ret = read_cpu_stat(&curr);
	printk("curr.idle=%llu, curr.system=%llu, curr.user=%llu\n", 
	curr.idle, curr.system, curr.user);
	if (ret == 0) {
		//cpu_usge_analyse(cputimeRB, &curr); 
		cputime_rb_push(cputimeRB, &curr);
	}
}

static int _cpu_usage_sendmsg2user(struct sock *ntsk, int pid, stat_cputime_t *cpu_info, int ret)
{
	int err; 
	struct sk_buff *skb2;
	struct nlmsghdr *nlhnew;
	SYS_USAGE_NETLINK_DATA_S *pstPRData;


	skb2 = nlmsg_new(sizeof(SYS_USAGE_NETLINK_DATA_S), GFP_KERNEL);
	if (skb2 == NULL) {
		printk( KERN_WARNING "_cpu_usage_sendmsg2user \r\n");
		return -ENOMEM;
	}

	nlhnew = nlmsg_put(skb2, 0, 0, SYS_USAGE_NTLK_CPU1, sizeof(SYS_USAGE_NETLINK_DATA_S), 0);
	if (nlhnew == NULL) {
		printk( KERN_WARNING "_cpu_usage_sendmsg2user \r\n");
		return -1;
	}

	pstPRData = nlmsg_data(nlhnew);
	memset(pstPRData, 0x0, sizeof(SYS_USAGE_NETLINK_DATA_S));
	pstPRData->cmd_type = SYS_USAGE_GET_ALL;
	pstPRData->total = cputime_get_total(cpu_info);
	pstPRData->load = cputime_get_load(cpu_info);
	pstPRData->idle = cputime_get_idle(cpu_info);
	pstPRData->io = cputime_get_iowait(cpu_info);
	pstPRData->system = cputime_get_system(cpu_info);
	pstPRData->irq = cputime_get_irq(cpu_info);
	pstPRData->guest = cputime_get_guest(cpu_info);
	pstPRData->user = cputime_get_user(cpu_info);
	pstPRData->ret = ret;
	//printk("total:%lu, load:%lu \r\n", pstPRData->total, pstPRData->load);
	nlmsg_end(skb2, nlhnew);

	err = netlink_unicast(ntsk, skb2, pid, MSG_DONTWAIT);
	if (err < 0) {
		printk( KERN_WARNING "send message to user error:%d \r\n", err);
		return err;
	}
	//printk( KERN_WARNING "uware send message to user :%d [%d] \r\n", pid, err); 
	return 0;
}


int sys_usage_timer_init(void)
{
	init_timer(&s_timer);
	s_timer.function = &sys_usage_timer_handle;
	s_timer.expires = jiffies + HZ;
	add_timer(&s_timer);
	cputimeRB = cputime_rb_create(300);  
	return 0;   
}

void sys_usage_timer_deinit(void)
{
	del_timer(&s_timer);
	cputime_rb_free(cputimeRB);   
}


void sys_dealwith_cpu_usage_msg(struct sock *uware_nlsk, struct nlmsghdr *nlh)
{
	int pid, type, err;
	SYS_USAGE_CPU_NETLINK_S *pstPRData = nlh;
	stat_cputime_t stat_cputime_tmp;
	int timeago;
	int ret;

	type = nlh->nlmsg_type;
	if (type != SYS_USAGE_NTLK_CPU1) {
		printk(KERN_WARNING "uware_dealwith_cpu_usage_msg:%d\r\n", type);
		return;
	}

	pid = nlh->nlmsg_pid; 
	timeago = pstPRData->offset;

	memset(&stat_cputime_tmp, 0, sizeof(stat_cputime_tmp));

	//printk(KERN_WARNING "\r\ntimeage:%d, pid:%lu\r\n", timeage, pid);
	switch(pstPRData->cmd_type)
	{
		case SYS_USAGE_GET_ALL:
			ret = cputime_rb_read(cputimeRB, timeago, &stat_cputime_tmp);
			if (ret == 0) {

			}
		default:
		break;
	}

	_cpu_usage_sendmsg2user(uware_nlsk, pid, &stat_cputime_tmp, ret);
	return;
}

