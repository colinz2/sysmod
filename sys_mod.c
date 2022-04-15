#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "sys_usage.h"

#define _AUTHOR "colin.zhang"
#define _DESC "module_linux"


#define NETLINK_USER 31


struct sock *nlsk = NULL;

static void sys_mod_recv_msg(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int type, err, i; 

	nlh = nlmsg_hdr(skb);
	err = 0;

	if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len) {
		printk(KERN_WARNING " error len \r\n");
		return;
	}

	type = nlh->nlmsg_type;
	if (type > SYS_USAGE_NTLK_MAX) {
		printk(KERN_WARNING "rcv error type:%d\r\n", type);
		return;
	}

	switch (type) {
		case SYS_USAGE_NTLK_CPU1:
			sys_dealwith_cpu_usage_msg(nlsk, nlh);
			break;
		default:
			printk( KERN_WARNING "netlink_rcv rcv invalid type:%d\r\n", type);
			err = -1;
		break;
	}

	if (err != 0 ) {
		printk( KERN_WARNING "netlink_rcv return :%d \r\n", err);
		return;
	}
}

static int __init sys_mod_nl_init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = sys_mod_recv_msg,
	};

	printk(KERN_INFO "Starting  kernel module...\n");    

	nlsk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);

	printk("Entering: %s\n", __func__);

	if (!nlsk){
		printk(KERN_ALERT "Error creating socket.\n");
		return -1;
	}

	return 0;
}

static int __init sys_mod_init(void)
{
	int ret;
	ret = sys_mod_nl_init();
	if (ret != 0) {
		return ret;
	}
	sys_usage_timer_init();
	return 0;
}

static void __exit sys_mod_exit(void)
{
	printk(KERN_INFO "exiting sys_mod module. goodbye.\n");
	netlink_kernel_release(nlsk);
	sys_usage_timer_deinit();
}

//set kernel function macros
module_init(sys_mod_init); 
module_exit(sys_mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(_AUTHOR);  
MODULE_DESCRIPTION(_DESC);
