#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>

typedef enum {
	SYS_USAGE_NTLK_UNUSED,
	SYS_USAGE_NTLK_CPU1 = 1,
	SYS_USAGE_NTLK_MAX
} SYSUSAGE_NETLINK_TYPE;

enum cpu_usage_type
{
	SYS_USAGE_GET_LOAD_TOTAL = 1,
	SYS_USAGE_GET_ALL
};

typedef struct SYS_USAGE_NETLINK_DATA_S
{
	uint32_t cmd_type;
	union {
		struct {
			uint64_t total;
			uint64_t load;
			uint64_t idle;
			uint64_t io;
			uint64_t system;
			uint64_t user;
			uint64_t irq;
			uint64_t guest;
		};
		uint32_t offset;
	};
	uint32_t ret;
	unsigned char buffer[0];
}SYS_USAGE_NETLINK_DATA_S;

typedef struct SYS_USAGE_CPU_NETLINK_STRUCT
{
	struct   nlmsghdr hdr;
	uint32_t cmd_type;
	union {
		struct {
			uint64_t total;
			uint64_t load;
			uint64_t idle;
			uint64_t io;
			uint64_t system;
			uint64_t user;
			uint64_t irq;
			uint64_t guest;
		};
		uint32_t offset;
	};
	uint32_t ret;
	unsigned char buffer[0];
}SYS_USAGE_CPU_NETLINK_S;

int sys_usage_timer_init(void);
void sys_usage_timer_deinit(void);
void sys_dealwith_cpu_usage_msg(struct sock *uware_nlsk, struct nlmsghdr *nlh);