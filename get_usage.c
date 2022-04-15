#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define NETLINK_USER 31

typedef enum {
  SYS_USAGE_NTLK_UNUSED,
  SYS_USAGE_NTLK_CPU1 = 1,
  SYS_USAGE_NTLK_MAX
} SYSUSAGE_NETLINK_TYPE;

enum cpu_usage_type { SYS_USAGE_GET_LOAD_TOTAL = 1, SYS_USAGE_GET_ALL };

typedef struct SYS_USAGE_NETLINK_DATA_S {
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
} SYS_USAGE_NETLINK_DATA_S;

typedef struct SYS_USAGE_CPU_NETLINK_STRUCT {
  struct nlmsghdr hdr;
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
} SYS_USAGE_CPU_NETLINK_S;

typedef struct cpu_usagetime_t {
  uint64_t total;
  uint64_t load;
  uint64_t idle;
  uint64_t io;
  uint64_t system;
  uint64_t user;
  uint64_t irq;
  uint64_t guest;
} cpu_usagetime_t;

static int set_nonblocking(int fd) {
  int flags;
  /* According to the Single UNIX Spec, the return value for F_GETFL should
  never be negative. */
  if ((flags = fcntl(fd, F_GETFL)) < 0) {
    return -1;
  }
  if (fcntl(fd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
    return -1;
  }
  return 0;
}

static int netlink_init(void) {
  int iFd;
  int iOpt = 1;
  struct sockaddr_nl addr;

  iFd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_USER);
  if (iFd < 0) {
    return -1;
  }
  setsockopt(iFd, SOL_SOCKET, SO_REUSEADDR, &iOpt, sizeof(iOpt));
  addr.nl_family = PF_NETLINK;
  addr.nl_pad = 0;
  addr.nl_pid = getpid();
  addr.nl_groups = 0;
  if (bind(iFd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(iFd);
    return -1;
  }
  set_nonblocking(iFd);
  return iFd;
}

static int netlink_send_get_data(int socketfd, void *data, int send_len,
                                 int recv_len) {
  int ret;
  int iSpeepCount = 0;

  struct sockaddr_nl st_peer_addr;
  st_peer_addr.nl_family = AF_NETLINK;
  st_peer_addr.nl_pad = 0;    /*always set to zero*/
  st_peer_addr.nl_pid = 0;    /*kernel's pid is zero*/
  st_peer_addr.nl_groups = 0; /*multicast groups mask, if unicast set to zero*/

  /*recv message */
  ret = sendto(socketfd, data, send_len, 0, (struct sockaddr *)&st_peer_addr,
               sizeof(st_peer_addr));
  if (ret < 0) {
    return -1;
  }
  while (1) {
    ret = recvfrom(socketfd, data, recv_len, 0, NULL, NULL);
    if (ret < 0 && iSpeepCount < 3) {
      iSpeepCount++;
    } else if (3 == iSpeepCount) {
      return -1;
    } else {
      break;
    }
  }

  return 0;
}

static int get_cputm_from_kernel(int offset, cpu_usagetime_t *curr) {
  int iRet;
  int iSocketFd = 0;
  SYS_USAGE_CPU_NETLINK_S stPRData;

  iSocketFd = netlink_init();
  if (iSocketFd <= 0) {
    return -1;
  }

  memset(&stPRData, 0x00, sizeof(stPRData));

  stPRData.hdr.nlmsg_len =
      sizeof(stPRData); // NLMSG_LENGTH(sizeof(netlink_notify_s))
  stPRData.hdr.nlmsg_flags = 0;
  stPRData.hdr.nlmsg_type = SYS_USAGE_NTLK_CPU1;
  stPRData.hdr.nlmsg_pid = getpid(); /* set sender  PID*/

  stPRData.cmd_type = SYS_USAGE_GET_ALL;
  stPRData.offset = offset;

  iRet = netlink_send_get_data(iSocketFd, &stPRData, sizeof(stPRData),
                               sizeof(stPRData));
  if (iRet == 0) {
    if (stPRData.ret != 0) {
      close(iSocketFd);
      return -1;
    } else {
      curr->total = stPRData.total;
      curr->load = stPRData.load;
      curr->io = stPRData.io;
      curr->irq = stPRData.irq;
      curr->system = stPRData.system;
      curr->idle = stPRData.idle;
      curr->guest = stPRData.guest;
      curr->user = stPRData.user;
    }
  } else {
    close(iSocketFd);
    return -1;
  }
  close(iSocketFd);
  return 0;
}

static void cal_cpu_usage_result(cpu_usagetime_t *b, cpu_usagetime_t *a,
                                 char *buf, int delay) {
  uint64_t total = a->total - b->total;
  uint64_t load = a->load - b->load;
  uint64_t irq = a->irq - b->irq;
  uint64_t system = a->system - b->system;
  uint64_t user = a->user - b->user;
  uint64_t io = a->io - b->io;
  uint64_t guest = a->guest - b->guest;
  uint64_t idle = a->idle - b->idle;

  float usage = (float)load * 100 / total;

  sprintf(buf,
          "%5.2f%% in last %3ds (total:%-5llu idle:%-5llu load:%-5llu "
          "io:%-5llu system:%-4llu user:%-5llu irq:%-5llu guest:%-4llu)\n",
          usage, delay, total, idle, load, io, system, user, irq, guest);
}

void test_cpu_usage(void) {
  cpu_usagetime_t bf, cur;
  char buf[512] = {0};
  int ret;

  ret = get_cputm_from_kernel(0, &cur);
  if (ret != 0) {
    printf("error to get cpu usage\n");
    return;
  }

  if (!get_cputm_from_kernel(5, &bf)) {
    cal_cpu_usage_result(&bf, &cur, buf, 5);
    printf("%s\n", buf);
  } else {
    return;
  }

  if (!get_cputm_from_kernel(60, &bf)) {
    cal_cpu_usage_result(&bf, &cur, buf, 60);
    printf("%s\n", buf);
  } else {
    return;
  }

  if (!get_cputm_from_kernel(300, &bf)) {
    cal_cpu_usage_result(&bf, &cur, buf, 300);
    printf("%s\n", buf);
  } else {
    return;
  }
}

int main() {
  test_cpu_usage();
  return 0;
}
