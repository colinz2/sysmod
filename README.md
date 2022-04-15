# sys_usage
using the kernel module to store statistics of /proc/stat, use netlink to get from user mode

- sysmod 在内核模块中统计 CPU 利用率。然后可以通过用户态工具获取内核的统计。

```bash
$ sudo apt-get install linux-headers-$(uname -r)
$ make

# 插入模块
$ sudo insmod sysmod

# 测试获取 CPU 利用率
$ ./test

# 卸载模块
$ sudo rmmod sysmod

```
# CPU 利用率生成工具
https://github.com/realzhangm/cpu_load_gen.git

# reference
simple-rootkit
