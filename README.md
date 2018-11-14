# sys_usage
using the kernel module to store statistics of /proc/stat, use netlink to get from user mode

```sh

$ sudo apt-get install linux-headers-$(uname -r)
$ make
$ sudo insmod sysmod
$ ./test

$ sudo rmmod sysmod

```


simple-rootkit
