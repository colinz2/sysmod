obj-m           := sysmod.o
sysmod-objs :=  sys_mod.o sys_usage.o
KBUILD_DIR      := /lib/modules/$(shell uname -r)/build

all: module app

module:
	make -C $(KBUILD_DIR) M=$(shell pwd)
app:
	gcc -o test test.c
clean:
	make -C $(KBUILD_DIR) M=$(shell pwd) clean

