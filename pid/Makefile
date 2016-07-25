obj-m           := pid.o
pid-objs :=  pid.o
KBUILD_DIR      := /lib/modules/$(shell uname -r)/build

all: module app

module:
	make -C $(KBUILD_DIR) M=$(shell pwd)
clean:
	make -C $(KBUILD_DIR) M=$(shell pwd) clean