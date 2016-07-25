obj-m           := pid.o
KBUILD_DIR      := /lib/modules/$(shell uname -r)/build

all: module

module:
	make -C $(KBUILD_DIR) M=$(shell pwd)
clean:
	make -C $(KBUILD_DIR) M=$(shell pwd) clean