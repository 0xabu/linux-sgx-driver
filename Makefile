ifneq ($(KERNELRELEASE),)
	isgx-y := \
		sgx_le_proxy_piggy.o \
		sgx_main.o \
		sgx_page_cache.o \
		sgx_ioctl.o \
		sgx_vma.o \
		sgx_util.o\
		sgx_encl.o \
		sgx_encl2.o \
		sgx_le.o
	obj-m += isgx.o
else
KVER ?= $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) AFLAGS_MODULE="-I$(PWD)" modules

install: default
	$(MAKE) INSTALL_MOD_DIR=kernel/drivers/intel/sgx -C $(KDIR) M=$(PWD) modules_install
	sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"

endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd *.o.ur-safe
