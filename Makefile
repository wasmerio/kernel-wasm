obj-m += linux-ext-wasm.o
linux-ext-wasm-objs += ext.o uapi.o kapi.o vm.o
HDR_PATH := /lib/modules/$(shell uname -r)/build

all:
	make -C $(HDR_PATH) M=$(PWD) modules

clean:
	make -C $(HDR_PATH) M=$(PWD) clean
