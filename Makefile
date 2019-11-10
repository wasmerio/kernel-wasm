HDR_PATH := /lib/modules/$(shell uname -r)

default:
	$(MAKE) -C $(HDR_PATH)/build M=$(PWD) modules

install:
	sudo $(MAKE) -C $(HDR_PATH)/build M=$(PWD) modules_install
	sudo depmod -a

clean:
	$(MAKE) -C $(HDR_PATH)/build M=$(PWD) clean
	rm $(shell find ${HDR_PATH} -name "*wasm*")
