KERN_DIR = /lib/modules/$(shell uname -r)/build
wxk_firewall-objs := firewall_hook.o
obj-m := wxk_firewall.o 

all:
	make -C $(KERN_DIR) M=$(shell pwd) modules

clean:
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order
