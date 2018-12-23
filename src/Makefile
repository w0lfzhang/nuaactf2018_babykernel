obj-m := magic.o 
KERNELDIR := /lib/modules/4.4.52/build
PWD := $(shell pwd) 
modules: 
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules 
modules_install: 
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
clean:  
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
