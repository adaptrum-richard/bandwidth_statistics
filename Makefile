obj-m += bw_info.o
bw_info-objs := bandwidth.o tree_map.o 
all:
	$(MAKE) -C $(DIR_LINUX) M=$(shell pwd) modules
clean:  
	rm -f *.ko *.o *.mod.o *.mod.c *.symvers  *.order 
