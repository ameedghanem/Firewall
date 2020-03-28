obj-m += hw5secws.o

hw5secws-objs = source/firewall.o source/conns_table.o source/rules_parser.o source/log_list.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
