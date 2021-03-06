VERSION     :=  1
MAX_SNULLS  :=  2

obj-m  := kylo$(VERSION).o

kylo$(VERSION)-y := \
        src/main.o \
        src/proc.o \
        src/work.o

EXTRA_CFLAGS = -I$(PWD)/hdr 
CFLAGS_MODULE=-DKYLOVER=$(VERSION) -DMAX_DEVS=$(MAX_SNULLS)
#KCPPFLAGS="-DDATE=\\\"\"$(shell date)\"\\\""
#KCPPFLAGS="-DDATE=$(shell date) -DPROCFS_NAME=kylo2"

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) $(KPPFLAGS) $(EXTRA_CFLAGS) modules
	@echo "---------------------------------------------------"
	@echo "sudo insmod ./kylo$(VERSION).ko"
	@echo "cat /proc/kylo$(VERSION)"
	@echo "sudo bash -c 'echo \"1\" > /proc/kylo$(VERSION)'"
	@echo "sudo bash -c 'echo \"2\" > /proc/kylo$(VERSION)'"
	@echo "sudo bash -c 'echo "test string" > /proc/kylo$(VERSION)'"
	@echo "sudo ifconfig sn0 local0; sudo ifconfig sn1 local1"
	@echo "ping -c 2 -s 1900 remote0"
	@echo "sudo rmmod kylo$(VERSION)"

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

debug:
	@echo      KVERSION $(KVERSION)
	@echo  EXTRA_CFLAGS $(EXTRA_CFLAGS)
	@echo CFLAGS_MODULE $(CFLAGS_MODULE)
	@echo KYLO_KM_NAME  kylo$(VERSION).ko
