obj-m  := kylo.o

kylo-y := \
        src/main.o \
        src/proc.o \
        src/work.o

EXTRA_CFLAGS = -I$(PWD)/hdr

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) $(EXTRA_CFLAGS) modules

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

debug:
	@echo     KVERSION $(KVERSION)
	@echo EXTRA_CFLAGS $(EXTRA_CFLAGS)
