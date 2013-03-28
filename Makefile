CC          := gcc -m32 -Wall -Wextra -pedantic -std=gnu99 #-D NDEBUG
CFLAGS      := -fPIC
LDFLAGS     :=

SOURCES     := $(wildcard *.c)
DEPENDS     := $(subst .c,.d,$(SOURCES))
MAINOBJS	  := $(subst .c,.o,$(shell grep -l "MAKE MAIN" $(SOURCES)))
SHAREDOBJS  := $(subst .c,.o,$(shell grep -l "MAKE SHARED LIBRARY" $(SOURCES)))
MAIN        := $(subst .o,,$(MAINOBJS))
SHARED			:= $(patsubst %.o,lib%.so,$(SHAREDOBJS))

all: $(DEPENDS) $(MAIN) $(SHARED)

test: all
	cd test; ln -sf ../libloader.so; LD_LIBRARY_PATH=. $(MAKE) test

$(DEPENDS) : %.d : %.c
	$(CC) -MT $(<:.c=.o) -MM $< > $@
	@echo -e "\t"$(CC) -c $(CFLAGS) $< -o $(<:.c=.o) >> $@

$(MAIN) : % : %.o
	$(CC) $(LDFLAGS) -o $@ $^

$(SHARED) : lib%.so : %.o
	$(CC) $(LDFLAGS) -shared -Wl,-soname=$@ -o $@ $^

-include $(DEPENDS)

clean:
	-rm -f *.o $(DEPENDS) $(MAIN) $(SHARED) $(MAINOBJS) $(SHAREDOBJS)
	-cd test; rm -f libloader.so; $(MAKE) clean

qemu:
	@qemu-system-x86_64 ../qemu/zso2013_cow.img \
		-drive file=../qemu/zso2013_cow.img,if=virtio \
		-enable-kvm \
		-smp 4 \
		-net nic,model=virtio -net user \
		-m 512M -balloon virtio \
		-fsdev local,id=hshare,path=./,security_model=none -device virtio-9p-pci,fsdev=hshare,mount_tag=hshare \
		-chardev stdio,id=cons,signal=off -device virtio-serial-pci -device virtconsole,chardev=cons \


.PHONY: clean test qemu
