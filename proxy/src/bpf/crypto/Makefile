obj-m += bpf_crypto_digest.o 
obj-m += bpf_crypto_shash.o 

# Enable BTF generation
KBUILD_CFLAGS += -g -O2

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean