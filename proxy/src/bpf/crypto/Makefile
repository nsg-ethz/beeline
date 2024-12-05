obj-m += bpf_crypto_shash.o 

# Enable BTF generation
KBUILD_CFLAGS += -g -O2
TARGET_DIR=$(PWD)/../../../../target/release/build
TARGET=$(TARGET_DIR)/bpf_crypto_shash.ko

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mkdir -p $(TARGET_DIR)
	cp bpf_crypto_shash.ko $(TARGET_DIR)
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

reload: all
	sudo rmmod bpf_crypto_shash.ko || true
	sudo insmod $(TARGET)

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean