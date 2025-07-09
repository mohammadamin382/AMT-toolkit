
obj-m += memory_driver.o

KVERSION = $(shell uname -r)
KERNEL_DIR = /lib/modules/$(KVERSION)/build
PWD = $(shell pwd)

# Compiler flags for advanced features
EXTRA_CFLAGS += -DCONFIG_NEXUS_QUANTUM=1
EXTRA_CFLAGS += -DQUANTUM_SIGNATURE=0xDEADBEEFCAFEBABE
EXTRA_CFLAGS += -O2 -Wno-unused-function
EXTRA_CFLAGS += -DDEBUG_QUANTUM_OPS

all:
	@echo "🔨 Building AMT Kernel Module..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
	@echo "✅ AMT kernel module built successfully"

clean:
	@echo "🧹 Cleaning AMT build artifacts..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	@echo "✅ Clean completed"

install: all
	@echo "📦 Installing AMT..."
	sudo insmod memory_driver.ko
	sudo chmod 666 /dev/nexus_quantummemx
	@echo "✅ AMT installed and ready"

uninstall:
	@echo "🗑️ Uninstalling AMT..."
	sudo rmmod memory_driver
	@echo "✅ AMT uninstalled"

#test: install
	#@echo "🧪 Running AMT tests..."
	#sudo python3 test_toolkit.py
	#@echo "✅ Tests completed"

.PHONY: all clean install uninstall test
