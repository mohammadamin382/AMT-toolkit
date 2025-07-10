
# Advanced Memory Toolkit (AMT) - Professional Makefile
# Supports multiple kernel versions and build configurations

# Module information
MODULE_NAME := memory_driver
obj-m := $(MODULE_NAME).o

# Kernel version detection
KERNELVER ?= $(shell uname -r)
KERNELDIR ?= /lib/modules/$(KERNELVER)/build
PWD := $(shell pwd)

# Build configuration
EXTRA_CFLAGS += -Wall -Wextra -Werror
EXTRA_CFLAGS += -O2
EXTRA_CFLAGS += -DDEBUG
EXTRA_CFLAGS += -fno-strict-aliasing
EXTRA_CFLAGS += -Wno-unused-parameter
EXTRA_CFLAGS += -Wno-missing-field-initializers

# Architecture-specific flags
ifeq ($(shell uname -m),x86_64)
    EXTRA_CFLAGS += -mcmodel=kernel
endif

# Kernel version specific flags
KERNEL_VERSION := $(shell echo $(KERNELVER) | cut -d. -f1-2)
KERNEL_MAJOR := $(shell echo $(KERNELVER) | cut -d. -f1)
KERNEL_MINOR := $(shell echo $(KERNELVER) | cut -d. -f2)

# Add version-specific compilation flags
ifeq ($(shell test $(KERNEL_MAJOR) -ge 6; echo $$?),0)
    EXTRA_CFLAGS += -DKERNEL_6_PLUS
endif

ifeq ($(shell test $(KERNEL_MAJOR) -ge 5; echo $$?),0)
    EXTRA_CFLAGS += -DKERNEL_5_PLUS
endif

# Default target
all: module

# Build the kernel module
module:
	@echo "Building AMT kernel module for kernel $(KERNELVER)"
	@echo "Kernel directory: $(KERNELDIR)"
	@echo "Architecture: $(shell uname -m)"
	@echo "Compiler flags: $(EXTRA_CFLAGS)"
	@if [ ! -d "$(KERNELDIR)" ]; then \
		echo "Error: Kernel headers not found at $(KERNELDIR)"; \
		echo "Install kernel headers: apt-get install linux-headers-$(KERNELVER)"; \
		exit 1; \
	fi
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f *.mod.c *.mod *.o *.ko *.symvers *.order
	rm -rf .tmp_versions

# Install the module
install: module
	@echo "Installing AMT module..."
	sudo $(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install
	sudo depmod -a
	@echo "Module installed successfully"

# Load the module
load: module
	@echo "Loading AMT module..."
	@if lsmod | grep -q $(MODULE_NAME); then \
		echo "Module already loaded, reloading..."; \
		sudo rmmod $(MODULE_NAME); \
	fi
	sudo insmod $(MODULE_NAME).ko debug_level=1 safety_level=2
	@sleep 1
	@if lsmod | grep -q $(MODULE_NAME); then \
		echo "Module loaded successfully"; \
		dmesg | tail -10 | grep "Advanced Memory"; \
	else \
		echo "Failed to load module"; \
		exit 1; \
	fi

# Unload the module
unload:
	@echo "Unloading AMT module..."
	@if lsmod | grep -q $(MODULE_NAME); then \
		sudo rmmod $(MODULE_NAME); \
		echo "Module unloaded successfully"; \
	else \
		echo "Module not currently loaded"; \
	fi

# Check module status
status:
	@echo "AMT Module Status:"
	@echo "=================="
	@if lsmod | grep -q $(MODULE_NAME); then \
		echo "Status: LOADED"; \
		lsmod | head -1; \
		lsmod | grep $(MODULE_NAME); \
		echo ""; \
		if [ -c /dev/amt_memory ]; then \
			echo "Device: /dev/amt_memory (OK)"; \
			ls -l /dev/amt_memory; \
		else \
			echo "Device: /dev/amt_memory (NOT FOUND)"; \
		fi; \
		echo ""; \
		if [ -f /proc/amt_info ]; then \
			echo "Proc interface: /proc/amt_info (OK)"; \
		else \
			echo "Proc interface: /proc/amt_info (NOT FOUND)"; \
		fi; \
	else \
		echo "Status: NOT LOADED"; \
	fi

# Show kernel logs related to AMT
logs:
	@echo "Recent AMT kernel logs:"
	@echo "======================"
	@dmesg | grep -i "amt\|advanced.*memory" | tail -20 || echo "No AMT logs found"

# Test the module
test: load
	@echo "Testing AMT module..."
	@if [ -f test1.py ]; then \
		python3 test1.py; \
	else \
		echo "test1.py not found, skipping tests"; \
	fi

# Development build with extra debugging
debug: EXTRA_CFLAGS += -DDEBUG -g
debug: module

# Package for distribution
package: clean
	@echo "Creating distribution package..."
	@DATE=$$(date +%Y%m%d); \
	tar -czf amt-toolkit-$$DATE.tar.gz \
		*.c *.py *.md Makefile setup.sh \
		--exclude=*.ko --exclude=*.o --exclude=*.mod*
	@echo "Package created: amt-toolkit-$$(date +%Y%m%d).tar.gz"

# Kernel compatibility check
compat-check:
	@echo "Kernel Compatibility Check:"
	@echo "=========================="
	@echo "Current kernel: $(KERNELVER)"
	@echo "Kernel major: $(KERNEL_MAJOR)"
	@echo "Kernel minor: $(KERNEL_MINOR)"
	@echo ""
	@if [ $(KERNEL_MAJOR) -lt 4 ]; then \
		echo "❌ Unsupported: Kernel $(KERNELVER) is too old"; \
		echo "   Minimum supported version: 4.0"; \
		exit 1; \
	elif [ $(KERNEL_MAJOR) -eq 4 ] && [ $(KERNEL_MINOR) -lt 0 ]; then \
		echo "❌ Unsupported: Kernel $(KERNELVER) is too old"; \
		exit 1; \
	else \
		echo "✅ Supported: Kernel $(KERNELVER) is compatible"; \
	fi
	@echo ""
	@echo "Available features for this kernel:"
	@if [ $(KERNEL_MAJOR) -ge 6 ]; then \
		echo "  ✅ Full feature set (Kernel 6.x)"; \
	elif [ $(KERNEL_MAJOR) -eq 5 ]; then \
		echo "  ✅ Most features (Kernel 5.x)"; \
	else \
		echo "  ⚠️  Basic features (Kernel 4.x)"; \
	fi

# Help target
help:
	@echo "Advanced Memory Toolkit (AMT) - Build System"
	@echo "==========================================="
	@echo ""
	@echo "Available targets:"
	@echo "  all, module     - Build the kernel module"
	@echo "  clean          - Clean build artifacts"
	@echo "  install        - Install module to system"
	@echo "  load           - Load module into kernel"
	@echo "  unload         - Unload module from kernel"
	@echo "  status         - Show module status"
	@echo "  logs           - Show recent kernel logs"
	@echo "  test           - Load module and run tests"
	@echo "  debug          - Build with extra debugging"
	@echo "  package        - Create distribution package"
	@echo "  compat-check   - Check kernel compatibility"
	@echo "  help           - Show this help"
	@echo ""
	@echo "Configuration:"
	@echo "  KERNELVER=$(KERNELVER)"
	@echo "  KERNELDIR=$(KERNELDIR)"
	@echo ""
	@echo "Examples:"
	@echo "  make clean && make load     # Clean build and load"
	@echo "  make test                   # Build, load and test"
	@echo "  make debug                  # Build with debugging"
	@echo "  sudo make install           # Install system-wide"

# Mark phony targets
.PHONY: all module clean install load unload status logs test debug package compat-check help

# Make sure we have a kernel build directory
check-kernel:
	@if [ ! -d "$(KERNELDIR)" ]; then \
		echo "Error: Kernel build directory not found: $(KERNELDIR)"; \
		echo "Please install kernel headers for your kernel version."; \
		echo ""; \
		echo "Ubuntu/Debian: apt-get install linux-headers-$(KERNELVER)"; \
		echo "CentOS/RHEL:   yum install kernel-devel-$(KERNELVER)"; \
		echo "Fedora:        dnf install kernel-devel-$(KERNELVER)"; \
		echo "Arch:          pacman -S linux-headers"; \
		exit 1; \
	fi

# Dependencies
module: check-kernel compat-check
load: module
test: load
install: module
