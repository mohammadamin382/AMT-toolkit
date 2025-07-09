#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/crypto.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <linux/random.h>
#include <linux/scatterlist.h>
#include <linux/capability.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/version.h>

// Kernel version compatibility macros
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define HAVE_MMAP_LOCK
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
#define HAVE_PTE_OFFSET_MAP_LOCK
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define HAVE_SCHED_MM_H
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
#define from_kuid_munged(ns, kuid) __kuid_val(kuid)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
#define COMPAT_OLD_VM_FLAGS
#endif

#define DEVICE_NAME "advanced_memory"
#define CLASS_NAME "advmem_class"
#define BUFFER_SIZE 8192

// IOCTL commands
#define IOCTL_READ_PHYS_MEM _IOR('M', 1, struct mem_operation)
#define IOCTL_WRITE_PHYS_MEM _IOW('M', 2, struct mem_operation)
#define IOCTL_VIRT_TO_PHYS _IOWR('M', 3, struct addr_translation)
#define IOCTL_PHYS_TO_VIRT _IOWR('M', 4, struct addr_translation)
#define IOCTL_GET_PAGE_INFO _IOWR('M', 5, struct page_info)
#define IOCTL_ENCRYPT_MEMORY _IOWR('M', 6, struct mem_encryption)
#define IOCTL_DECRYPT_MEMORY _IOWR('M', 7, struct mem_encryption)

struct mem_operation {
    unsigned long phys_addr;
    unsigned long size;
    unsigned long flags;
    char data[BUFFER_SIZE];
    int result;
};

struct addr_translation {
    unsigned long input_addr;
    unsigned long output_addr;
    pid_t pid;
    int success;
    unsigned long page_table_levels[5];
    unsigned long protection_flags;
};

struct page_info {
    unsigned long addr;
    unsigned long page_frame;
    unsigned long flags;
    int present;
    int writable;
    int user;
    int accessed;
    int dirty;
    int global;
    int nx;
    unsigned long cache_type;
};

struct mem_encryption {
    unsigned long addr;
    unsigned long size;
    char key[32];
    char iv[16];
    int algorithm; // 0=AES256, 1=ChaCha20
    char encrypted_data[BUFFER_SIZE];
    int result;
};

static int major_number;
static struct class* advmem_class = NULL;
static struct device* advmem_device = NULL;
static DEFINE_MUTEX(advmem_mutex);

// Debug level: 0=errors only, 1=info, 2=debug
static int debug_level = 1;
module_param(debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Debug level (0=errors, 1=info, 2=debug)");

// Safe mode levels: 0=disabled, 1=basic, 2=standard, 3=maximum
static int safe_mode = 2;
module_param(safe_mode, int, 0644);
MODULE_PARM_DESC(safe_mode, "Safety level (0=disabled, 1=basic, 2=standard, 3=maximum)");

// Debug macros
#define advmem_err(fmt, ...) \
    printk(KERN_ERR "Advanced Memory: " fmt, ##__VA_ARGS__)

#define advmem_info(fmt, ...) \
    do { if (debug_level >= 1) \
        printk(KERN_INFO "Advanced Memory: " fmt, ##__VA_ARGS__); \
    } while (0)

#define advmem_debug(fmt, ...) \
    do { if (debug_level >= 2) \
        printk(KERN_DEBUG "Advanced Memory: " fmt, ##__VA_ARGS__); \
    } while (0)

// Safety check macros
#define SAFETY_CHECK_LEVEL(level) (safe_mode >= (level))
#define SAFETY_DISABLED() (safe_mode == 0)

// Memory range limits based on safety level
#define SAFE_MAX_SIZE_LEVEL1    (64 * 1024)      // 64KB
#define SAFE_MAX_SIZE_LEVEL2    (16 * 1024)      // 16KB  
#define SAFE_MAX_SIZE_LEVEL3    (4 * 1024)       // 4KB

// Critical memory ranges to protect in safe mode
#define CRITICAL_MEM_START      0x0
#define CRITICAL_MEM_END        0x100000         // First 1MB
#define KERNEL_STACK_PROTECT    0xffffc90000000000UL
#define VSYSCALL_START          0xffffffffff600000UL
#define VSYSCALL_END            0xffffffffff601000UL

// Compatibility helper for older kernels
static inline void advmem_mmap_read_lock(struct mm_struct *mm) {
#ifdef HAVE_MMAP_LOCK
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
}

static inline void advmem_mmap_read_unlock(struct mm_struct *mm) {
#ifdef HAVE_MMAP_LOCK
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
}

static inline pte_t *advmem_pte_offset_map(pmd_t *pmd, unsigned long addr) {
#ifdef HAVE_PTE_OFFSET_MAP_LOCK
    return pte_offset_map(pmd, addr);
#else
    return pte_offset_kernel(pmd, addr);
#endif
}

// Safety validation functions
static bool is_safe_physical_address(unsigned long phys_addr, size_t size) {
    if (SAFETY_DISABLED()) return true;
    
    // Level 1+: Basic critical region protection
    if (SAFETY_CHECK_LEVEL(1)) {
        if (phys_addr < CRITICAL_MEM_END) {
            advmem_err("SAFETY: Blocked access to critical memory region 0x%lx\n", phys_addr);
            return false;
        }
    }
    
    // Level 2+: Additional range checks
    if (SAFETY_CHECK_LEVEL(2)) {
        if (phys_addr >= 0xffffffffff000000UL) {
            advmem_err("SAFETY: Blocked access to high memory region 0x%lx\n", phys_addr);
            return false;
        }
    }
    
    // Level 3: Maximum paranoia - only allow well-known safe ranges
    if (SAFETY_CHECK_LEVEL(3)) {
        unsigned long pfn = phys_addr >> PAGE_SHIFT;
        if (!pfn_valid(pfn)) {
            advmem_err("SAFETY: Invalid PFN 0x%lx\n", pfn);
            return false;
        }
        
        // Additional checks for NUMA nodes and memory zones
        struct page *page = pfn_to_page(pfn);
        if (!page || PageReserved(page) || PageSlab(page) || PageCompound(page)) {
            advmem_err("SAFETY: Unsafe page properties at 0x%lx\n", phys_addr);
            return false;
        }
    }
    
    return true;
}

static bool is_safe_virtual_address(unsigned long virt_addr, pid_t pid) {
    if (SAFETY_DISABLED()) return true;
    
    // Level 1+: Basic kernel protection
    if (SAFETY_CHECK_LEVEL(1)) {
        if (virt_addr >= KERNEL_STACK_PROTECT && virt_addr < (KERNEL_STACK_PROTECT + 0x10000000000UL)) {
            advmem_err("SAFETY: Blocked kernel stack access 0x%lx\n", virt_addr);
            return false;
        }
        
        if (virt_addr >= VSYSCALL_START && virt_addr < VSYSCALL_END) {
            advmem_err("SAFETY: Blocked vsyscall page access 0x%lx\n", virt_addr);
            return false;
        }
    }
    
    // Level 2+: Process validation
    if (SAFETY_CHECK_LEVEL(2) && pid != 0) {
        struct task_struct *task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (!task || task->flags & PF_EXITING) {
            advmem_err("SAFETY: Invalid or exiting process %d\n", pid);
            return false;
        }
    }
    
    // Level 3: Strict user space validation
    if (SAFETY_CHECK_LEVEL(3)) {
        if (pid == 0 && virt_addr < PAGE_OFFSET) {
            advmem_err("SAFETY: Invalid kernel address 0x%lx\n", virt_addr);
            return false;
        }
    }
    
    return true;
}

static size_t get_safe_max_size(void) {
    if (SAFETY_DISABLED()) return BUFFER_SIZE;
    
    switch (safe_mode) {
        case 1: return SAFE_MAX_SIZE_LEVEL1;
        case 2: return SAFE_MAX_SIZE_LEVEL2;
        case 3: return SAFE_MAX_SIZE_LEVEL3;
        default: return BUFFER_SIZE;
    }
}

static bool is_safe_operation_size(size_t size) {
    if (SAFETY_DISABLED()) return (size <= BUFFER_SIZE);
    
    size_t max_size = get_safe_max_size();
    if (size > max_size) {
        advmem_err("SAFETY: Size %zu exceeds safe limit %zu (level %d)\n", 
                   size, max_size, safe_mode);
        return false;
    }
    
    return true;
}

// Function prototypes
static int device_open(struct inode*, struct file*);
static int device_release(struct inode*, struct file*);
static long device_ioctl(struct file*, unsigned int, unsigned long);
static int read_physical_memory(unsigned long phys_addr, void* buffer, size_t size);
static int write_physical_memory(unsigned long phys_addr, const void* buffer, size_t size);
static unsigned long virtual_to_physical_addr(unsigned long virt_addr, pid_t pid);
static unsigned long physical_to_virtual_addr(unsigned long phys_addr, pid_t pid);
static int get_page_information(unsigned long addr, struct page_info *info);
static int encrypt_memory_region(struct mem_encryption *enc);
static int decrypt_memory_region(struct mem_encryption *enc);

static struct file_operations fops = {
    .open = device_open,
    .release = device_release,
    .unlocked_ioctl = device_ioctl,
};

// Enhanced physical memory read with multi-page support and safety checks
static int read_physical_memory(unsigned long phys_addr, void* buffer, size_t size) {
    void __iomem *mapped_addr;
    struct page *page;
    unsigned long pfn, start_pfn, end_pfn;
    size_t bytes_read = 0;
    size_t chunk_size;
    unsigned long current_addr = phys_addr;
    char *buf_ptr = (char *)buffer;

    if (!buffer || size == 0) {
        advmem_err("Invalid parameters for read: buffer=%p, size=%zu\n", buffer, size);
        return -EINVAL;
    }

    // Safety checks
    if (!is_safe_operation_size(size)) {
        return -EINVAL;
    }
    
    if (!is_safe_physical_address(phys_addr, size)) {
        return -EPERM;
    }

    // Apply size limits only if safety is enabled
    if (!SAFETY_DISABLED() && size > get_safe_max_size()) {
        advmem_err("Size %zu exceeds safety limit %zu\n", size, get_safe_max_size());
        return -EINVAL;
    }

    start_pfn = phys_addr >> PAGE_SHIFT;
    end_pfn = (phys_addr + size - 1) >> PAGE_SHIFT;

    advmem_debug("Reading %zu bytes from 0x%lx (spans %lu pages)\n", 
                 size, phys_addr, end_pfn - start_pfn + 1);

    // Process each page that the read spans
    while (bytes_read < size) {
        pfn = current_addr >> PAGE_SHIFT;

        // Check if physical address is valid
        if (!pfn_valid(pfn)) {
            advmem_err("Invalid physical address: 0x%lx (PFN: %lx)\n", current_addr, pfn);
            return -EINVAL;
        }

        // Get the page structure
        page = pfn_to_page(pfn);
        if (!page) {
            advmem_err("Cannot get page for PFN: %lx\n", pfn);
            return -EINVAL;
        }

        // Additional safety checks
        if (PageReserved(page)) {
            advmem_debug("Reading from reserved page at PFN: %lx\n", pfn);
        }

        // Calculate chunk size for this page
        chunk_size = min(size - bytes_read, PAGE_SIZE - (current_addr & ~PAGE_MASK));

        // Map the physical address
        mapped_addr = ioremap(current_addr, chunk_size);
        if (!mapped_addr) {
            advmem_err("Failed to map physical address: 0x%lx\n", current_addr);
            return -ENOMEM;
        }

        // Copy data from physical memory
        memcpy_fromio(buf_ptr + bytes_read, mapped_addr, chunk_size);
        iounmap(mapped_addr);

        bytes_read += chunk_size;
        current_addr += chunk_size;
    }

    advmem_info("Successfully read %zu bytes from 0x%lx\n", size, phys_addr);
    return 0;
}

// Enhanced physical memory write with multi-page support and safety checks
static int write_physical_memory(unsigned long phys_addr, const void* buffer, size_t size) {
    void __iomem *mapped_addr;
    struct page *page;
    unsigned long pfn, start_pfn, end_pfn;
    size_t bytes_written = 0;
    size_t chunk_size;
    unsigned long current_addr = phys_addr;
    const char *buf_ptr = (const char *)buffer;

    if (!buffer || size == 0) {
        advmem_err("Invalid parameters for write: buffer=%p, size=%zu\n", buffer, size);
        return -EINVAL;
    }

    // Safety checks - stricter for write operations
    if (!is_safe_operation_size(size)) {
        return -EINVAL;
    }
    
    if (!is_safe_physical_address(phys_addr, size)) {
        return -EPERM;
    }

    // Additional safety for write operations
    if (SAFETY_CHECK_LEVEL(2)) {
        // Double-check critical memory protection for writes
        if (phys_addr < CRITICAL_MEM_END * 2) {
            advmem_err("SAFETY: Write to critical region blocked at 0x%lx\n", phys_addr);
            return -EPERM;
        }
    }

    // Apply size limits only if safety is enabled
    if (!SAFETY_DISABLED() && size > get_safe_max_size()) {
        advmem_err("Write size %zu exceeds safety limit %zu\n", size, get_safe_max_size());
        return -EINVAL;
    }

    start_pfn = phys_addr >> PAGE_SHIFT;
    end_pfn = (phys_addr + size - 1) >> PAGE_SHIFT;

    advmem_debug("Writing %zu bytes to 0x%lx (spans %lu pages)\n", 
                 size, phys_addr, end_pfn - start_pfn + 1);

    // Process each page that the write spans
    while (bytes_written < size) {
        pfn = current_addr >> PAGE_SHIFT;

        // Check if physical address is valid
        if (!pfn_valid(pfn)) {
            advmem_err("Invalid physical address: 0x%lx (PFN: %lx)\n", current_addr, pfn);
            return -EINVAL;
        }

        // Get the page structure
        page = pfn_to_page(pfn);
        if (!page) {
            advmem_err("Cannot get page for PFN: %lx\n", pfn);
            return -EINVAL;
        }

        // Enhanced safety checks - only apply if safety is enabled
        if (!SAFETY_DISABLED()) {
            if (PageReserved(page)) {
                advmem_err("Attempting to write to reserved page at PFN: %lx - DENIED\n", pfn);
                return -EPERM;
            }

            if (PageLocked(page)) {
                advmem_err("Attempting to write to locked page at PFN: %lx - DENIED\n", pfn);
                return -EBUSY;
            }

            // Level 3: Additional page safety checks
            if (SAFETY_CHECK_LEVEL(3)) {
                if (PageSlab(page) || PageCompound(page) || PageAnon(page)) {
                    advmem_err("SAFETY: Unsafe page type at PFN: %lx\n", pfn);
                    return -EPERM;
                }
            }
        }

        // Calculate chunk size for this page
        chunk_size = min(size - bytes_written, PAGE_SIZE - (current_addr & ~PAGE_MASK));

        // Map the physical address with write permissions
        mapped_addr = ioremap(current_addr, chunk_size);
        if (!mapped_addr) {
            advmem_err("Failed to map physical address: 0x%lx\n", current_addr);
            return -ENOMEM;
        }

        // Copy data to physical memory
        memcpy_toio(mapped_addr, buf_ptr + bytes_written, chunk_size);

        // Ensure data is written
        wmb();
        iounmap(mapped_addr);

        bytes_written += chunk_size;
        current_addr += chunk_size;
    }

    advmem_info("Successfully wrote %zu bytes to 0x%lx\n", size, phys_addr);
    return 0;
}

// Enhanced virtual to physical address translation
static unsigned long virtual_to_physical_addr(unsigned long virt_addr, pid_t pid) {
    struct task_struct *task;
    struct mm_struct *mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long phys_addr = 0;

    // Safety validation
    if (!is_safe_virtual_address(virt_addr, pid)) {
        return 0;
    }

    if (pid == 0) {
        // Kernel address - use direct translation if possible
        if (virt_addr >= PAGE_OFFSET) {
            phys_addr = virt_to_phys((void*)virt_addr);
            return phys_addr;
        }
        mm = current->mm;
    } else {
        // User process address
        task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (!task) {
            advmem_err("Process %d not found\n", pid);
            return 0;
        }
        mm = task->mm;
    }

    if (!mm) {
        advmem_err("No memory management struct\n");
        return 0;
    }

    advmem_mmap_read_lock(mm);

    // Walk the page table
    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        goto out;
    }

    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        goto out;
    }

    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        goto out;
    }

    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        goto out;
    }

    pte = advmem_pte_offset_map(pmd, virt_addr);
    if (!pte || pte_none(*pte)) {
#ifdef HAVE_PTE_OFFSET_MAP_LOCK
        if (pte) pte_unmap(pte);
#endif
        goto out;
    }

    if (pte_present(*pte)) {
        phys_addr = (pte_pfn(*pte) << PAGE_SHIFT) + (virt_addr & ~PAGE_MASK);
        
        // Additional safety check for translated address
        if (!SAFETY_DISABLED() && !is_safe_physical_address(phys_addr, PAGE_SIZE)) {
            advmem_err("SAFETY: Translated address 0x%lx failed safety check\n", phys_addr);
            phys_addr = 0;
        }
    }

#ifdef HAVE_PTE_OFFSET_MAP_LOCK
    pte_unmap(pte);
#endif

out:
    advmem_mmap_read_unlock(mm);
    return phys_addr;
}

// Physical to virtual address translation (limited functionality)
static unsigned long physical_to_virtual_addr(unsigned long phys_addr, pid_t pid) {
    unsigned long virt_addr = 0;

    // For kernel addresses, try direct mapping
    if (pfn_valid(phys_addr >> PAGE_SHIFT)) {
        // Check if it's in the direct mapping range
        virt_addr = (unsigned long)phys_to_virt(phys_addr);

        // Verify the translation works both ways
        if (virt_to_phys((void*)virt_addr) == phys_addr) {
            return virt_addr;
        }
    }

    // For user space, we would need to scan all VMAs which is expensive
    // This is a fundamental limitation - physical to virtual mapping
    // is not unique and context-dependent
    printk(KERN_WARNING "Advanced Memory: Physical to virtual translation limited\n");
    return 0;
}

// Enhanced page information retrieval
static int get_page_information(unsigned long addr, struct page_info *info) {
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    memset(info, 0, sizeof(*info));
    info->addr = addr;

    if (!mm) {
        // Kernel address
        if (addr >= PAGE_OFFSET) {
            info->page_frame = virt_to_phys((void*)addr) >> PAGE_SHIFT;
            info->present = 1;
            info->writable = 1;
            info->user = 0;
            return 0;
        }
        return -EINVAL;
    }

    // Safety check for address
    if (!is_safe_virtual_address(addr, 0)) {
        return -EPERM;
    }

    advmem_mmap_read_lock(mm);

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        goto out;
    }

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        goto out;
    }

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        goto out;
    }

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        goto out;
    }

    pte = advmem_pte_offset_map(pmd, addr);
    if (!pte || pte_none(*pte)) {
#ifdef HAVE_PTE_OFFSET_MAP_LOCK
        if (pte) pte_unmap(pte);
#endif
        goto out;
    }

    info->present = pte_present(*pte);
    info->writable = pte_write(*pte);
    info->user = pte_user(*pte);
    info->accessed = pte_young(*pte);
    info->dirty = pte_dirty(*pte);
    info->page_frame = pte_pfn(*pte);
    info->flags = pte_val(*pte);

#ifdef HAVE_PTE_OFFSET_MAP_LOCK
    pte_unmap(pte);
#endif

out:
    advmem_mmap_read_unlock(mm);
    return 0;
}

// Enhanced AES encryption with proper padding and IV management
static int encrypt_memory_region(struct mem_encryption *enc) {
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg_in, sg_out;
    char *plaintext, *ciphertext;
    size_t padded_size;
    unsigned int block_size;
    int ret = 0;

    // Safety and size validation
    if (enc->size == 0) {
        advmem_err("Invalid encryption size: %lu\n", enc->size);
        return -EINVAL;
    }

    if (!is_safe_operation_size(enc->size)) {
        return -EINVAL;
    }

    if (!is_safe_physical_address(enc->addr, enc->size)) {
        return -EPERM;
    }

    // Apply safety limits
    if (!SAFETY_DISABLED()) {
        size_t max_size = get_safe_max_size();
        if (enc->size > max_size) {
            advmem_err("Encryption size %lu exceeds safety limit %zu\n", enc->size, max_size);
            return -EINVAL;
        }

        // Level 3: Restrict encryption algorithms
        if (SAFETY_CHECK_LEVEL(3) && enc->algorithm != 0) {
            advmem_err("SAFETY: Only AES allowed in level 3 mode\n");
            return -EINVAL;
        }
    } else if (enc->size > BUFFER_SIZE) {
        advmem_err("Encryption size %lu exceeds buffer limit %d\n", enc->size, BUFFER_SIZE);
        return -EINVAL;
    }

    advmem_debug("Encrypting %lu bytes at 0x%lx with algorithm %d\n", 
                 enc->size, enc->addr, enc->algorithm);

    // Setup crypto algorithm
    if (enc->algorithm == 0) {
        tfm = crypto_alloc_skcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
    } else if (enc->algorithm == 1) {
        tfm = crypto_alloc_skcipher("chacha20", 0, CRYPTO_ALG_ASYNC);
    } else {
        advmem_err("Unsupported encryption algorithm: %d\n", enc->algorithm);
        return -EINVAL;
    }

    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        advmem_err("Failed to allocate cipher: %d\n", ret);
        return ret;
    }

    block_size = crypto_skcipher_blocksize(tfm);
    padded_size = ALIGN(enc->size, block_size);

    advmem_debug("Block size: %u, padded size: %zu\n", block_size, padded_size);

    // Allocate padded buffers
    plaintext = kzalloc(padded_size, GFP_KERNEL);
    ciphertext = kzalloc(padded_size, GFP_KERNEL);
    if (!plaintext || !ciphertext) {
        ret = -ENOMEM;
        goto cleanup_crypto;
    }

    // Read memory to encrypt
    ret = read_physical_memory(enc->addr, plaintext, enc->size);
    if (ret) {
        advmem_err("Failed to read memory for encryption: %d\n", ret);
        goto cleanup;
    }

    // Apply PKCS#7 padding if needed
    if (padded_size > enc->size) {
        unsigned char pad_value = padded_size - enc->size;
        memset(plaintext + enc->size, pad_value, pad_value);
        advmem_debug("Applied PKCS#7 padding: %u bytes\n", pad_value);
    }

    ret = crypto_skcipher_setkey(tfm, enc->key, 32);
    if (ret) {
        advmem_err("Failed to set encryption key: %d\n", ret);
        goto cleanup;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        advmem_err("Failed to allocate cipher request\n");
        goto cleanup;
    }

    // Generate random IV if not provided (for CBC mode)
    if (enc->algorithm == 0) {
        get_random_bytes(enc->iv, 16);
        advmem_debug("Generated random IV for CBC mode\n");
    }

    // Setup scatter gather lists
    sg_init_one(&sg_in, plaintext, padded_size);
    sg_init_one(&sg_out, ciphertext, padded_size);

    skcipher_request_set_tfm(req, tfm);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, NULL, NULL);
    skcipher_request_set_crypt(req, &sg_in, &sg_out, padded_size, enc->iv);

    // Perform encryption
    ret = crypto_skcipher_encrypt(req);
    if (ret == 0) {
        // Copy encrypted data to output buffer
        size_t copy_size = min(padded_size, (size_t)BUFFER_SIZE);
        memcpy(enc->encrypted_data, ciphertext, copy_size);
        
        // Write encrypted data back to memory
        ret = write_physical_memory(enc->addr, ciphertext, enc->size);
        if (ret == 0) {
            advmem_info("Successfully encrypted %lu bytes\n", enc->size);
        }
    } else {
        advmem_err("Encryption failed: %d\n", ret);
    }

    skcipher_request_free(req);

cleanup:
    // Securely clear sensitive data
    if (plaintext) {
        memzero_explicit(plaintext, padded_size);
        kfree(plaintext);
    }
    if (ciphertext) {
        memzero_explicit(ciphertext, padded_size);
        kfree(ciphertext);
    }

cleanup_crypto:
    crypto_free_skcipher(tfm);
    return ret;
}

// Enhanced AES decryption with proper padding validation
static int decrypt_memory_region(struct mem_encryption *enc) {
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct scatterlist sg_in, sg_out;
    char *ciphertext, *plaintext;
    size_t padded_size;
    unsigned int block_size;
    int ret = 0;

    // Safety and size validation
    if (enc->size == 0) {
        advmem_err("Invalid decryption size: %lu\n", enc->size);
        return -EINVAL;
    }

    if (!is_safe_operation_size(enc->size)) {
        return -EINVAL;
    }

    if (!is_safe_physical_address(enc->addr, enc->size)) {
        return -EPERM;
    }

    // Apply safety limits
    if (!SAFETY_DISABLED()) {
        size_t max_size = get_safe_max_size();
        if (enc->size > max_size) {
            advmem_err("Decryption size %lu exceeds safety limit %zu\n", enc->size, max_size);
            return -EINVAL;
        }

        // Level 3: Restrict decryption algorithms
        if (SAFETY_CHECK_LEVEL(3) && enc->algorithm != 0) {
            advmem_err("SAFETY: Only AES allowed in level 3 mode\n");
            return -EINVAL;
        }
    } else if (enc->size > BUFFER_SIZE) {
        advmem_err("Decryption size %lu exceeds buffer limit %d\n", enc->size, BUFFER_SIZE);
        return -EINVAL;
    }

    advmem_debug("Decrypting %lu bytes at 0x%lx with algorithm %d\n", 
                 enc->size, enc->addr, enc->algorithm);

    // Setup crypto algorithm
    if (enc->algorithm == 0) {
        tfm = crypto_alloc_skcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
    } else if (enc->algorithm == 1) {
        tfm = crypto_alloc_skcipher("chacha20", 0, CRYPTO_ALG_ASYNC);
    } else {
        advmem_err("Unsupported decryption algorithm: %d\n", enc->algorithm);
        return -EINVAL;
    }

    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        advmem_err("Failed to allocate cipher: %d\n", ret);
        return ret;
    }

    block_size = crypto_skcipher_blocksize(tfm);
    padded_size = ALIGN(enc->size, block_size);

    advmem_debug("Block size: %u, padded size: %zu\n", block_size, padded_size);

    // Allocate padded buffers
    ciphertext = kzalloc(padded_size, GFP_KERNEL);
    plaintext = kzalloc(padded_size, GFP_KERNEL);
    if (!ciphertext || !plaintext) {
        ret = -ENOMEM;
        goto cleanup_crypto;
    }

    // Read encrypted memory
    ret = read_physical_memory(enc->addr, ciphertext, enc->size);
    if (ret) {
        advmem_err("Failed to read memory for decryption: %d\n", ret);
        goto cleanup;
    }

    ret = crypto_skcipher_setkey(tfm, enc->key, 32);
    if (ret) {
        advmem_err("Failed to set decryption key: %d\n", ret);
        goto cleanup;
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        advmem_err("Failed to allocate cipher request\n");
        goto cleanup;
    }

    // Setup scatter gather lists
    sg_init_one(&sg_in, ciphertext, padded_size);
    sg_init_one(&sg_out, plaintext, padded_size);

    skcipher_request_set_tfm(req, tfm);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, NULL, NULL);
    skcipher_request_set_crypt(req, &sg_in, &sg_out, padded_size, enc->iv);

    // Perform decryption
    ret = crypto_skcipher_decrypt(req);
    if (ret == 0) {
        // Validate PKCS#7 padding for CBC mode
        if (enc->algorithm == 0 && padded_size > enc->size) {
            unsigned char pad_value = plaintext[enc->size];
            if (pad_value > 0 && pad_value <= block_size) {
                int i;
                for (i = enc->size; i < padded_size; i++) {
                    if (plaintext[i] != pad_value) {
                        advmem_err("Invalid PKCS#7 padding detected\n");
                        ret = -EINVAL;
                        goto cleanup_req;
                    }
                }
                advmem_debug("Valid PKCS#7 padding removed: %u bytes\n", pad_value);
            }
        }

        // Copy decrypted data to output buffer
        size_t copy_size = min(enc->size, (size_t)BUFFER_SIZE);
        memcpy(enc->encrypted_data, plaintext, copy_size);
        
        // Write decrypted data back to memory
        ret = write_physical_memory(enc->addr, plaintext, enc->size);
        if (ret == 0) {
            advmem_info("Successfully decrypted %lu bytes\n", enc->size);
        }
    } else {
        advmem_err("Decryption failed: %d\n", ret);
    }

cleanup_req:
    skcipher_request_free(req);

cleanup:
    // Securely clear sensitive data
    if (ciphertext) {
        memzero_explicit(ciphertext, padded_size);
        kfree(ciphertext);
    }
    if (plaintext) {
        memzero_explicit(plaintext, padded_size);
        kfree(plaintext);
    }

cleanup_crypto:
    crypto_free_skcipher(tfm);
    return ret;
}

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct mem_operation mem_op;
    struct addr_translation addr_trans;
    struct page_info page_inf;
    struct mem_encryption mem_enc;
    int ret = 0;

    // Security check: require CAP_SYS_ADMIN capability
    if (!capable(CAP_SYS_ADMIN)) {
        advmem_err("Access denied: CAP_SYS_ADMIN capability required\n");
        return -EPERM;
    }

    // Validate user pointer
    if (!arg) {
        advmem_err("Invalid argument pointer\n");
        return -EINVAL;
    }

    // Acquire mutex for thread safety
    if (mutex_lock_interruptible(&advmem_mutex)) {
        advmem_debug("IOCTL interrupted while waiting for mutex\n");
        return -ERESTARTSYS;
    }

    advmem_debug("IOCTL command: 0x%x\n", cmd);

    switch (cmd) {
        case IOCTL_READ_PHYS_MEM:
            if (copy_from_user(&mem_op, (void*)arg, sizeof(mem_op))) {
                ret = -EFAULT;
                break;
            }

            ret = read_physical_memory(mem_op.phys_addr, mem_op.data, mem_op.size);
            mem_op.result = ret;

            if (copy_to_user((void*)arg, &mem_op, sizeof(mem_op))) {
                ret = -EFAULT;
                break;
            }
            break;

        case IOCTL_WRITE_PHYS_MEM:
            if (copy_from_user(&mem_op, (void*)arg, sizeof(mem_op))) {
                ret = -EFAULT;
                break;
            }

            ret = write_physical_memory(mem_op.phys_addr, mem_op.data, mem_op.size);
            mem_op.result = ret;

            if (copy_to_user((void*)arg, &mem_op, sizeof(mem_op))) {
                ret = -EFAULT;
                break;
            }
            break;

        case IOCTL_VIRT_TO_PHYS:
            if (copy_from_user(&addr_trans, (void*)arg, sizeof(addr_trans))) {
                ret = -EFAULT;
                break;
            }

            addr_trans.output_addr = virtual_to_physical_addr(addr_trans.input_addr, addr_trans.pid);
            addr_trans.success = (addr_trans.output_addr != 0);

            if (copy_to_user((void*)arg, &addr_trans, sizeof(addr_trans))) {
                ret = -EFAULT;
                break;
            }
            ret = 0;
            break;

        case IOCTL_PHYS_TO_VIRT:
            if (copy_from_user(&addr_trans, (void*)arg, sizeof(addr_trans))) {
                ret = -EFAULT;
                break;
            }

            addr_trans.output_addr = physical_to_virtual_addr(addr_trans.input_addr, addr_trans.pid);
            addr_trans.success = (addr_trans.output_addr != 0);

            if (copy_to_user((void*)arg, &addr_trans, sizeof(addr_trans))) {
                ret = -EFAULT;
                break;
            }
            ret = 0;
            break;

        case IOCTL_GET_PAGE_INFO:
            if (copy_from_user(&page_inf, (void*)arg, sizeof(page_inf))) {
                ret = -EFAULT;
                break;
            }

            ret = get_page_information(page_inf.addr, &page_inf);

            if (copy_to_user((void*)arg, &page_inf, sizeof(page_inf))) {
                ret = -EFAULT;
                break;
            }
            break;

        case IOCTL_ENCRYPT_MEMORY:
            if (copy_from_user(&mem_enc, (void*)arg, sizeof(mem_enc))) {
                ret = -EFAULT;
                break;
            }

            ret = encrypt_memory_region(&mem_enc);
            mem_enc.result = ret;

            if (copy_to_user((void*)arg, &mem_enc, sizeof(mem_enc))) {
                ret = -EFAULT;
                break;
            }
            break;

        case IOCTL_DECRYPT_MEMORY:
            if (copy_from_user(&mem_enc, (void*)arg, sizeof(mem_enc))) {
                ret = -EFAULT;
                break;
            }

            ret = decrypt_memory_region(&mem_enc);
            mem_enc.result = ret;

            if (copy_to_user((void*)arg, &mem_enc, sizeof(mem_enc))) {
                ret = -EFAULT;
                break;
            }
            break;

        default:
            advmem_err("Unknown IOCTL command: 0x%x\n", cmd);
            ret = -EINVAL;
            break;
    }

    mutex_unlock(&advmem_mutex);
    return ret;
}

static int device_open(struct inode *inodep, struct file *filep) {
    advmem_info("Device opened by PID %d (UID: %u)\n", 
                current->pid, from_kuid_munged(current_user_ns(), current_uid()));
    return 0;
}

static int device_release(struct inode *inodep, struct file *filep) {
    advmem_info("Device closed by PID %d\n", current->pid);
    return 0;
}

static int __init advmem_init(void) {
    advmem_info("Initializing Advanced Memory Toolkit kernel module\n");
    advmem_info("Kernel version: %s (compiled for %d.%d.%d)\n", 
                utsname()->release, 
                LINUX_VERSION_CODE >> 16,
                (LINUX_VERSION_CODE >> 8) & 0xff,
                LINUX_VERSION_CODE & 0xff);
    advmem_info("Debug level: %d (0=errors, 1=info, 2=debug)\n", debug_level);
    advmem_info("Safe mode: %d (0=disabled, 1=basic, 2=standard, 3=maximum)\n", safe_mode);
    
    if (SAFETY_DISABLED()) {
        advmem_info("⚠️  WARNING: Safety mode DISABLED - No protection active!\n");
    } else {
        advmem_info("🛡️  Safety mode active - Max operation size: %zu bytes\n", get_safe_max_size());
    }

    // Initialize mutex
    mutex_init(&advmem_mutex);

    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        advmem_err("Failed to register character device: %d\n", major_number);
        return major_number;
    }

    advmem_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(advmem_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        advmem_err("Failed to create device class: %ld\n", PTR_ERR(advmem_class));
        return PTR_ERR(advmem_class);
    }

    advmem_device = device_create(advmem_class, NULL, 
                                MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(advmem_device)) {
        class_destroy(advmem_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        advmem_err("Failed to create device: %ld\n", PTR_ERR(advmem_device));
        return PTR_ERR(advmem_device);
    }

    advmem_info("Module loaded successfully (major number: %d)\n", major_number);
    advmem_info("Device: /dev/%s\n", DEVICE_NAME);
    advmem_info("Security: CAP_SYS_ADMIN capability required\n");
    return 0;
}

static void __exit advmem_exit(void) {
    // Cleanup in reverse order
    if (advmem_device) {
        device_destroy(advmem_class, MKDEV(major_number, 0));
    }
    
    if (advmem_class) {
        class_unregister(advmem_class);
        class_destroy(advmem_class);
    }
    
    if (major_number > 0) {
        unregister_chrdev(major_number, DEVICE_NAME);
    }

    // Ensure no pending operations
    mutex_destroy(&advmem_mutex);

    advmem_info("Advanced Memory Toolkit module unloaded safely\n");
}

module_init(advmem_init);
module_exit(advmem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Memory Development Team");
MODULE_DESCRIPTION("Advanced Memory Toolkit - Professional Memory Operations");
MODULE_VERSION("3.0");
