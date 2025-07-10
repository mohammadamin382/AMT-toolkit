
/*
 * Advanced Memory Toolkit (AMT) - Professional Kernel Module
 * Safe Memory Operations Framework for Linux Kernel
 * 
 * Features:
 * - Physical/Virtual memory read/write operations
 * - Address translation (virtual ↔ physical)
 * - Advanced page information retrieval
 * - Memory monitoring and debugging capabilities
 * - Comprehensive kernel version compatibility
 * - Multi-level safety mechanisms
 * 
 * Author: Mohammad Amin
 * License: GPL v2
 * Version: 4.0 Professional
 */

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
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/atomic.h>
#include <linux/spinlock.h>
#include <linux/ratelimit.h>
#include <linux/jiffies.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/io.h>
#include <asm/tlbflush.h>

/* Kernel version compatibility headers */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/sched/signal.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/mmap_lock.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
#include <linux/fortify-string.h>
#endif

/* Version-specific compatibility macros */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define HAVE_CLASS_CREATE_NO_MODULE
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#define HAVE_NEW_VM_FLAGS
#define HAVE_NO_SET_MEMORY_X
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
#define HAVE_PTE_OFFSET_MAP_NOLOCK
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define HAVE_MMAP_LOCK_API
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#define HAVE_PROC_OPS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#define HAVE_ACCESS_OK_2_ARGS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
#define HAVE_TOTALRAM_PAGES_FUNC
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define HAVE_GET_USER_PAGES_REMOTE
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 6, 0)
#define HAVE_OLD_MM_CONTEXT
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#error "Kernel version too old! Minimum supported version is 4.0"
#endif

/* Memory layout compatibility */
#ifndef PAGE_OFFSET
#ifdef CONFIG_X86_64
#define PAGE_OFFSET 0xffff888000000000UL
#else
#define PAGE_OFFSET 0xc0000000UL
#endif
#endif

#ifndef VMALLOC_START
#ifdef CONFIG_X86_64
#define VMALLOC_START 0xffffc90000000000UL
#else
#define VMALLOC_START 0xe0000000UL
#endif
#endif

/* Device configuration */
#define DEVICE_NAME "amt_memory"
#define CLASS_NAME "amt_class"
#define PROC_NAME "amt_info"
#define MAX_BUFFER_SIZE (64 * 1024)  /* 64KB max buffer */
#define DEFAULT_BUFFER_SIZE (8 * 1024)  /* 8KB default */

/* IOCTL command definitions */
#define AMT_MAGIC 'A'
#define AMT_READ_PHYS           _IOWR(AMT_MAGIC, 1, struct amt_mem_operation)
#define AMT_WRITE_PHYS          _IOW(AMT_MAGIC, 2, struct amt_mem_operation)
#define AMT_VIRT_TO_PHYS        _IOWR(AMT_MAGIC, 3, struct amt_addr_translation)
#define AMT_PHYS_TO_VIRT        _IOWR(AMT_MAGIC, 4, struct amt_addr_translation)
#define AMT_GET_PAGE_INFO       _IOWR(AMT_MAGIC, 5, struct amt_page_info)
#define AMT_GET_MEMORY_STATS    _IOR(AMT_MAGIC, 6, struct amt_memory_stats)
#define AMT_SET_DEBUG_LEVEL     _IOW(AMT_MAGIC, 7, int)
#define AMT_GET_SYSTEM_INFO     _IOR(AMT_MAGIC, 8, struct amt_system_info)
#define AMT_MEMORY_SEARCH       _IOWR(AMT_MAGIC, 9, struct amt_memory_search)
#define AMT_GET_PROCESS_MAPS    _IOWR(AMT_MAGIC, 10, struct amt_process_maps)

/* Data structures */
struct amt_mem_operation {
    __u64 phys_addr;
    __u32 size;
    __u32 flags;
    __u64 timestamp;
    __s32 result;
    __u8 data[0];  /* Variable length data */
} __packed;

struct amt_addr_translation {
    __u64 input_addr;
    __u64 output_addr;
    __s32 pid;
    __u32 flags;
    __s32 success;
    __u64 page_table_entries[5];  /* PGD, P4D, PUD, PMD, PTE */
    __u32 protection_flags;
    __u32 cache_type;
} __packed;

struct amt_page_info {
    __u64 addr;
    __u64 page_frame_number;
    __u32 flags;
    __u32 ref_count;
    __u32 map_count;
    __u8 present:1;
    __u8 writable:1;
    __u8 user_accessible:1;
    __u8 accessed:1;
    __u8 dirty:1;
    __u8 global_page:1;
    __u8 nx_bit:1;
    __u8 reserved:1;
    __u32 cache_type;
    __u64 physical_addr;
} __packed;

struct amt_memory_stats {
    __u64 total_ram;
    __u64 free_ram;
    __u64 available_ram;
    __u64 cached;
    __u64 buffers;
    __u64 slab;
    __u32 operations_count;
    __u32 error_count;
    __u64 bytes_read;
    __u64 bytes_written;
} __packed;

struct amt_system_info {
    __u32 kernel_version;
    __u32 page_size;
    __u64 page_offset;
    __u64 vmalloc_start;
    __u64 vmalloc_end;
    __u32 cpu_count;
    __u32 node_count;
    char arch[16];
    char version_string[64];
} __packed;

struct amt_memory_search {
    __u64 start_addr;
    __u64 end_addr;
    __u8 pattern[32];
    __u32 pattern_size;
    __u32 max_results;
    __u32 found_count;
    __u64 results[64];  /* Found addresses */
} __packed;

struct amt_process_maps {
    __s32 pid;
    __u32 map_count;
    struct {
        __u64 start;
        __u64 end;
        __u32 flags;
        char name[64];
    } maps[32];
} __packed;

/* Global variables */
static int major_number;
static struct class *amt_class = NULL;
static struct device *amt_device = NULL;
static struct proc_dir_entry *amt_proc_entry = NULL;

/* Synchronization */
static DEFINE_MUTEX(amt_mutex);
static DEFINE_SPINLOCK(amt_stats_lock);

/* Statistics and monitoring */
static atomic_t operation_count = ATOMIC_INIT(0);
static atomic_t error_count = ATOMIC_INIT(0);
static atomic64_t bytes_read = ATOMIC64_INIT(0);
static atomic64_t bytes_written = ATOMIC64_INIT(0);

/* Configuration parameters */
static int debug_level = 1;
module_param(debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Debug level (0=errors only, 1=info, 2=debug, 3=verbose)");

static int safety_level = 2;
module_param(safety_level, int, 0644);
MODULE_PARM_DESC(safety_level, "Safety level (0=disabled, 1=basic, 2=standard, 3=paranoid)");

static int max_buffer_size = DEFAULT_BUFFER_SIZE;
module_param(max_buffer_size, int, 0644);
MODULE_PARM_DESC(max_buffer_size, "Maximum buffer size for operations");

static bool enable_monitoring = true;
module_param(enable_monitoring, bool, 0644);
MODULE_PARM_DESC(enable_monitoring, "Enable operation monitoring and statistics");

/* Rate limiting for error messages */
static DEFINE_RATELIMIT_STATE(amt_ratelimit, HZ, 10);

/* Debug and logging macros */
#define amt_err(fmt, ...) \
    do { \
        if (__ratelimit(&amt_ratelimit)) \
            printk(KERN_ERR "AMT_ERROR: " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define amt_warn(fmt, ...) \
    do { \
        if (debug_level >= 1) \
            printk(KERN_WARNING "AMT_WARN: " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define amt_info(fmt, ...) \
    do { \
        if (debug_level >= 1) \
            printk(KERN_INFO "AMT_INFO: " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define amt_debug(fmt, ...) \
    do { \
        if (debug_level >= 2) \
            printk(KERN_DEBUG "AMT_DEBUG: " fmt "\n", ##__VA_ARGS__); \
    } while (0)

#define amt_verbose(fmt, ...) \
    do { \
        if (debug_level >= 3) \
            printk(KERN_DEBUG "AMT_VERBOSE: " fmt "\n", ##__VA_ARGS__); \
    } while (0)

/* Compatibility wrapper functions */
static inline void amt_mmap_read_lock(struct mm_struct *mm)
{
#ifdef HAVE_MMAP_LOCK_API
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
}

static inline void amt_mmap_read_unlock(struct mm_struct *mm)
{
#ifdef HAVE_MMAP_LOCK_API
    mmap_read_unlock(mm);
#else
    up_read(&mm->mmap_sem);
#endif
}

static inline unsigned long amt_totalram_pages(void)
{
#ifdef HAVE_TOTALRAM_PAGES_FUNC
    return totalram_pages();
#else
    return totalram_pages;
#endif
}

static inline int amt_access_ok(const void __user *addr, unsigned long size)
{
#ifdef HAVE_ACCESS_OK_2_ARGS
    return access_ok(addr, size);
#else
    return access_ok(VERIFY_READ, addr, size);
#endif
}

static inline pte_t *amt_pte_offset_map(pmd_t *pmd, unsigned long addr)
{
#ifdef HAVE_PTE_OFFSET_MAP_NOLOCK
    return pte_offset_map_nolock(NULL, pmd, addr, NULL);
#else
    return pte_offset_map(pmd, addr);
#endif
}

static inline void amt_pte_unmap(pte_t *pte)
{
#ifndef HAVE_PTE_OFFSET_MAP_NOLOCK
    pte_unmap(pte);
#endif
}

/* Safety validation functions */
static bool amt_is_safe_physical_address(unsigned long phys_addr, size_t size)
{
    unsigned long pfn;
    
    if (safety_level == 0)
        return true;

    /* Basic checks */
    if (phys_addr == 0 || size == 0 || size > max_buffer_size) {
        amt_debug("Invalid address or size: addr=0x%lx, size=%zu", phys_addr, size);
        return false;
    }

    /* Check for overflow */
    if (phys_addr + size < phys_addr) {
        amt_debug("Address overflow detected: addr=0x%lx, size=%zu", phys_addr, size);
        return false;
    }

    /* Check if PFN is valid */
    pfn = phys_addr >> PAGE_SHIFT;
    if (!pfn_valid(pfn)) {
        amt_debug("Invalid PFN: 0x%lx", pfn);
        return false;
    }

    /* Level 1+: Protect critical memory regions */
    if (safety_level >= 1) {
        /* Protect first 1MB */
        if (phys_addr < 0x100000) {
            amt_debug("Access to critical memory region denied: 0x%lx", phys_addr);
            return false;
        }
    }

    /* Level 2+: Additional checks */
    if (safety_level >= 2) {
        struct page *page = pfn_to_page(pfn);
        
        if (!page) {
            amt_debug("Cannot get page structure for PFN: 0x%lx", pfn);
            return false;
        }

        /* Check page flags */
        if (PageReserved(page) || PageSlab(page)) {
            amt_debug("Page has restricted flags: PFN=0x%lx", pfn);
            return false;
        }
    }

    /* Level 3: Paranoid mode */
    if (safety_level >= 3) {
        /* Only allow specific memory ranges */
        if (phys_addr >= 0xf0000000UL) {
            amt_debug("High memory access denied in paranoid mode: 0x%lx", phys_addr);
            return false;
        }
    }

    return true;
}

static bool amt_is_safe_virtual_address(unsigned long virt_addr, pid_t pid)
{
    if (safety_level == 0)
        return true;

    if (virt_addr == 0) {
        amt_debug("NULL virtual address");
        return false;
    }

    /* Kernel address checks */
    if (pid == 0) {
        if (virt_addr < PAGE_OFFSET) {
            amt_debug("Invalid kernel address: 0x%lx", virt_addr);
            return false;
        }
    } else {
        /* User address checks */
        if (virt_addr >= TASK_SIZE) {
            amt_debug("Invalid user address: 0x%lx", virt_addr);
            return false;
        }
    }

    return true;
}

/* Core memory operation functions */
static int amt_read_physical_memory(unsigned long phys_addr, void *buffer, size_t size)
{
    void __iomem *mapped_addr;
    struct page *page;
    unsigned long pfn;
    size_t bytes_read = 0;
    size_t chunk_size;
    unsigned long current_addr = phys_addr;
    char *buf_ptr = (char *)buffer;

    if (!buffer || size == 0) {
        amt_err("Invalid parameters: buffer=%p, size=%zu", buffer, size);
        return -EINVAL;
    }

    if (!amt_is_safe_physical_address(phys_addr, size)) {
        amt_err("Unsafe physical address: 0x%lx", phys_addr);
        atomic_inc(&error_count);
        return -EPERM;
    }

    amt_verbose("Reading %zu bytes from physical address 0x%lx", size, phys_addr);

    while (bytes_read < size) {
        pfn = current_addr >> PAGE_SHIFT;
        
        if (!pfn_valid(pfn)) {
            amt_err("Invalid PFN during read: 0x%lx", pfn);
            atomic_inc(&error_count);
            return -EINVAL;
        }

        page = pfn_to_page(pfn);
        if (!page) {
            amt_err("Cannot get page for PFN: 0x%lx", pfn);
            atomic_inc(&error_count);
            return -EINVAL;
        }

        chunk_size = min(size - bytes_read, PAGE_SIZE - (current_addr & ~PAGE_MASK));

        mapped_addr = ioremap(current_addr, chunk_size);
        if (!mapped_addr) {
            amt_err("Failed to map physical address: 0x%lx", current_addr);
            atomic_inc(&error_count);
            return -ENOMEM;
        }

        memcpy_fromio(buf_ptr + bytes_read, mapped_addr, chunk_size);
        iounmap(mapped_addr);

        bytes_read += chunk_size;
        current_addr += chunk_size;
    }

    atomic_inc(&operation_count);
    atomic64_add(size, &bytes_read);
    amt_debug("Successfully read %zu bytes from 0x%lx", size, phys_addr);
    
    return 0;
}

static int amt_write_physical_memory(unsigned long phys_addr, const void *buffer, size_t size)
{
    void __iomem *mapped_addr;
    struct page *page;
    unsigned long pfn;
    size_t bytes_written = 0;
    size_t chunk_size;
    unsigned long current_addr = phys_addr;
    const char *buf_ptr = (const char *)buffer;

    if (!buffer || size == 0) {
        amt_err("Invalid parameters: buffer=%p, size=%zu", buffer, size);
        return -EINVAL;
    }

    if (!amt_is_safe_physical_address(phys_addr, size)) {
        amt_err("Unsafe physical address for write: 0x%lx", phys_addr);
        atomic_inc(&error_count);
        return -EPERM;
    }

    amt_verbose("Writing %zu bytes to physical address 0x%lx", size, phys_addr);

    while (bytes_written < size) {
        pfn = current_addr >> PAGE_SHIFT;
        
        if (!pfn_valid(pfn)) {
            amt_err("Invalid PFN during write: 0x%lx", pfn);
            atomic_inc(&error_count);
            return -EINVAL;
        }

        page = pfn_to_page(pfn);
        if (!page) {
            amt_err("Cannot get page for PFN: 0x%lx", pfn);
            atomic_inc(&error_count);
            return -EINVAL;
        }

        /* Additional safety checks for write operations */
        if (safety_level >= 2) {
            if (PageReserved(page) || PageSlab(page) || PageLocked(page)) {
                amt_err("Page not safe for writing: PFN=0x%lx", pfn);
                atomic_inc(&error_count);
                return -EPERM;
            }
        }

        chunk_size = min(size - bytes_written, PAGE_SIZE - (current_addr & ~PAGE_MASK));

        mapped_addr = ioremap(current_addr, chunk_size);
        if (!mapped_addr) {
            amt_err("Failed to map physical address for write: 0x%lx", current_addr);
            atomic_inc(&error_count);
            return -ENOMEM;
        }

        memcpy_toio(mapped_addr, buf_ptr + bytes_written, chunk_size);
        wmb(); /* Write memory barrier */
        iounmap(mapped_addr);

        bytes_written += chunk_size;
        current_addr += chunk_size;
    }

    atomic_inc(&operation_count);
    atomic64_add(size, &bytes_written);
    amt_debug("Successfully wrote %zu bytes to 0x%lx", size, phys_addr);
    
    return 0;
}

static unsigned long amt_virtual_to_physical(unsigned long virt_addr, pid_t pid)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long phys_addr = 0;
    bool mm_locked = false;

    if (!amt_is_safe_virtual_address(virt_addr, pid)) {
        amt_err("Unsafe virtual address: 0x%lx", virt_addr);
        return 0;
    }

    amt_verbose("Translating virtual address 0x%lx (PID: %d)", virt_addr, pid);

    if (pid == 0) {
        /* Kernel address translation */
        if (virt_addr >= PAGE_OFFSET) {
            phys_addr = virt_to_phys((void *)virt_addr);
            amt_debug("Kernel direct mapping: 0x%lx -> 0x%lx", virt_addr, phys_addr);
            return phys_addr;
        }
        mm = current->mm;
    } else {
        /* User process address translation */
        rcu_read_lock();
        task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (!task || (task->flags & PF_EXITING)) {
            rcu_read_unlock();
            amt_err("Invalid or exiting process: PID %d", pid);
            return 0;
        }
        mm = get_task_mm(task);
        rcu_read_unlock();
        
        if (!mm) {
            amt_err("No memory management structure for PID: %d", pid);
            return 0;
        }
    }

    if (!mm) {
        amt_err("No memory management structure available");
        return 0;
    }

    amt_mmap_read_lock(mm);
    mm_locked = true;

    /* Walk the page table hierarchy */
    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        amt_debug("Invalid PGD entry for address: 0x%lx", virt_addr);
        goto out;
    }

    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        amt_debug("Invalid P4D entry for address: 0x%lx", virt_addr);
        goto out;
    }

    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        amt_debug("Invalid PUD entry for address: 0x%lx", virt_addr);
        goto out;
    }

    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        amt_debug("Invalid PMD entry for address: 0x%lx", virt_addr);
        goto out;
    }

    pte = amt_pte_offset_map(pmd, virt_addr);
    if (!pte || pte_none(*pte)) {
        amt_debug("Invalid PTE entry for address: 0x%lx", virt_addr);
        if (pte)
            amt_pte_unmap(pte);
        goto out;
    }

    if (pte_present(*pte)) {
        phys_addr = (pte_pfn(*pte) << PAGE_SHIFT) + (virt_addr & ~PAGE_MASK);
        amt_debug("Translation successful: 0x%lx -> 0x%lx", virt_addr, phys_addr);
    } else {
        amt_debug("Page not present for address: 0x%lx", virt_addr);
    }

    amt_pte_unmap(pte);

out:
    if (mm_locked)
        amt_mmap_read_unlock(mm);
    
    if (pid != 0 && mm)
        mmput(mm);

    if (phys_addr)
        atomic_inc(&operation_count);
    else
        atomic_inc(&error_count);

    return phys_addr;
}

static int amt_get_page_information(unsigned long addr, struct amt_page_info *info)
{
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct page *page = NULL;
    unsigned long pfn;
    bool mm_locked = false;

    if (!info) {
        amt_err("NULL page info structure");
        return -EINVAL;
    }

    memset(info, 0, sizeof(*info));
    info->addr = addr;

    amt_verbose("Getting page information for address: 0x%lx", addr);

    /* Handle kernel addresses */
    if (addr >= PAGE_OFFSET) {
        unsigned long phys_addr = virt_to_phys((void *)addr);
        pfn = phys_addr >> PAGE_SHIFT;
        
        if (pfn_valid(pfn)) {
            page = pfn_to_page(pfn);
            info->page_frame_number = pfn;
            info->physical_addr = phys_addr;
            info->present = 1;
            info->writable = 1;
            info->user_accessible = 0;
            
            if (page) {
                info->ref_count = page_ref_count(page);
                info->map_count = page_mapcount(page);
                info->flags = page->flags;
            }
            
            amt_debug("Kernel page info retrieved for: 0x%lx", addr);
            atomic_inc(&operation_count);
            return 0;
        }
    }

    /* Handle user addresses */
    if (!mm) {
        amt_err("No memory management structure for user address");
        return -EINVAL;
    }

    amt_mmap_read_lock(mm);
    mm_locked = true;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto out;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto out;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto out;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto out;

    pte = amt_pte_offset_map(pmd, addr);
    if (!pte || pte_none(*pte)) {
        if (pte)
            amt_pte_unmap(pte);
        goto out;
    }

    /* Extract page information */
    info->present = pte_present(*pte);
    info->writable = pte_write(*pte);
    info->user_accessible = pte_user(*pte);
    info->accessed = pte_young(*pte);
    info->dirty = pte_dirty(*pte);
    info->global_page = pte_global(*pte);
    info->nx_bit = pte_nx(*pte);
    info->flags = pte_val(*pte);

    if (info->present) {
        pfn = pte_pfn(*pte);
        info->page_frame_number = pfn;
        info->physical_addr = (pfn << PAGE_SHIFT) + (addr & ~PAGE_MASK);
        
        if (pfn_valid(pfn)) {
            page = pfn_to_page(pfn);
            if (page) {
                info->ref_count = page_ref_count(page);
                info->map_count = page_mapcount(page);
            }
        }
    }

    amt_pte_unmap(pte);

out:
    if (mm_locked)
        amt_mmap_read_unlock(mm);

    amt_debug("Page info retrieved for address: 0x%lx (present: %d)", 
              addr, info->present);
    atomic_inc(&operation_count);
    return 0;
}

static int amt_get_memory_statistics(struct amt_memory_stats *stats)
{
    struct sysinfo si;
    
    if (!stats) {
        amt_err("NULL statistics structure");
        return -EINVAL;
    }

    si_meminfo(&si);

    stats->total_ram = si.totalram * PAGE_SIZE;
    stats->free_ram = si.freeram * PAGE_SIZE;
    stats->available_ram = si.freeram * PAGE_SIZE; /* Simplified */
    stats->cached = global_node_page_state(NR_FILE_PAGES) * PAGE_SIZE;
    stats->buffers = si.bufferram * PAGE_SIZE;
    stats->slab = global_node_page_state(NR_SLAB_RECLAIMABLE) * PAGE_SIZE +
                  global_node_page_state(NR_SLAB_UNRECLAIMABLE) * PAGE_SIZE;

    /* Our driver statistics */
    stats->operations_count = atomic_read(&operation_count);
    stats->error_count = atomic_read(&error_count);
    stats->bytes_read = atomic64_read(&bytes_read);
    stats->bytes_written = atomic64_read(&bytes_written);

    amt_debug("Memory statistics retrieved");
    return 0;
}

static int amt_get_system_information(struct amt_system_info *info)
{
    if (!info) {
        amt_err("NULL system info structure");
        return -EINVAL;
    }

    memset(info, 0, sizeof(*info));

    info->kernel_version = LINUX_VERSION_CODE;
    info->page_size = PAGE_SIZE;
    info->page_offset = PAGE_OFFSET;
    info->vmalloc_start = VMALLOC_START;
#ifdef VMALLOC_END
    info->vmalloc_end = VMALLOC_END;
#endif
    info->cpu_count = num_online_cpus();
    info->node_count = num_online_nodes();

    strncpy(info->arch, UTS_MACHINE, sizeof(info->arch) - 1);
    snprintf(info->version_string, sizeof(info->version_string), 
             "%d.%d.%d", 
             (LINUX_VERSION_CODE >> 16) & 0xff,
             (LINUX_VERSION_CODE >> 8) & 0xff,
             LINUX_VERSION_CODE & 0xff);

    amt_debug("System information retrieved");
    return 0;
}

/* Device file operations */
static int amt_device_open(struct inode *inode, struct file *file)
{
    if (!capable(CAP_SYS_ADMIN)) {
        amt_err("Permission denied: CAP_SYS_ADMIN required");
        return -EPERM;
    }

    amt_info("Device opened by PID %d (UID: %u)", 
             current->pid, from_kuid_munged(current_user_ns(), current_uid()));
    return 0;
}

static int amt_device_release(struct inode *inode, struct file *file)
{
    amt_info("Device closed by PID %d", current->pid);
    return 0;
}

static long amt_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;
    void __user *argp = (void __user *)arg;

    /* Capability check */
    if (!capable(CAP_SYS_ADMIN)) {
        amt_err("IOCTL access denied: CAP_SYS_ADMIN required");
        return -EPERM;
    }

    /* Argument validation */
    if (!argp) {
        amt_err("Invalid IOCTL argument pointer");
        return -EINVAL;
    }

    if (mutex_lock_interruptible(&amt_mutex))
        return -ERESTARTSYS;

    amt_verbose("IOCTL command: 0x%x", cmd);

    switch (cmd) {
    case AMT_READ_PHYS: {
        struct amt_mem_operation op;
        void *data_buf = NULL;

        if (copy_from_user(&op, argp, sizeof(op))) {
            ret = -EFAULT;
            break;
        }

        if (op.size > max_buffer_size) {
            amt_err("Read size too large: %u > %d", op.size, max_buffer_size);
            ret = -EINVAL;
            break;
        }

        data_buf = kzalloc(op.size, GFP_KERNEL);
        if (!data_buf) {
            ret = -ENOMEM;
            break;
        }

        op.timestamp = ktime_get_ns();
        ret = amt_read_physical_memory(op.phys_addr, data_buf, op.size);
        op.result = ret;

        if (ret == 0) {
            if (copy_to_user(argp, &op, sizeof(op)) ||
                copy_to_user((char __user *)argp + sizeof(op), data_buf, op.size)) {
                ret = -EFAULT;
            }
        } else {
            if (copy_to_user(argp, &op, sizeof(op)))
                ret = -EFAULT;
        }

        kfree(data_buf);
        break;
    }

    case AMT_WRITE_PHYS: {
        struct amt_mem_operation op;
        void *data_buf = NULL;

        if (copy_from_user(&op, argp, sizeof(op))) {
            ret = -EFAULT;
            break;
        }

        if (op.size > max_buffer_size) {
            amt_err("Write size too large: %u > %d", op.size, max_buffer_size);
            ret = -EINVAL;
            break;
        }

        data_buf = kzalloc(op.size, GFP_KERNEL);
        if (!data_buf) {
            ret = -ENOMEM;
            break;
        }

        if (copy_from_user(data_buf, (char __user *)argp + sizeof(op), op.size)) {
            kfree(data_buf);
            ret = -EFAULT;
            break;
        }

        op.timestamp = ktime_get_ns();
        ret = amt_write_physical_memory(op.phys_addr, data_buf, op.size);
        op.result = ret;

        kfree(data_buf);

        if (copy_to_user(argp, &op, sizeof(op)))
            ret = -EFAULT;
        break;
    }

    case AMT_VIRT_TO_PHYS: {
        struct amt_addr_translation trans;

        if (copy_from_user(&trans, argp, sizeof(trans))) {
            ret = -EFAULT;
            break;
        }

        trans.output_addr = amt_virtual_to_physical(trans.input_addr, trans.pid);
        trans.success = (trans.output_addr != 0);

        if (copy_to_user(argp, &trans, sizeof(trans)))
            ret = -EFAULT;
        break;
    }

    case AMT_GET_PAGE_INFO: {
        struct amt_page_info info;

        if (copy_from_user(&info, argp, sizeof(info))) {
            ret = -EFAULT;
            break;
        }

        ret = amt_get_page_information(info.addr, &info);

        if (copy_to_user(argp, &info, sizeof(info)))
            ret = -EFAULT;
        break;
    }

    case AMT_GET_MEMORY_STATS: {
        struct amt_memory_stats stats;

        ret = amt_get_memory_statistics(&stats);
        if (ret == 0) {
            if (copy_to_user(argp, &stats, sizeof(stats)))
                ret = -EFAULT;
        }
        break;
    }

    case AMT_SET_DEBUG_LEVEL: {
        int level;

        if (copy_from_user(&level, argp, sizeof(level))) {
            ret = -EFAULT;
            break;
        }

        if (level < 0 || level > 3) {
            ret = -EINVAL;
            break;
        }

        debug_level = level;
        amt_info("Debug level changed to: %d", level);
        break;
    }

    case AMT_GET_SYSTEM_INFO: {
        struct amt_system_info info;

        ret = amt_get_system_information(&info);
        if (ret == 0) {
            if (copy_to_user(argp, &info, sizeof(info)))
                ret = -EFAULT;
        }
        break;
    }

    default:
        amt_err("Unknown IOCTL command: 0x%x", cmd);
        ret = -EINVAL;
        break;
    }

    mutex_unlock(&amt_mutex);
    return ret;
}

/* Proc file operations */
#ifdef HAVE_PROC_OPS
static int amt_proc_show(struct seq_file *m, void *v)
{
    struct amt_memory_stats stats;
    struct amt_system_info sysinfo;

    seq_printf(m, "Advanced Memory Toolkit (AMT) - Status\n");
    seq_printf(m, "=====================================\n\n");

    seq_printf(m, "Version: 4.0 Professional\n");
    seq_printf(m, "Kernel Version: %d.%d.%d\n",
               (LINUX_VERSION_CODE >> 16) & 0xff,
               (LINUX_VERSION_CODE >> 8) & 0xff,
               LINUX_VERSION_CODE & 0xff);

    seq_printf(m, "\nConfiguration:\n");
    seq_printf(m, "  Debug Level: %d\n", debug_level);
    seq_printf(m, "  Safety Level: %d\n", safety_level);
    seq_printf(m, "  Max Buffer Size: %d bytes\n", max_buffer_size);
    seq_printf(m, "  Monitoring: %s\n", enable_monitoring ? "enabled" : "disabled");

    if (amt_get_memory_statistics(&stats) == 0) {
        seq_printf(m, "\nOperation Statistics:\n");
        seq_printf(m, "  Total Operations: %u\n", stats.operations_count);
        seq_printf(m, "  Errors: %u\n", stats.error_count);
        seq_printf(m, "  Bytes Read: %llu\n", stats.bytes_read);
        seq_printf(m, "  Bytes Written: %llu\n", stats.bytes_written);

        seq_printf(m, "\nSystem Memory:\n");
        seq_printf(m, "  Total RAM: %llu MB\n", stats.total_ram / (1024 * 1024));
        seq_printf(m, "  Free RAM: %llu MB\n", stats.free_ram / (1024 * 1024));
        seq_printf(m, "  Cached: %llu MB\n", stats.cached / (1024 * 1024));
        seq_printf(m, "  Slab: %llu MB\n", stats.slab / (1024 * 1024));
    }

    if (amt_get_system_information(&sysinfo) == 0) {
        seq_printf(m, "\nSystem Information:\n");
        seq_printf(m, "  Architecture: %s\n", sysinfo.arch);
        seq_printf(m, "  Page Size: %u bytes\n", sysinfo.page_size);
        seq_printf(m, "  Page Offset: 0x%llx\n", sysinfo.page_offset);
        seq_printf(m, "  VMA Start: 0x%llx\n", sysinfo.vmalloc_start);
        seq_printf(m, "  CPU Count: %u\n", sysinfo.cpu_count);
        seq_printf(m, "  NUMA Nodes: %u\n", sysinfo.node_count);
    }

    return 0;
}

static int amt_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, amt_proc_show, NULL);
}

static const struct proc_ops amt_proc_ops = {
    .proc_open = amt_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static int amt_proc_show(struct seq_file *m, void *v)
{
    /* Same implementation as above but with older proc interface */
    return 0;
}

static int amt_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, amt_proc_show, NULL);
}

static const struct file_operations amt_proc_fops = {
    .open = amt_proc_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif

/* File operations structure */
static const struct file_operations amt_fops = {
    .owner = THIS_MODULE,
    .open = amt_device_open,
    .release = amt_device_release,
    .unlocked_ioctl = amt_device_ioctl,
    .compat_ioctl = amt_device_ioctl,
};

/* Module initialization */
static int __init amt_init(void)
{
    int ret = 0;

    amt_info("Initializing Advanced Memory Toolkit v4.0");
    amt_info("Kernel: %s %s", UTS_SYSNAME, UTS_RELEASE);
    amt_info("Architecture: %s", UTS_MACHINE);
    amt_info("Configuration: debug=%d, safety=%d, buffer=%d", 
             debug_level, safety_level, max_buffer_size);

    /* Validate parameters */
    if (max_buffer_size > MAX_BUFFER_SIZE) {
        amt_warn("Buffer size too large, clamping to %d", MAX_BUFFER_SIZE);
        max_buffer_size = MAX_BUFFER_SIZE;
    }

    if (max_buffer_size < 1024) {
        amt_warn("Buffer size too small, setting to 1024");
        max_buffer_size = 1024;
    }

    /* Initialize synchronization */
    mutex_init(&amt_mutex);

    /* Register character device */
    major_number = register_chrdev(0, DEVICE_NAME, &amt_fops);
    if (major_number < 0) {
        amt_err("Failed to register character device: %d", major_number);
        return major_number;
    }

    /* Create device class */
#ifdef HAVE_CLASS_CREATE_NO_MODULE
    amt_class = class_create(CLASS_NAME);
#else
    amt_class = class_create(THIS_MODULE, CLASS_NAME);
#endif
    if (IS_ERR(amt_class)) {
        ret = PTR_ERR(amt_class);
        amt_err("Failed to create device class: %d", ret);
        goto cleanup_chrdev;
    }

    /* Create device */
    amt_device = device_create(amt_class, NULL, MKDEV(major_number, 0), 
                               NULL, DEVICE_NAME);
    if (IS_ERR(amt_device)) {
        ret = PTR_ERR(amt_device);
        amt_err("Failed to create device: %d", ret);
        goto cleanup_class;
    }

    /* Create proc entry */
#ifdef HAVE_PROC_OPS
    amt_proc_entry = proc_create(PROC_NAME, 0644, NULL, &amt_proc_ops);
#else
    amt_proc_entry = proc_create(PROC_NAME, 0644, NULL, &amt_proc_fops);
#endif
    if (!amt_proc_entry) {
        amt_warn("Failed to create proc entry");
        /* Continue without proc entry */
    }

    amt_info("Module loaded successfully");
    amt_info("Device: /dev/%s (major: %d)", DEVICE_NAME, major_number);
    amt_info("Proc: /proc/%s", PROC_NAME);
    amt_info("Ready for operation");

    return 0;

cleanup_class:
    class_destroy(amt_class);
cleanup_chrdev:
    unregister_chrdev(major_number, DEVICE_NAME);
    return ret;
}

/* Module cleanup */
static void __exit amt_exit(void)
{
    amt_info("Shutting down Advanced Memory Toolkit");

    /* Remove proc entry */
    if (amt_proc_entry) {
        proc_remove(amt_proc_entry);
        amt_debug("Proc entry removed");
    }

    /* Clean up device */
    if (amt_device) {
        device_destroy(amt_class, MKDEV(major_number, 0));
        amt_debug("Device destroyed");
    }

    if (amt_class) {
        class_destroy(amt_class);
        amt_debug("Class destroyed");
    }

    if (major_number > 0) {
        unregister_chrdev(major_number, DEVICE_NAME);
        amt_debug("Character device unregistered");
    }

    /* Final statistics */
    amt_info("Final statistics:");
    amt_info("  Operations: %d", atomic_read(&operation_count));
    amt_info("  Errors: %d", atomic_read(&error_count));
    amt_info("  Bytes read: %lld", atomic64_read(&bytes_read));
    amt_info("  Bytes written: %lld", atomic64_read(&bytes_written));

    amt_info("Module unloaded safely");
}

module_init(amt_init);
module_exit(amt_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Mohammad Amin");
MODULE_DESCRIPTION("Advanced Memory Toolkit - Professional Memory Operations Framework");
MODULE_VERSION("4.0");
MODULE_ALIAS("char-major-" __stringify(DEVICE_NAME));
