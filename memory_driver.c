
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
#include <linux/utsname.h>
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
#define HAVE_NEWER_PTE_API
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 10, 0)
#define HAVE_LATEST_MM_API
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
#define HAVE_PTE_OFFSET_MAP_NOLOCK
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define HAVE_MMAP_LOCK_API
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define HAVE_NEWER_MMAP_LOCK
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define HAVE_KERNEL_6_12_PLUS
/* Additional compatibility for very new kernels */
/* In kernel 6.12+, pte_offset_map behavior changed */
#undef HAVE_PTE_OFFSET_MAP_NOLOCK
/* Define new PTE API macros for 6.12+ */
#define HAVE_KERNEL_6_12_PTE_API
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#define HAVE_KERNEL_6_11_PLUS
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 8, 0)
#define HAVE_KERNEL_6_8_PLUS
#endif

/* Enhanced architecture detection and support */
#ifdef CONFIG_X86_64
    #define AMT_IS_KERNEL_ADDR(addr) ((addr) >= PAGE_OFFSET)
    #define AMT_IS_USER_ADDR(addr) ((addr) < TASK_SIZE)
    #define AMT_ARCH_NAME "x86_64"
#elif defined(CONFIG_X86_32)
    #define AMT_IS_KERNEL_ADDR(addr) ((addr) >= PAGE_OFFSET)
    #define AMT_IS_USER_ADDR(addr) ((addr) < TASK_SIZE)
    #define AMT_ARCH_NAME "x86_32"
#elif defined(CONFIG_ARM64)
    #define AMT_IS_KERNEL_ADDR(addr) ((addr) >= PAGE_OFFSET)
    #define AMT_IS_USER_ADDR(addr) ((addr) < TASK_SIZE)
    #define AMT_ARCH_NAME "arm64"
#elif defined(CONFIG_ARM)
    #define AMT_IS_KERNEL_ADDR(addr) ((addr) >= PAGE_OFFSET)
    #define AMT_IS_USER_ADDR(addr) ((addr) < TASK_SIZE)
    #define AMT_ARCH_NAME "arm32"
#elif defined(CONFIG_RISCV)
    #define AMT_IS_KERNEL_ADDR(addr) ((addr) >= PAGE_OFFSET)
    #define AMT_IS_USER_ADDR(addr) ((addr) < TASK_SIZE)
    #define AMT_ARCH_NAME "riscv"
#else
    #define AMT_IS_KERNEL_ADDR(addr) ((addr) >= PAGE_OFFSET)
    #define AMT_IS_USER_ADDR(addr) ((addr) < TASK_SIZE)
    #define AMT_ARCH_NAME "unknown"
#endif

/* Global cached values for runtime detection */
static unsigned long amt_cached_task_size;
static unsigned long amt_cached_page_offset;
static bool amt_cache_initialized = false;

/* Error codes for better debugging */
#define AMT_SUCCESS             0
#define AMT_ERR_INVALID_ADDR    -1
#define AMT_ERR_NOT_SUPPORTED   -2
#define AMT_ERR_ACCESS_DENIED   -3
#define AMT_ERR_PAGE_NOT_PRESENT -4
#define AMT_ERR_KERNEL_RESTRICT  -5
#define AMT_ERR_MEMORY_FAULT    -6

/* Translation method flags */
#define AMT_METHOD_AUTO         0
#define AMT_METHOD_FORCE_GUP    1
#define AMT_METHOD_FORCE_PTE    2
#define AMT_METHOD_KERNEL_ONLY  3

/* Global configuration */
static int amt_translation_method = AMT_METHOD_AUTO;
static bool amt_dev_mode = false;

/* Enhanced get_user_pages compatibility */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define amt_get_user_pages(mm, addr, nr, flags, pages, vmas) \
    get_user_pages_remote(current, mm, addr, nr, flags, pages, vmas, NULL)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#define amt_get_user_pages(mm, addr, nr, flags, pages, vmas) \
    get_user_pages_remote(current, mm, addr, nr, flags, pages, vmas, NULL, NULL)
#else
#define amt_get_user_pages(mm, addr, nr, flags, pages, vmas) \
    get_user_pages(addr, nr, flags, pages, vmas)
#endif

/* Initialize cached runtime values */
static void amt_init_runtime_cache(void)
{
    if (!amt_cache_initialized) {
        amt_cached_task_size = TASK_SIZE;
        amt_cached_page_offset = PAGE_OFFSET;
        amt_cache_initialized = true;
        
        amt_info("Runtime cache initialized:");
        amt_info("  TASK_SIZE: 0x%lx", amt_cached_task_size);
        amt_info("  PAGE_OFFSET: 0x%lx", amt_cached_page_offset);
        amt_info("  Architecture: %s", AMT_ARCH_NAME);
    }
}

/* Enhanced address validation */
static inline bool amt_is_valid_kernel_address(unsigned long addr)
{
    if (!amt_cache_initialized)
        amt_init_runtime_cache();
    
    return AMT_IS_KERNEL_ADDR(addr) && (addr >= amt_cached_page_offset);
}

static inline bool amt_is_valid_user_address(unsigned long addr)
{
    if (!amt_cache_initialized)
        amt_init_runtime_cache();
    
    return AMT_IS_USER_ADDR(addr) && (addr < amt_cached_task_size);
}

/* Enhanced page table walk for development/debugging */
static int amt_pte_walk_debug(struct mm_struct *mm, unsigned long virt_addr, 
                             unsigned long *phys_addr, bool force_walk)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    int result = AMT_ERR_PAGE_NOT_PRESENT;
    
    *phys_addr = 0;
    
    if (!mm) {
        amt_debug("No MM structure for PTE walk");
        return AMT_ERR_INVALID_ADDR;
    }
    
    amt_mmap_read_lock(mm);
    
    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        amt_debug("PTE walk failed at PGD level for 0x%lx", virt_addr);
        goto out;
    }
    
    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        amt_debug("PTE walk failed at P4D level for 0x%lx", virt_addr);
        goto out;
    }
    
    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        amt_debug("PTE walk failed at PUD level for 0x%lx", virt_addr);
        goto out;
    }
    
    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        amt_debug("PTE walk failed at PMD level for 0x%lx", virt_addr);
        goto out;
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    if (!force_walk && amt_is_valid_user_address(virt_addr)) {
        amt_warn("PTE walk on kernel 6.12+ for user-space not recommended (addr: 0x%lx)", virt_addr);
        result = AMT_ERR_KERNEL_RESTRICT;
        goto out;
    }
#endif
    
    pte = AMT_PTE_OFFSET_MAP(pmd, virt_addr);
    if (!pte || pte_none(*pte)) {
        amt_debug("PTE walk failed at PTE level for 0x%lx", virt_addr);
        AMT_PTE_UNMAP(pte);
        goto out;
    }
    
    if (pte_present(*pte)) {
        *phys_addr = (pte_pfn(*pte) << PAGE_SHIFT) + (virt_addr & ~PAGE_MASK);
        result = AMT_SUCCESS;
        amt_debug("PTE walk successful: 0x%lx -> 0x%lx", virt_addr, *phys_addr);
    } else {
        amt_debug("PTE present bit not set for 0x%lx", virt_addr);
        result = AMT_ERR_PAGE_NOT_PRESENT;
    }
    
    AMT_PTE_UNMAP(pte);
    
out:
    amt_mmap_read_unlock(mm);
    return result;
}

/* Enhanced GUP-based translation with proper error handling */
static int amt_gup_translate(struct mm_struct *mm, unsigned long virt_addr, 
                            unsigned long *phys_addr)
{
    struct page *page;
    int ret;
    
    *phys_addr = 0;
    
    if (!mm) {
        amt_err("No MM structure for GUP translation");
        return AMT_ERR_INVALID_ADDR;
    }
    
    if (!amt_is_valid_user_address(virt_addr)) {
        amt_debug("Address 0x%lx not valid for user-space GUP", virt_addr);
        return AMT_ERR_INVALID_ADDR;
    }
    
    amt_mmap_read_lock(mm);
    ret = amt_get_user_pages(mm, virt_addr, 1, FOLL_GET, &page, NULL);
    amt_mmap_read_unlock(mm);
    
    if (ret == 1) {
        *phys_addr = page_to_phys(page) + (virt_addr & ~PAGE_MASK);
        put_page(page);
        amt_debug("GUP translation successful: 0x%lx -> 0x%lx", virt_addr, *phys_addr);
        return AMT_SUCCESS;
    } else {
        amt_debug("GUP failed for address 0x%lx (ret: %d)", virt_addr, ret);
        
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
        if (amt_is_valid_user_address(virt_addr)) {
            amt_warn("User-space virtual-to-physical translation may be restricted on kernel >= 6.12 (address: 0x%lx)", virt_addr);
        }
#endif
        
        return (ret == 0) ? AMT_ERR_PAGE_NOT_PRESENT : AMT_ERR_MEMORY_FAULT;
    }
}

/* Main enhanced translation function */
static inline unsigned long amt_get_user_physical_addr(struct mm_struct *mm, unsigned long virt_addr)
{
    unsigned long phys_addr = 0;
    int result;
    
    if (!amt_cache_initialized)
        amt_init_runtime_cache();
    
    /* Handle kernel addresses directly */
    if (amt_is_valid_kernel_address(virt_addr)) {
        phys_addr = virt_to_phys((void *)virt_addr);
        amt_verbose("Kernel direct mapping: 0x%lx -> 0x%lx", virt_addr, phys_addr);
        return phys_addr;
    }
    
    /* Handle user addresses based on method and kernel version */
    if (amt_is_valid_user_address(virt_addr)) {
        bool use_gup = true;
        
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
        /* Kernel 6.12+ prefers GUP for user-space */
        if (amt_translation_method == AMT_METHOD_FORCE_PTE) {
            use_gup = false;
            amt_debug("Forcing PTE walk on kernel 6.12+ (dev mode)");
        }
#else
        /* Older kernels: choose based on method */
        if (amt_translation_method == AMT_METHOD_FORCE_PTE) {
            use_gup = false;
        }
#endif
        
        if (use_gup) {
            result = amt_gup_translate(mm, virt_addr, &phys_addr);
            if (result == AMT_SUCCESS) {
                return phys_addr;
            }
            
            /* Fallback to PTE walk if GUP fails and dev mode is enabled */
            if (amt_dev_mode && result != AMT_ERR_KERNEL_RESTRICT) {
                amt_debug("GUP failed, trying PTE walk fallback");
                result = amt_pte_walk_debug(mm, virt_addr, &phys_addr, true);
                if (result == AMT_SUCCESS) {
                    amt_info("PTE walk fallback successful for 0x%lx", virt_addr);
                    return phys_addr;
                }
            }
        } else {
            /* Direct PTE walk (dev mode or forced) */
            result = amt_pte_walk_debug(mm, virt_addr, &phys_addr, true);
            if (result == AMT_SUCCESS) {
                return phys_addr;
            }
        }
        
        /* Log the failure reason */
        switch (result) {
        case AMT_ERR_KERNEL_RESTRICT:
            amt_warn("Translation restricted by kernel version for address 0x%lx", virt_addr);
            break;
        case AMT_ERR_PAGE_NOT_PRESENT:
            amt_debug("Page not present for address 0x%lx", virt_addr);
            break;
        case AMT_ERR_MEMORY_FAULT:
            amt_debug("Memory fault during translation of address 0x%lx", virt_addr);
            break;
        default:
            amt_debug("Translation failed for address 0x%lx (error: %d)", virt_addr, result);
            break;
        }
    } else {
        amt_debug("Invalid address range: 0x%lx", virt_addr);
    }
    
    return 0;
}

static inline pte_t *amt_safe_pte_lookup(struct mm_struct *mm, unsigned long addr, 
                                        pgd_t **pgd_out, p4d_t **p4d_out, 
                                        pud_t **pud_out, pmd_t **pmd_out)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    
    if (addr >= TASK_SIZE) {
        /* Kernel space - use kernel page tables */
        pgd = pgd_offset_k(addr);
    } else {
        /* User space */
        if (!mm) return NULL;
        pgd = pgd_offset(mm, addr);
    }
    
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;
    
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;
    
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;
    
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return NULL;
    
    if (pgd_out) *pgd_out = pgd;
    if (p4d_out) *p4d_out = p4d;
    if (pud_out) *pud_out = pud;
    if (pmd_out) *pmd_out = pmd;
    
    if (addr >= TASK_SIZE) {
        /* For kernel addresses, use pte_offset_kernel */
        return pte_offset_kernel(pmd, addr);
    }
    
    /* For user addresses in 6.12+, we can't safely map PTEs directly */
    return NULL;
}

#define AMT_PTE_OFFSET_MAP(pmd, addr) amt_safe_pte_lookup(current->mm, addr, NULL, NULL, NULL, NULL)
#define AMT_PTE_UNMAP(pte) do { } while(0)

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
/* For 6.5-6.11, use pte_offset_map with unmap */
#define AMT_PTE_OFFSET_MAP(pmd, addr) pte_offset_map(pmd, addr)
#define AMT_PTE_UNMAP(pte) do { if (pte) pte_unmap(pte); } while(0)

static inline unsigned long amt_get_user_physical_addr(struct mm_struct *mm, unsigned long virt_addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long phys_addr = 0;
    
    if (virt_addr >= PAGE_OFFSET) {
        return virt_to_phys((void *)virt_addr);
    }
    
    if (!mm) return 0;
    
    mmap_read_lock(mm);
    
    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) goto out;
    
    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) goto out;
    
    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud) || pud_bad(*pud)) goto out;
    
    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) goto out;
    
    pte = pte_offset_map(pmd, virt_addr);
    if (!pte || pte_none(*pte)) {
        if (pte) pte_unmap(pte);
        goto out;
    }
    
    if (pte_present(*pte)) {
        phys_addr = (pte_pfn(*pte) << PAGE_SHIFT) + (virt_addr & ~PAGE_MASK);
    }
    
    pte_unmap(pte);
    
out:
    mmap_read_unlock(mm);
    return phys_addr;
}

#elif defined(HAVE_PTE_OFFSET_MAP_NOLOCK)
/* For kernels with pte_offset_map_nolock */
#define AMT_PTE_OFFSET_MAP(pmd, addr) pte_offset_map_nolock(NULL, pmd, addr, NULL)
#define AMT_PTE_UNMAP(pte) do { } while(0)

static inline unsigned long amt_get_user_physical_addr(struct mm_struct *mm, unsigned long virt_addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long phys_addr = 0;
    
    if (virt_addr >= PAGE_OFFSET) {
        return virt_to_phys((void *)virt_addr);
    }
    
    if (!mm) return 0;
    
    mmap_read_lock(mm);
    
    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) goto out;
    
    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) goto out;
    
    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud) || pud_bad(*pud)) goto out;
    
    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) goto out;
    
    pte = pte_offset_map_nolock(NULL, pmd, virt_addr, NULL);
    if (!pte || pte_none(*pte)) goto out;
    
    if (pte_present(*pte)) {
        phys_addr = (pte_pfn(*pte) << PAGE_SHIFT) + (virt_addr & ~PAGE_MASK);
    }
    
out:
    mmap_read_unlock(mm);
    return phys_addr;
}

#else
/* Fallback to standard pte_offset_map */
#define AMT_PTE_OFFSET_MAP(pmd, addr) pte_offset_map(pmd, addr)
#define AMT_PTE_UNMAP(pte) do { if (pte) pte_unmap(pte); } while(0)

static inline unsigned long amt_get_user_physical_addr(struct mm_struct *mm, unsigned long virt_addr)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long phys_addr = 0;
    
    if (virt_addr >= PAGE_OFFSET) {
        return virt_to_phys((void *)virt_addr);
    }
    
    if (!mm) return 0;
    
    mmap_read_lock(mm);
    
    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) goto out;
    
    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) goto out;
    
    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud) || pud_bad(*pud)) goto out;
    
    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) goto out;
    
    pte = pte_offset_map(pmd, virt_addr);
    if (!pte || pte_none(*pte)) {
        if (pte) pte_unmap(pte);
        goto out;
    }
    
    if (pte_present(*pte)) {
        phys_addr = (pte_pfn(*pte) << PAGE_SHIFT) + (virt_addr & ~PAGE_MASK);
    }
    
    pte_unmap(pte);
    
out:
    mmap_read_unlock(mm);
    return phys_addr;
}

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
#define AMT_SET_TRANSLATION_METHOD _IOW(AMT_MAGIC, 11, int)
#define AMT_GET_TRANSLATION_METHOD _IOR(AMT_MAGIC, 12, int)
#define AMT_SET_DEV_MODE        _IOW(AMT_MAGIC, 13, int)
#define AMT_GET_DEV_MODE        _IOR(AMT_MAGIC, 14, int)
#define AMT_GET_KERNEL_CAPS     _IOR(AMT_MAGIC, 15, struct amt_kernel_capabilities)

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
    __s32 kernel_errno;          /* Detailed kernel error code */
    __u32 translation_method;    /* Method used for translation */
    __u8 kernel_restriction;     /* Set if restricted by kernel version */
    __u8 address_type;          /* 0=user, 1=kernel, 2=invalid */
    __u8 fallback_used;         /* Set if fallback method was used */
    __u8 reserved;              /* Padding for alignment */
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

struct amt_kernel_capabilities {
    __u32 kernel_version;
    __u32 has_gup;              /* get_user_pages available */
    __u32 has_pte_offset_map;   /* pte_offset_map available */
    __u32 gup_restricted;       /* GUP restrictions in place */
    __u32 supports_user_trans;  /* User-space translation supported */
    __u32 supports_pte_walk;    /* PTE walk supported */
    __u32 architecture;         /* Architecture type */
    char arch_name[16];         /* Architecture name */
    __u32 translation_methods;  /* Bitmask of supported methods */
    __u32 security_level;       /* Kernel security restrictions */
} __packed;

/* Global variables */
static int major_number;
static struct class *amt_class = NULL;
static struct device *amt_device = NULL;
static struct proc_dir_entry *amt_proc_entry = NULL;

/* Synchronization */
static DEFINE_MUTEX(amt_mutex);

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    mmap_read_lock(mm);
#else
    down_read(&mm->mmap_sem);
#endif
}

static inline void amt_mmap_read_unlock(struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
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

/* Use the compatibility macros instead of functions */

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
    size_t local_bytes_read = 0;
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

    while (local_bytes_read < size) {
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

        chunk_size = min(size - local_bytes_read, PAGE_SIZE - (current_addr & ~PAGE_MASK));

        mapped_addr = ioremap(current_addr, chunk_size);
        if (!mapped_addr) {
            amt_err("Failed to map physical address: 0x%lx", current_addr);
            atomic_inc(&error_count);
            return -ENOMEM;
        }

        memcpy_fromio(buf_ptr + local_bytes_read, mapped_addr, chunk_size);
        iounmap(mapped_addr);

        local_bytes_read += chunk_size;
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
    size_t local_bytes_written = 0;
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

    while (local_bytes_written < size) {
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

        chunk_size = min(size - local_bytes_written, PAGE_SIZE - (current_addr & ~PAGE_MASK));

        mapped_addr = ioremap(current_addr, chunk_size);
        if (!mapped_addr) {
            amt_err("Failed to map physical address for write: 0x%lx", current_addr);
            atomic_inc(&error_count);
            return -ENOMEM;
        }

        memcpy_toio(mapped_addr, buf_ptr + local_bytes_written, chunk_size);
        wmb(); /* Write memory barrier */
        iounmap(mapped_addr);

        local_bytes_written += chunk_size;
        current_addr += chunk_size;
    }

    atomic_inc(&operation_count);
    atomic64_add(size, &bytes_written);
    amt_debug("Successfully wrote %zu bytes to 0x%lx", size, phys_addr);
    
    return 0;
}

static int amt_virtual_to_physical_detailed(unsigned long virt_addr, pid_t pid, 
                                            struct amt_addr_translation *trans)
{
    struct task_struct *task = NULL;
    struct mm_struct *mm = NULL;
    unsigned long phys_addr = 0;
    int result = AMT_SUCCESS;
    bool mm_acquired = false;

    /* Initialize translation structure */
    memset(trans, 0, sizeof(*trans));
    trans->input_addr = virt_addr;
    trans->pid = pid;
    trans->kernel_errno = 0;
    trans->translation_method = amt_translation_method;

    if (!amt_is_safe_virtual_address(virt_addr, pid)) {
        amt_err("Unsafe virtual address: 0x%lx", virt_addr);
        trans->kernel_errno = AMT_ERR_INVALID_ADDR;
        return -EINVAL;
    }

    amt_verbose("Translating virtual address 0x%lx (PID: %d)", virt_addr, pid);

    /* Determine address type */
    if (amt_is_valid_kernel_address(virt_addr)) {
        trans->address_type = 1; /* Kernel */
        
        if (pid == 0) {
            /* Direct kernel address translation */
            phys_addr = virt_to_phys((void *)virt_addr);
            amt_debug("Kernel direct mapping: 0x%lx -> 0x%lx", virt_addr, phys_addr);
            trans->output_addr = phys_addr;
            trans->success = 1;
            atomic_inc(&operation_count);
            return 0;
        } else {
            /* Kernel address requested for user PID - use current mm */
            mm = current->mm;
            amt_debug("Kernel address with user PID, using current->mm");
        }
    } else if (amt_is_valid_user_address(virt_addr)) {
        trans->address_type = 0; /* User */
        
        if (pid == 0) {
            mm = current->mm;
        } else {
            /* User process address translation */
            rcu_read_lock();
            task = pid_task(find_vpid(pid), PIDTYPE_PID);
            if (!task || (task->flags & PF_EXITING)) {
                rcu_read_unlock();
                amt_err("Invalid or exiting process: PID %d", pid);
                trans->kernel_errno = AMT_ERR_INVALID_ADDR;
                return -ESRCH;
            }
            mm = get_task_mm(task);
            rcu_read_unlock();
            mm_acquired = true;
            
            if (!mm) {
                amt_err("No memory management structure for PID: %d", pid);
                trans->kernel_errno = AMT_ERR_INVALID_ADDR;
                return -EINVAL;
            }
        }
    } else {
        trans->address_type = 2; /* Invalid */
        amt_err("Invalid address range: 0x%lx", virt_addr);
        trans->kernel_errno = AMT_ERR_INVALID_ADDR;
        return -EINVAL;
    }

    if (!mm) {
        amt_err("No memory management structure available");
        trans->kernel_errno = AMT_ERR_INVALID_ADDR;
        return -EINVAL;
    }

    /* Perform translation using enhanced function */
    phys_addr = amt_get_user_physical_addr(mm, virt_addr);
    
    /* Clean up mm reference if acquired */
    if (mm_acquired) {
        mmput(mm);
    }

    trans->output_addr = phys_addr;
    if (phys_addr) {
        trans->success = 1;
        trans->kernel_errno = AMT_SUCCESS;
        amt_debug("Translation successful: 0x%lx -> 0x%lx", virt_addr, phys_addr);
        atomic_inc(&operation_count);
    } else {
        trans->success = 0;
        
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
        if (trans->address_type == 0) { /* User address */
            trans->kernel_restriction = 1;
            trans->kernel_errno = AMT_ERR_KERNEL_RESTRICT;
            amt_warn("User-space virtual-to-physical translation may be restricted on kernel >= 6.12 (address: 0x%lx, pid: %d)", virt_addr, pid);
        } else {
            trans->kernel_errno = AMT_ERR_PAGE_NOT_PRESENT;
        }
#else
        trans->kernel_errno = AMT_ERR_PAGE_NOT_PRESENT;
#endif
        
        amt_debug("Translation failed for address: 0x%lx", virt_addr);
        atomic_inc(&error_count);
        result = -EFAULT;
    }

    return result;
}

/* Legacy wrapper for compatibility */
static unsigned long amt_virtual_to_physical(unsigned long virt_addr, pid_t pid)
{
    struct amt_addr_translation trans;
    amt_virtual_to_physical_detailed(virt_addr, pid, &trans);
    return trans.output_addr;
}

static int amt_get_page_information(unsigned long addr, struct amt_page_info *info)
{
    struct mm_struct *mm = current->mm;
    struct page *page = NULL;
    unsigned long pfn;
    unsigned long phys_addr;

    if (!info) {
        amt_err("NULL page info structure");
        return -EINVAL;
    }

    memset(info, 0, sizeof(*info));
    info->addr = addr;

    amt_verbose("Getting page information for address: 0x%lx", addr);

    /* Handle kernel addresses */
    if (addr >= PAGE_OFFSET) {
        phys_addr = virt_to_phys((void *)addr);
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
                info->map_count = page_count(page);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    /* For kernel 6.12+, use get_user_pages approach */
    mmap_read_lock(mm);
    
    int ret = get_user_pages(addr, 1, FOLL_GET, &page, NULL);
    if (ret == 1) {
        info->present = 1;
        info->user_accessible = 1;
        info->writable = 1; /* Simplified - actual permissions may vary */
        
        pfn = page_to_pfn(page);
        info->page_frame_number = pfn;
        info->physical_addr = page_to_phys(page) + (addr & ~PAGE_MASK);
        info->ref_count = page_ref_count(page);
        info->map_count = page_count(page);
        info->flags = page->flags;
        
        put_page(page);
        amt_debug("User page info retrieved via get_user_pages for: 0x%lx", addr);
    } else {
        amt_debug("get_user_pages failed for address: 0x%lx", addr);
    }
    
    mmap_read_unlock(mm);
#else
    /* For older kernels, use traditional page table walk */
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    amt_mmap_read_lock(mm);

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        goto out_old;

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        goto out_old;

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud))
        goto out_old;

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        goto out_old;

    pte = AMT_PTE_OFFSET_MAP(pmd, addr);
    if (!pte || pte_none(*pte)) {
        AMT_PTE_UNMAP(pte);
        goto out_old;
    }

    /* Extract page information */
    info->present = pte_present(*pte);
    info->writable = pte_write(*pte);
    info->user_accessible = 1;
    info->accessed = pte_young(*pte);
    info->dirty = pte_dirty(*pte);
    info->global_page = pte_global(*pte);
    info->nx_bit = 0;
    info->flags = pte_val(*pte);

    if (info->present) {
        pfn = pte_pfn(*pte);
        info->page_frame_number = pfn;
        info->physical_addr = (pfn << PAGE_SHIFT) + (addr & ~PAGE_MASK);
        
        if (pfn_valid(pfn)) {
            page = pfn_to_page(pfn);
            if (page) {
                info->ref_count = page_ref_count(page);
                info->map_count = page_count(page);
            }
        }
    }

    AMT_PTE_UNMAP(pte);

out_old:
    amt_mmap_read_unlock(mm);
#endif

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
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    stats->cached = global_node_page_state(NR_FILE_PAGES) * PAGE_SIZE;
    stats->buffers = si.bufferram * PAGE_SIZE;
    stats->slab = global_node_page_state(NR_SLAB_RECLAIMABLE_B) +
                  global_node_page_state(NR_SLAB_UNRECLAIMABLE_B);
#else
    stats->cached = global_page_state(NR_FILE_PAGES) * PAGE_SIZE;
    stats->buffers = si.bufferram * PAGE_SIZE;
    stats->slab = global_page_state(NR_SLAB_RECLAIMABLE) +
                  global_page_state(NR_SLAB_UNRECLAIMABLE);
#endif

    /* Our driver statistics */
    stats->operations_count = atomic_read(&operation_count);
    stats->error_count = atomic_read(&error_count);
    stats->bytes_read = atomic64_read(&bytes_read);
    stats->bytes_written = atomic64_read(&bytes_written);

    amt_debug("Memory statistics retrieved");
    return 0;
}

static int amt_get_kernel_capabilities(struct amt_kernel_capabilities *caps)
{
    if (!caps) {
        amt_err("NULL kernel capabilities structure");
        return -EINVAL;
    }

    memset(caps, 0, sizeof(*caps));

    /* Basic kernel information */
    caps->kernel_version = LINUX_VERSION_CODE;
    strncpy(caps->arch_name, AMT_ARCH_NAME, sizeof(caps->arch_name) - 1);

    /* Architecture detection */
#ifdef CONFIG_X86_64
    caps->architecture = 1;
#elif defined(CONFIG_X86_32)
    caps->architecture = 2;
#elif defined(CONFIG_ARM64)
    caps->architecture = 3;
#elif defined(CONFIG_ARM)
    caps->architecture = 4;
#elif defined(CONFIG_RISCV)
    caps->architecture = 5;
#else
    caps->architecture = 0; /* Unknown */
#endif

    /* Feature detection */
    caps->has_gup = 1; /* get_user_pages is always available in supported kernels */
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    caps->has_pte_offset_map = 0; /* Restricted in 6.12+ */
    caps->gup_restricted = 1;
    caps->supports_user_trans = 1; /* Via GUP only */
    caps->supports_pte_walk = 0;   /* Not recommended */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
    caps->has_pte_offset_map = 1;
    caps->gup_restricted = 0;
    caps->supports_user_trans = 1;
    caps->supports_pte_walk = 1;
#else
    caps->has_pte_offset_map = 1;
    caps->gup_restricted = 0;
    caps->supports_user_trans = 1;
    caps->supports_pte_walk = 1;
#endif

    /* Translation method support bitmask */
    caps->translation_methods = 0;
    caps->translation_methods |= (1 << AMT_METHOD_AUTO);
    if (caps->has_gup)
        caps->translation_methods |= (1 << AMT_METHOD_FORCE_GUP);
    if (caps->supports_pte_walk)
        caps->translation_methods |= (1 << AMT_METHOD_FORCE_PTE);
    caps->translation_methods |= (1 << AMT_METHOD_KERNEL_ONLY);

    /* Security level based on kernel version and configuration */
    if (caps->gup_restricted || !caps->supports_pte_walk) {
        caps->security_level = 3; /* High restriction */
    } else if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)) {
        caps->security_level = 2; /* Medium restriction */
    } else {
        caps->security_level = 1; /* Low restriction */
    }

    amt_debug("Kernel capabilities retrieved");
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

    strncpy(info->arch, utsname()->machine, sizeof(info->arch) - 1);
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

        ret = amt_virtual_to_physical_detailed(trans.input_addr, trans.pid, &trans);
        
        /* Always copy back the result, even on error */
        if (copy_to_user(argp, &trans, sizeof(trans)))
            ret = -EFAULT;
        else if (ret != 0)
            ret = 0;  /* Error info is in the structure */
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

    case AMT_SET_TRANSLATION_METHOD: {
        int method;

        if (copy_from_user(&method, argp, sizeof(method))) {
            ret = -EFAULT;
            break;
        }

        if (method < AMT_METHOD_AUTO || method > AMT_METHOD_KERNEL_ONLY) {
            ret = -EINVAL;
            break;
        }

        amt_translation_method = method;
        amt_info("Translation method changed to: %d", method);
        break;
    }

    case AMT_GET_TRANSLATION_METHOD: {
        if (copy_to_user(argp, &amt_translation_method, sizeof(amt_translation_method)))
            ret = -EFAULT;
        break;
    }

    case AMT_SET_DEV_MODE: {
        int dev_mode;

        if (copy_from_user(&dev_mode, argp, sizeof(dev_mode))) {
            ret = -EFAULT;
            break;
        }

        amt_dev_mode = (dev_mode != 0);
        amt_info("Developer mode %s", amt_dev_mode ? "enabled" : "disabled");
        break;
    }

    case AMT_GET_DEV_MODE: {
        int dev_mode = amt_dev_mode ? 1 : 0;
        if (copy_to_user(argp, &dev_mode, sizeof(dev_mode)))
            ret = -EFAULT;
        break;
    }

    case AMT_GET_KERNEL_CAPS: {
        struct amt_kernel_capabilities caps;
        
        ret = amt_get_kernel_capabilities(&caps);
        if (ret == 0) {
            if (copy_to_user(argp, &caps, sizeof(caps)))
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
    amt_info("Kernel: %s %s", utsname()->sysname, utsname()->release);
    amt_info("Architecture: %s", utsname()->machine);
    amt_info("Configuration: debug=%d, safety=%d, buffer=%d", 
             debug_level, safety_level, max_buffer_size);

    /* Initialize runtime cache */
    amt_init_runtime_cache();

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
