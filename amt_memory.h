
/*
 * Advanced Memory Toolkit (AMT) - User-space Header
 * Professional Memory Operations Framework for Linux Kernel
 * 
 * This header provides user-space applications with the necessary
 * definitions to interact with the AMT kernel module.
 * 
 * Author: Mohammad Amin
 * License: GPL v2
 * Version: 4.0 Professional
 */

#ifndef _AMT_MEMORY_H
#define _AMT_MEMORY_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* Device path */
#define AMT_DEVICE_PATH "/dev/amt_memory"

/* IOCTL magic number */
#define AMT_MAGIC 'A'

/* Error codes */
#define AMT_SUCCESS             0
#define AMT_ERR_INVALID_ADDR    -1
#define AMT_ERR_NOT_SUPPORTED   -2
#define AMT_ERR_ACCESS_DENIED   -3
#define AMT_ERR_PAGE_NOT_PRESENT -4
#define AMT_ERR_KERNEL_RESTRICT  -5
#define AMT_ERR_MEMORY_FAULT    -6

/* Translation methods */
#define AMT_METHOD_AUTO         0
#define AMT_METHOD_FORCE_GUP    1
#define AMT_METHOD_FORCE_PTE    2
#define AMT_METHOD_KERNEL_ONLY  3

/* Architecture types */
#define AMT_ARCH_UNKNOWN        0
#define AMT_ARCH_X86_64         1
#define AMT_ARCH_X86_32         2
#define AMT_ARCH_ARM64          3
#define AMT_ARCH_ARM32          4
#define AMT_ARCH_RISCV          5

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

/* IOCTL command definitions */
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

/* Helper macros for error checking */
#define AMT_IS_SUCCESS(result) ((result) == AMT_SUCCESS)
#define AMT_IS_KERNEL_RESTRICTED(errno) ((errno) == AMT_ERR_KERNEL_RESTRICT)
#define AMT_IS_PAGE_NOT_PRESENT(errno) ((errno) == AMT_ERR_PAGE_NOT_PRESENT)

/* Helper macros for capability checking */
#define AMT_SUPPORTS_METHOD(caps, method) ((caps)->translation_methods & (1 << (method)))
#define AMT_HAS_GUP_RESTRICTION(caps) ((caps)->gup_restricted)
#define AMT_SECURITY_LEVEL(caps) ((caps)->security_level)

#endif /* _AMT_MEMORY_H */
