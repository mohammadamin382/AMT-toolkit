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
#include <linux/capability.h>
#include <linux/mutex.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/random.h>
#include <linux/scatterlist.h>

// شامل کردن header های مناسب برای نسخه‌های مختلف کرنل
// چون کرنل لینوکس همش تغییر می‌کنه! 😅
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#endif

// ماکروهای سازگاری برای نسخه‌های مختلف کرنل
// این ماکروها مثل مترجم زبان هستن بین نسخه‌های مختلف! 🤪
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
// تو نسخه‌های قدیمی crypto پیچیده‌تر بود، مثل پازل 1000 تکه! 🧩
#define CRYPTO_NOT_AVAILABLE
#endif

// ماکروهای سازگاری برای کرنل 6.0+
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#define HAVE_NEW_CLASS_CREATE
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#define HAVE_NO_PTE_USER
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
#include <linux/utsname.h>
#define HAVE_UTSNAME_HEADER
#endif

// ماکروی سازگاری برای pte_offset_map در کرنل 6.12+
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#define HAVE_NO_PTE_OFFSET_MAP
#endif

// ماکروهای جایگزین برای توابع حذف شده
#ifdef HAVE_NO_PTE_USER
#define pte_user(pte) (!pte_present(pte) ? 0 : !(pte_val(pte) & _PAGE_USER) ? 0 : 1)
#endif

// تابع جایگزین برای utsname در کرنل‌های جدید
#ifdef HAVE_UTSNAME_HEADER
#define advmem_utsname() (&init_uts_ns.name)
#else
#define advmem_utsname() utsname()
#endif

// تعاریف اصلی - اینا رو دست نزن وگرنه کل سیستم می‌ره تو فاز! 💥
#define DEVICE_NAME "advanced_memory"
#define CLASS_NAME "advmem_class"
#define BUFFER_SIZE 8192

// دستورات IOCTL - اینا مثل کلیدهای جادویی هستن! 🗝️✨
#define IOCTL_READ_PHYS_MEM _IOR('M', 1, struct mem_operation)
#define IOCTL_WRITE_PHYS_MEM _IOW('M', 2, struct mem_operation)
#define IOCTL_VIRT_TO_PHYS _IOWR('M', 3, struct addr_translation)
#define IOCTL_PHYS_TO_VIRT _IOWR('M', 4, struct addr_translation)
#define IOCTL_GET_PAGE_INFO _IOWR('M', 5, struct page_info)


// ساختارها - اینا مثل قالب کیک هستن، شکل داده‌ها رو مشخص می‌کنن! 🧁
struct mem_operation {
    unsigned long phys_addr;    // آدرس فیزیکی - مثل آدرس خونه تو دنیای واقعی! 🏠
    unsigned long size;         // اندازه - نه خیلی کوچیک، نه خیلی بزرگ! 📏
    unsigned long flags;        // پرچم‌ها - مثل علامت راهنمایی رانندگی! 🚦
    char data[BUFFER_SIZE];     // داده‌ها - اینجا همه چیز ذخیره می‌شه! 📦
    int result;                 // نتیجه - موفق یا ناموفق؟ 🎯
};

struct addr_translation {
    unsigned long input_addr;      // آدرس ورودی - چیزی که می‌خوایم تبدیل کنیم 📍
    unsigned long output_addr;     // آدرس خروجی - چیزی که بعد تبدیل می‌شه 📍
    pid_t pid;                    // شناسه پروسه - مثل شناسنامه! 🆔
    int success;                  // موفقیت - آره یا نه؟ ✅❌
    unsigned long page_table_levels[5];  // سطوح جدول صفحه - مثل طبقات ساختمان! 🏢
    unsigned long protection_flags;      // پرچم‌های حفاظتی - نگهبان حافظه! 🛡️
};

struct page_info {
    unsigned long addr;        // آدرس - کجاست؟ 📍
    unsigned long page_frame;  // شماره فریم صفحه - مثل شماره اتاق! 🚪
    unsigned long flags;       // پرچم‌ها - ویژگی‌های صفحه 🏴
    int present;              // حاضر - آیا صفحه اونجاست؟ 👻
    int writable;             // قابل نوشتن - می‌شه روش نوشت? ✏️
    int user;                 // کاربری - کاربر عادی دسترسی داره؟ 👤
    int accessed;             // دسترسی شده - اخیراً استفاده شده؟ 👀
    int dirty;                // کثیف - تغییر کرده؟ 💩
    int global;               // سراسری - همه جا معتبره؟ 🌍
    int nx;                   // غیرقابل اجرا - کد نمی‌شه اجرا کرد 🚫
    unsigned long cache_type;  // نوع کش - سریع یا کند؟ ⚡
};



// متغیرهای سراسری - اینا مثل حافظه مشترک هستن! 🧠
static int major_number;                    // شماره اصلی دستگاه 🔢
static struct class* advmem_class = NULL;   // کلاس دستگاه 🎓
static struct device* advmem_device = NULL; // خود دستگاه 📱
static DEFINE_MUTEX(advmem_mutex);          // mutex برای thread safety - قفل جادویی! 🔒

// سطح debug: 0=فقط خطاها، 1=اطلاعات، 2=همه چیز! 🐛
static int debug_level = 1;
module_param(debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Debug level (0=errors, 1=info, 2=debug) - هرچی بیشتر باشه، بیشتر حرف می‌زنم! 😄");

// حالت امن: 0=غیرفعال، 1=پایه، 2=متوسط، 3=حداکثر 🛡️
static int safe_mode = 2;
module_param(safe_mode, int, 0644);
MODULE_PARM_DESC(safe_mode, "Safety level (0=disabled, 1=basic, 2=standard, 3=maximum) - بالاتر = امن‌تر! 🔐");

// ماکروهای debug - اینا کمک می‌کنن بفهمیم چه خبره! 🕵️
#define advmem_err(fmt, ...) \
    printk(KERN_ERR "🚨 Advanced Memory ERROR: " fmt, ##__VA_ARGS__)

#define advmem_info(fmt, ...) \
    do { if (debug_level >= 1) \
        printk(KERN_INFO "ℹ️ Advanced Memory: " fmt, ##__VA_ARGS__); \
    } while (0)

#define advmem_debug(fmt, ...) \
    do { if (debug_level >= 2) \
        printk(KERN_DEBUG "🐛 Advanced Memory DEBUG: " fmt, ##__VA_ARGS__); \
    } while (0)

// ماکروهای بررسی امنیت - مثل نگهبان! 💂
#define SAFETY_CHECK_LEVEL(level) (safe_mode >= (level))
#define SAFETY_DISABLED() (safe_mode == 0)

// محدودیت‌های اندازه بر اساس سطح امنیت
// هرچی امن‌تر، کوچیک‌تر! 📦
#define SAFE_MAX_SIZE_LEVEL1    (64 * 1024)      // 64KB - نسبتاً آزاد
#define SAFE_MAX_SIZE_LEVEL2    (16 * 1024)      // 16KB - متوسط
#define SAFE_MAX_SIZE_LEVEL3    (4 * 1024)       // 4KB - محتاط

// محدوده‌های حیاتی حافظه که نباید دستشون بزنیم! ⚠️
#define CRITICAL_MEM_START      0x0
#define CRITICAL_MEM_END        0x100000         // اول 1MB - ممنوعه!
#define KERNEL_STACK_PROTECT    0xffffc90000000000UL  // پشته کرنل - دست نزن!
#define VSYSCALL_START          0xffffffffff600000UL   // vsyscall - ممنوع!
#define VSYSCALL_END            0xffffffffff601000UL

// توابع کمکی سازگاری - اینا کمک می‌کنن با نسخه‌های مختلف کار کنیم! 🤝
static inline void advmem_mmap_read_lock(struct mm_struct *mm) {
#ifdef HAVE_MMAP_LOCK
    mmap_read_lock(mm);  // نسخه جدید - شیک و مدرن! ✨
#else
    down_read(&mm->mmap_sem);  // نسخه قدیمی - قدیمی ولی کارساز! 🗿
#endif
}

static inline void advmem_mmap_read_unlock(struct mm_struct *mm) {
#ifdef HAVE_MMAP_LOCK
    mmap_read_unlock(mm);  // باز کردن قفل مدرن 🔓
#else
    up_read(&mm->mmap_sem);  // باز کردن قفل قدیمی 🗝️
#endif
}

static inline pte_t *advmem_pte_offset_map(pmd_t *pmd, unsigned long addr) {
#ifdef HAVE_NO_PTE_OFFSET_MAP
    return pte_offset_kernel(pmd, addr);  // کرنل 6.12+ فقط pte_offset_kernel داره
#elif defined(HAVE_PTE_OFFSET_MAP_LOCK)
    return pte_offset_map(pmd, addr);  // روش جدید - با قفل! 🔒
#else
    return pte_offset_kernel(pmd, addr);  // روش قدیمی - بدون قفل! 🚪
#endif
}

// توابع بررسی امنیت - اینا مثل گارد محافظ هستن! 🛡️

// بررسی امنیت آدرس فیزیکی - مثل چک کردن شناسنامه! 🆔
static bool is_safe_physical_address(unsigned long phys_addr, size_t size) {
    if (SAFETY_DISABLED()) {
        advmem_debug("امنیت غیرفعاله، همه چیز مجازه! 🚨");
        return true;
    }

    // سطح 1+: محافظت از نواحی حیاتی
    if (SAFETY_CHECK_LEVEL(1)) {
        if (phys_addr < CRITICAL_MEM_END) {
            advmem_err("دست به ناحیه خطرناک نزن! آدرس: 0x%lx 💀", phys_addr);
            return false;
        }
    }

    // سطح 2+: بررسی‌های اضافی
    if (SAFETY_CHECK_LEVEL(2)) {
        if (phys_addr >= 0xffffffffff000000UL) {
            advmem_err("این آدرس خیلی بالاست، ترسناکه! 0x%lx 🎢", phys_addr);
            return false;
        }
    }

    // سطح 3: حداکثر احتیاط - فقط آدرس‌های کاملاً ایمن!
    if (SAFETY_CHECK_LEVEL(3)) {
        unsigned long pfn = phys_addr >> PAGE_SHIFT;
        if (!pfn_valid(pfn)) {
            advmem_err("این PFN معتبر نیست! 0x%lx 🚫", pfn);
            return false;
        }

        struct page *page = pfn_to_page(pfn);
        if (!page || PageReserved(page) || PageSlab(page) || PageCompound(page)) {
            advmem_err("این صفحه مشکوکه! آدرس: 0x%lx 🤔", phys_addr);
            return false;
        }
    }

    advmem_debug("آدرس فیزیکی ایمنه! ✅");
    return true;
}

// بررسی امنیت آدرس مجازی - مثل کنترل پاسپورت! 🛂
static bool is_safe_virtual_address(unsigned long virt_addr, pid_t pid) {
    if (SAFETY_DISABLED()) {
        advmem_debug("حالت YOLO فعاله! 🤪");
        return true;
    }

    // سطح 1+: محافظت اولیه کرنل
    if (SAFETY_CHECK_LEVEL(1)) {
        if (virt_addr >= KERNEL_STACK_PROTECT && virt_addr < (KERNEL_STACK_PROTECT + 0x10000000000UL)) {
            advmem_err("پشته کرنل ممنوعه! 🚫 آدرس: 0x%lx", virt_addr);
            return false;
        }

        if (virt_addr >= VSYSCALL_START && virt_addr < VSYSCALL_END) {
            advmem_err("vsyscall دست نخور! 🔥 آدرس: 0x%lx", virt_addr);
            return false;
        }
    }

    // سطح 2+: بررسی پروسه
    if (SAFETY_CHECK_LEVEL(2) && pid != 0) {
        struct task_struct *task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (!task || task->flags & PF_EXITING) {
            advmem_err("پروسه معتبر نیست یا داره می‌میره! PID: %d 💀", pid);
            return false;
        }
    }

    // سطح 3: سختگیری کامل!
    if (SAFETY_CHECK_LEVEL(3)) {
        if (pid == 0 && virt_addr < PAGE_OFFSET) {
            advmem_err("آدرس کرنل معتبر نیست! 0x%lx ⚠️", virt_addr);
            return false;
        }
    }

    advmem_debug("آدرس مجازی قبوله! 👍");
    return true;
}

// دریافت حداکثر اندازه امن - بسته به سطح امنیت! 📏
static size_t get_safe_max_size(void) {
    if (SAFETY_DISABLED()) {
        advmem_debug("بدون محدودیت! 🚀");
        return BUFFER_SIZE;
    }

    switch (safe_mode) {
        case 1: 
            advmem_debug("سطح 1: %d بایت مجاز", SAFE_MAX_SIZE_LEVEL1);
            return SAFE_MAX_SIZE_LEVEL1;
        case 2: 
            advmem_debug("سطح 2: %d بایت مجاز", SAFE_MAX_SIZE_LEVEL2);
            return SAFE_MAX_SIZE_LEVEL2;
        case 3: 
            advmem_debug("سطح 3: %d بایت مجاز", SAFE_MAX_SIZE_LEVEL3);
            return SAFE_MAX_SIZE_LEVEL3;
        default: 
            return BUFFER_SIZE;
    }
}

// بررسی اندازه عملیات - نه خیلی کم، نه خیلی زیاد! ⚖️
static bool is_safe_operation_size(size_t size) {
    if (SAFETY_DISABLED()) return (size <= BUFFER_SIZE);

    size_t max_size = get_safe_max_size();
    if (size > max_size) {
        advmem_err("اندازه %zu خیلی زیاده! حداکثر %zu (سطح %d) 📏", 
                   size, max_size, safe_mode);
        return false;
    }

    advmem_debug("اندازه مناسبه! 👌");
    return true;
}

// تعریف توابع - اینا کارهای اصلی رو انجام می‌دن! 🔧
static int device_open(struct inode*, struct file*);
static int device_release(struct inode*, struct file*);
static long device_ioctl(struct file*, unsigned int, unsigned long);
static int read_physical_memory(unsigned long phys_addr, void* buffer, size_t size);
static int write_physical_memory(unsigned long phys_addr, const void* buffer, size_t size);
static unsigned long virtual_to_physical_addr(unsigned long virt_addr, pid_t pid);
static unsigned long physical_to_virtual_addr(unsigned long phys_addr, pid_t pid);
static int get_page_information(unsigned long addr, struct page_info *info);



// عملیات فایل - این جدول مثل فهرست تلفن توابع هست! 📞
static struct file_operations fops = {
    .open = device_open,
    .release = device_release,
    .unlocked_ioctl = device_ioctl,
};

// خواندن حافظه فیزیکی - مثل خواندن کتاب از کتابخونه! 📚
static int read_physical_memory(unsigned long phys_addr, void* buffer, size_t size) {
    void __iomem *mapped_addr;
    struct page *page;
    unsigned long pfn, start_pfn, end_pfn;
    size_t bytes_read = 0;
    size_t chunk_size;
    unsigned long current_addr = phys_addr;
    char *buf_ptr = (char *)buffer;

    if (!buffer || size == 0) {
        advmem_err("پارامترهای خواندن اشتباهن! buffer=%p, size=%zu 🤦", buffer, size);
        return -EINVAL;
    }

    // بررسی‌های امنیتی - مثل گذرنامه چک کردن! 🛂
    if (!is_safe_operation_size(size)) {
        advmem_err("اندازه غیرمجازه! 🚫");
        return -EINVAL;
    }

    if (!is_safe_physical_address(phys_addr, size)) {
        advmem_err("آدرس خطرناکه! 💀");
        return -EPERM;
    }

    start_pfn = phys_addr >> PAGE_SHIFT;
    end_pfn = (phys_addr + size - 1) >> PAGE_SHIFT;

    advmem_debug("خواندن %zu بایت از 0x%lx (%lu صفحه) 📖", 
                 size, phys_addr, end_pfn - start_pfn + 1);

    // پردازش هر صفحه - یکی یکی بررسی می‌کنیم! 🔍
    while (bytes_read < size) {
        pfn = current_addr >> PAGE_SHIFT;

        // بررسی معتبر بودن آدرس فیزیکی
        if (!pfn_valid(pfn)) {
            advmem_err("آدرس فیزیکی معتبر نیست: 0x%lx (PFN: %lx) 💥", current_addr, pfn);
            return -EINVAL;
        }

        // دریافت ساختار صفحه
        page = pfn_to_page(pfn);
        if (!page) {
            advmem_err("نمی‌تونم صفحه رو پیدا کنم! PFN: %lx 🕵️", pfn);
            return -EINVAL;
        }

        // بررسی‌های اضافی امنیت
        if (PageReserved(page)) {
            advmem_debug("خواندن از صفحه رزرو شده! PFN: %lx ⚠️", pfn);
        }

        // محاسبه اندازه chunk برای این صفحه
        chunk_size = min(size - bytes_read, PAGE_SIZE - (current_addr & ~PAGE_MASK));

        // نگاشت آدرس فیزیکی - مثل دریافت نقشه! 🗺️
        mapped_addr = ioremap(current_addr, chunk_size);
        if (!mapped_addr) {
            advmem_err("نگاشت آدرس فیزیکی شکست خورد: 0x%lx 😵", current_addr);
            return -ENOMEM;
        }

        // کپی کردن داده از حافظه فیزیکی - عمل جادو! ✨
        memcpy_fromio(buf_ptr + bytes_read, mapped_addr, chunk_size);
        iounmap(mapped_addr);  // آزادسازی نگاشت

        bytes_read += chunk_size;
        current_addr += chunk_size;
    }

    advmem_info("موفقیت! %zu بایت از 0x%lx خونده شد! 🎉", size, phys_addr);
    return 0;
}

// نوشتن حافظه فیزیکی - مثل نوشتن تو دفتر! ✍️
static int write_physical_memory(unsigned long phys_addr, const void* buffer, size_t size) {
    void __iomem *mapped_addr;
    struct page *page;
    unsigned long pfn, start_pfn, end_pfn;
    size_t bytes_written = 0;
    size_t chunk_size;
    unsigned long current_addr = phys_addr;
    const char *buf_ptr = (const char *)buffer;

    if (!buffer || size == 0) {
        advmem_err("پارامترهای نوشتن اشتباهن! buffer=%p, size=%zu 🤷", buffer, size);
        return -EINVAL;
    }

    // بررسی‌های امنیتی - برای نوشتن سختگیری بیشتری می‌کنیم! 🔒
    if (!is_safe_operation_size(size)) {
        advmem_err("اندازه نامناسب برای نوشتن! 🚨");
        return -EINVAL;
    }

    if (!is_safe_physical_address(phys_addr, size)) {
        advmem_err("آدرس برای نوشتن خطرناکه! ☠️");
        return -EPERM;
    }

    // امنیت اضافی برای عملیات نوشتن
    if (SAFETY_CHECK_LEVEL(2)) {
        if (phys_addr < CRITICAL_MEM_END * 2) {
            advmem_err("نوشتن تو ناحیه حیاتی ممنوع! آدرس: 0x%lx 🛑", phys_addr);
            return -EPERM;
        }
    }

    start_pfn = phys_addr >> PAGE_SHIFT;
    end_pfn = (phys_addr + size - 1) >> PAGE_SHIFT;

    advmem_debug("نوشتن %zu بایت به 0x%lx (%lu صفحه) ✍️", 
                 size, phys_addr, end_pfn - start_pfn + 1);

    // پردازش هر صفحه - دقت کامل! 🎯
    while (bytes_written < size) {
        pfn = current_addr >> PAGE_SHIFT;

        if (!pfn_valid(pfn)) {
            advmem_err("آدرس فیزیکی معتبر نیست: 0x%lx (PFN: %lx) 💀", current_addr, pfn);
            return -EINVAL;
        }

        page = pfn_to_page(pfn);
        if (!page) {
            advmem_err("صفحه پیدا نشد! PFN: %lx 👻", pfn);
            return -EINVAL;
        }

        // بررسی‌های امنیتی پیشرفته - فقط اگه امنیت فعال باشه
        if (!SAFETY_DISABLED()) {
            if (PageReserved(page)) {
                advmem_err("نوشتن تو صفحه رزرو ممنوع! PFN: %lx 🚫", pfn);
                return -EPERM;
            }

            if (PageLocked(page)) {
                advmem_err("صفحه قفله، نمی‌شه نوشت! PFN: %lx 🔐", pfn);
                return -EBUSY;
            }

            // سطح 3: بررسی‌های اضافی
            if (SAFETY_CHECK_LEVEL(3)) {
                if (PageSlab(page) || PageCompound(page) || PageAnon(page)) {
                    advmem_err("نوع صفحه امن نیست! PFN: %lx 🤨", pfn);
                    return -EPERM;
                }
            }
        }

        chunk_size = min(size - bytes_written, PAGE_SIZE - (current_addr & ~PAGE_MASK));

        // نگاشت آدرس فیزیکی با مجوز نوشتن
        mapped_addr = ioremap(current_addr, chunk_size);
        if (!mapped_addr) {
            advmem_err("نگاشت برای نوشتن شکست خورد: 0x%lx 😞", current_addr);
            return -ENOMEM;
        }

        // کپی کردن داده به حافظه فیزیکی - حالا رفت تو حافظه! 🚀
        memcpy_toio(mapped_addr, buf_ptr + bytes_written, chunk_size);

        // اطمینان از نوشته شدن داده - force write! 💪
        wmb();
        iounmap(mapped_addr);

        bytes_written += chunk_size;
        current_addr += chunk_size;
    }

    advmem_info("عالی! %zu بایت به 0x%lx نوشته شد! 🏆", size, phys_addr);
    return 0;
}

// تبدیل آدرس مجازی به فیزیکی - مثل GPS برای حافظه! 🧭
static unsigned long virtual_to_physical_addr(unsigned long virt_addr, pid_t pid) {
    struct task_struct *task;
    struct mm_struct *mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    unsigned long phys_addr = 0;

    // بررسی امنیت آدرس مجازی
    if (!is_safe_virtual_address(virt_addr, pid)) {
        advmem_err("آدرس مجازی امن نیست! 🚨");
        return 0;
    }

    if (pid == 0) {
        // آدرس کرنل - ترجمه مستقیم اگه ممکن باشه
        if (virt_addr >= PAGE_OFFSET) {
            phys_addr = virt_to_phys((void*)virt_addr);
            advmem_debug("ترجمه مستقیم کرنل: 0x%lx → 0x%lx 🔄", virt_addr, phys_addr);
            return phys_addr;
        }
        mm = current->mm;
    } else {
        // آدرس پروسه کاربری
        task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (!task) {
            advmem_err("پروسه %d پیدا نشد! 🕵️", pid);
            return 0;
        }
        mm = task->mm;
    }

    if (!mm) {
        advmem_err("ساختار مدیریت حافظه موجود نیست! 🤷");
        return 0;
    }

    // قفل کردن mm برای خواندن
    advmem_mmap_read_lock(mm);

    // راه رفتن تو جدول صفحه - مثل پیمایش یه ساختمان! 🏢
    pgd = pgd_offset(mm, virt_addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        advmem_debug("سطح PGD موجود نیست! 🚪");
        goto out;
    }

    p4d = p4d_offset(pgd, virt_addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        advmem_debug("سطح P4D موجود نیست! 🚪");
        goto out;
    }

    pud = pud_offset(p4d, virt_addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        advmem_debug("سطح PUD موجود نیست! 🚪");
        goto out;
    }

    pmd = pmd_offset(pud, virt_addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        advmem_debug("سطح PMD موجود نیست! 🚪");
        goto out;
    }

    pte = advmem_pte_offset_map(pmd, virt_addr);
    if (!pte || pte_none(*pte)) {
        advmem_debug("سطح PTE موجود نیست! 🚪");
#if defined(HAVE_PTE_OFFSET_MAP_LOCK) && !defined(HAVE_NO_PTE_OFFSET_MAP)
        if (pte) pte_unmap(pte);
#endif
        goto out;
    }

    // بررسی حضور صفحه
    if (pte_present(*pte)) {
        phys_addr = (pte_pfn(*pte) << PAGE_SHIFT) + (virt_addr & ~PAGE_MASK);

        // بررسی امنیت آدرس ترجمه شده
        if (!SAFETY_DISABLED() && !is_safe_physical_address(phys_addr, PAGE_SIZE)) {
            advmem_err("آدرس ترجمه شده امن نیست! 0x%lx ⚠️", phys_addr);
            phys_addr = 0;
        } else {
            advmem_debug("ترجمه موفق: 0x%lx → 0x%lx ✅", virt_addr, phys_addr);
        }
    }

#if defined(HAVE_PTE_OFFSET_MAP_LOCK) && !defined(HAVE_NO_PTE_OFFSET_MAP)
    pte_unmap(pte);
#endif

out:
    advmem_mmap_read_unlock(mm);
    return phys_addr;
}

// تبدیل آدرس فیزیکی به مجازی - کار سخته! 😅
static unsigned long physical_to_virtual_addr(unsigned long phys_addr, pid_t pid) {
    unsigned long virt_addr = 0;

    advmem_debug("تلاش برای ترجمه فیزیکی به مجازی: 0x%lx 🔄", phys_addr);

    // برای آدرس‌های کرنل، نگاشت مستقیم رو امتحان می‌کنیم
    if (pfn_valid(phys_addr >> PAGE_SHIFT)) {
        virt_addr = (unsigned long)phys_to_virt(phys_addr);

        // تایید ترجمه - مطمئن می‌شیم که برعکسش هم کار می‌کنه!
        if (virt_to_phys((void*)virt_addr) == phys_addr) {
            advmem_debug("ترجمه معکوس موفق! 0x%lx → 0x%lx ✅", phys_addr, virt_addr);
            return virt_addr;
        }
    }

    // برای فضای کاربری، باید همه VMA ها رو اسکن کنیم که خیلی گرونه!
    // این یه محدودیت اساسیه - نگاشت فیزیکی به مجازی یکتا نیست!
    advmem_info("ترجمه فیزیکی به مجازی محدودیت داره! 🤔");
    return 0;
}

// دریافت اطلاعات صفحه - مثل گرفتن شناسنامه صفحه! 📄
static int get_page_information(unsigned long addr, struct page_info *info) {
    struct mm_struct *mm = current->mm;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    // پاک کردن اطلاعات - شروع تمیز! 🧹
    memset(info, 0, sizeof(*info));
    info->addr = addr;

    if (!mm) {
        // آدرس کرنل
        if (addr >= PAGE_OFFSET) {
            info->page_frame = virt_to_phys((void*)addr) >> PAGE_SHIFT;
            info->present = 1;
            info->writable = 1;
            info->user = 0;
            advmem_debug("اطلاعات آدرس کرنل برگردونده شد! 🎯");
            return 0;
        }
        advmem_err("آدرس کرنل معتبر نیست! 🚫");
        return -EINVAL;
    }

    // بررسی امنیت آدرس
    if (!is_safe_virtual_address(addr, 0)) {
        advmem_err("آدرس برای دریافت اطلاعات امن نیست! ⚠️");
        return -EPERM;
    }

    advmem_mmap_read_lock(mm);

    // پیمایش جدول صفحه - گام به گام! 👣
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) {
        advmem_debug("PGD پیدا نشد! 🔍");
        goto out;
    }

    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        advmem_debug("P4D پیدا نشد! 🔍");
        goto out;
    }

    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) {
        advmem_debug("PUD پیدا نشد! 🔍");
        goto out;
    }

    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) {
        advmem_debug("PMD پیدا نشد! 🔍");
        goto out;
    }

    pte = advmem_pte_offset_map(pmd, addr);
    if (!pte || pte_none(*pte)) {
        advmem_debug("PTE پیدا نشد! 🔍");
#if defined(HAVE_PTE_OFFSET_MAP_LOCK) && !defined(HAVE_NO_PTE_OFFSET_MAP)
        if (pte) pte_unmap(pte);
#endif
        goto out;
    }

    // استخراج اطلاعات صفحه - همه چیز رو می‌گیریم! 🕵️
    info->present = pte_present(*pte);       // حاضر و آماده؟
    info->writable = pte_write(*pte);        // قابل نوشتن؟
#ifdef HAVE_NO_PTE_USER
    // در کرنل‌های جدید pte_user حذف شده، از fallback استفاده می‌کنیم
    info->user = pte_user(*pte);             // کاربری؟ (with fallback)
#else
    info->user = pte_user(*pte);             // کاربری؟
#endif
    info->accessed = pte_young(*pte);        // اخیراً استفاده شده؟
    info->dirty = pte_dirty(*pte);           // تغییر کرده؟
    info->page_frame = pte_pfn(*pte);        // شماره فریم
    info->flags = pte_val(*pte);             // همه پرچم‌ها

    advmem_debug("اطلاعات صفحه جمع‌آوری شد! 📊");

#if defined(HAVE_PTE_OFFSET_MAP_LOCK) && !defined(HAVE_NO_PTE_OFFSET_MAP)
    pte_unmap(pte);
#endif

out:
    advmem_mmap_read_unlock(mm);
    return 0;
}



// تابع اصلی IOCTL - دل برنامه! ❤️
static long device_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    // استفاده از pointer برای کاهش stack usage
    struct mem_operation *mem_op = NULL;
    struct addr_translation *addr_trans = NULL;
    struct page_info *page_inf = NULL;
    
    int ret = 0;

    // بررسی امنیتی: نیاز به مجوز CAP_SYS_ADMIN
    if (!capable(CAP_SYS_ADMIN)) {
        advmem_err("دسترسی مردود! نیاز به مجوز CAP_SYS_ADMIN! 🛡️");
        return -EPERM;
    }

    // بررسی معتبر بودن pointer کاربر
    if (!arg) {
        advmem_err("pointer نامعتبر! 🚫");
        return -EINVAL;
    }

    // گرفتن mutex برای thread safety - یکی یکی! 🔄
    if (mutex_lock_interruptible(&advmem_mutex)) {
        advmem_debug("IOCTL هنگام انتظار برای mutex قطع شد! 😵");
        return -ERESTARTSYS;
    }

    advmem_debug("دستور IOCTL: 0x%x - بریم ببینیم چیه! 👀", cmd);

    switch (cmd) {
        case IOCTL_READ_PHYS_MEM:
            advmem_debug("درخواست خواندن حافظه فیزیکی! 📖");
            mem_op = kmalloc(sizeof(*mem_op), GFP_KERNEL);
            if (!mem_op) {
                ret = -ENOMEM;
                break;
            }
            
            if (copy_from_user(mem_op, (void*)arg, sizeof(*mem_op))) {
                advmem_err("کپی از کاربر شکست خورد! 😞");
                ret = -EFAULT;
                kfree(mem_op);
                break;
            }

            ret = read_physical_memory(mem_op->phys_addr, mem_op->data, mem_op->size);
            mem_op->result = ret;

            if (copy_to_user((void*)arg, mem_op, sizeof(*mem_op))) {
                advmem_err("کپی به کاربر شکست خورد! 😞");
                ret = -EFAULT;
            }
            kfree(mem_op);
            break;

        case IOCTL_WRITE_PHYS_MEM:
            advmem_debug("درخواست نوشتن حافظه فیزیکی! ✍️");
            mem_op = kmalloc(sizeof(*mem_op), GFP_KERNEL);
            if (!mem_op) {
                ret = -ENOMEM;
                break;
            }
            
            if (copy_from_user(mem_op, (void*)arg, sizeof(*mem_op))) {
                ret = -EFAULT;
                kfree(mem_op);
                break;
            }

            ret = write_physical_memory(mem_op->phys_addr, mem_op->data, mem_op->size);
            mem_op->result = ret;

            if (copy_to_user((void*)arg, mem_op, sizeof(*mem_op))) {
                ret = -EFAULT;
            }
            kfree(mem_op);
            break;

        case IOCTL_VIRT_TO_PHYS:
            advmem_debug("درخواست تبدیل مجازی به فیزیکی! 🔄");
            addr_trans = kmalloc(sizeof(*addr_trans), GFP_KERNEL);
            if (!addr_trans) {
                ret = -ENOMEM;
                break;
            }
            
            if (copy_from_user(addr_trans, (void*)arg, sizeof(*addr_trans))) {
                ret = -EFAULT;
                kfree(addr_trans);
                break;
            }

            addr_trans->output_addr = virtual_to_physical_addr(addr_trans->input_addr, addr_trans->pid);
            addr_trans->success = (addr_trans->output_addr != 0);

            if (copy_to_user((void*)arg, addr_trans, sizeof(*addr_trans))) {
                ret = -EFAULT;
            } else {
                ret = 0;  // موفقیت در IOCTL
            }
            kfree(addr_trans);
            break;

        case IOCTL_PHYS_TO_VIRT:
            advmem_debug("درخواست تبدیل فیزیکی به مجازی! 🔄");
            addr_trans = kmalloc(sizeof(*addr_trans), GFP_KERNEL);
            if (!addr_trans) {
                ret = -ENOMEM;
                break;
            }
            
            if (copy_from_user(addr_trans, (void*)arg, sizeof(*addr_trans))) {
                ret = -EFAULT;
                kfree(addr_trans);
                break;
            }

            addr_trans->output_addr = physical_to_virtual_addr(addr_trans->input_addr, addr_trans->pid);
            addr_trans->success = (addr_trans->output_addr != 0);

            if (copy_to_user((void*)arg, addr_trans, sizeof(*addr_trans))) {
                ret = -EFAULT;
            } else {
                ret = 0;
            }
            kfree(addr_trans);
            break;

        case IOCTL_GET_PAGE_INFO:
            advmem_debug("درخواست اطلاعات صفحه! 📄");
            page_inf = kmalloc(sizeof(*page_inf), GFP_KERNEL);
            if (!page_inf) {
                ret = -ENOMEM;
                break;
            }
            
            if (copy_from_user(page_inf, (void*)arg, sizeof(*page_inf))) {
                ret = -EFAULT;
                kfree(page_inf);
                break;
            }

            ret = get_page_information(page_inf->addr, page_inf);

            if (copy_to_user((void*)arg, page_inf, sizeof(*page_inf))) {
                ret = -EFAULT;
            }
            kfree(page_inf);
            break;



        default:
            advmem_err("دستور IOCTL ناشناخته: 0x%x 🤔", cmd);
            ret = -EINVAL;
            break;
    }

    // آزادسازی mutex - کار تموم شد! 🔓
    mutex_unlock(&advmem_mutex);
    return ret;
}

// باز کردن دستگاه - سلام گفتن! 👋
static int device_open(struct inode *inodep, struct file *filep) {
    advmem_info("دستگاه توسط PID %d باز شد (UID: %u) 🚪", 
                current->pid, from_kuid_munged(current_user_ns(), current_uid()));
    return 0;
}

// بستن دستگاه - خداحافظ! 👋
static int device_release(struct inode *inodep, struct file *filep) {
    advmem_info("دستگاه توسط PID %d بسته شد 🚪", current->pid);
    return 0;
}

// راه‌اندازی ماژول - تولد! 🎂
static int __init advmem_init(void) {
    advmem_info("راه‌اندازی ماژول کرنل Advanced Memory Toolkit! 🚀");
    advmem_info("نسخه کرنل: %s (کامپایل شده برای %d.%d.%d) 🐧", 
                advmem_utsname()->release, 
                LINUX_VERSION_CODE >> 16,
                (LINUX_VERSION_CODE >> 8) & 0xff,
                LINUX_VERSION_CODE & 0xff);
    advmem_info("سطح debug: %d (0=خطاها، 1=اطلاعات، 2=debug) 🐛", debug_level);
    advmem_info("حالت امن: %d (0=غیرفعال، 1=پایه، 2=متوسط، 3=حداکثر) 🛡️", safe_mode);

    if (SAFETY_DISABLED()) {
        advmem_info("⚠️  هشدار: حالت امن غیرفعاله - هیچ محافظتی نیست! 💀");
    } else {
        advmem_info("🛡️  حالت امن فعاله - حداکثر اندازه عملیات: %zu بایت", get_safe_max_size());
    }

#ifdef CRYPTO_NOT_AVAILABLE
    advmem_info("🔒 توجه: Crypto در این نسخه کرنل در دسترس نیست!");
#endif

    // راه‌اندازی mutex - قفل جادویی! 🔮
    mutex_init(&advmem_mutex);

    // ثبت character device - اعلام حضور! 📢
    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        advmem_err("ثبت character device شکست خورد: %d 💥", major_number);
        return major_number;
    }

    // ایجاد کلاس دستگاه - ساخت خانواده! 👨‍👩‍👧‍👦
#ifdef HAVE_NEW_CLASS_CREATE
    advmem_class = class_create(CLASS_NAME);
#else
    advmem_class = class_create(THIS_MODULE, CLASS_NAME);
#endif
    if (IS_ERR(advmem_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        advmem_err("ایجاد کلاس دستگاه شکست خورد: %ld 😞", PTR_ERR(advmem_class));
        return PTR_ERR(advmem_class);
    }

    // ایجاد دستگاه - متولد شدن! 👶
    advmem_device = device_create(advmem_class, NULL, 
                                MKDEV(major_number, 0), NULL, DEVICE_NAME);
    if (IS_ERR(advmem_device)) {
        class_destroy(advmem_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        advmem_err("ایجاد دستگاه شکست خورد: %ld 😭", PTR_ERR(advmem_device));
        return PTR_ERR(advmem_device);
    }

    advmem_info("ماژول با موفقیت بارگذاری شد! (شماره اصلی: %d) 🎉", major_number);
    advmem_info("دستگاه: /dev/%s 📱", DEVICE_NAME);
    advmem_info("امنیت: نیاز به مجوز CAP_SYS_ADMIN 🔐");
    advmem_info("آماده انجام ماموریت‌های خطرناک! 😎");
    return 0;
}

// خروج ماژول - خداحافظی! 😢
static void __exit advmem_exit(void) {
    // تمیزکاری به ترتیب معکوس - مثل جمع کردن اسباب‌بازی! 🧹
    if (advmem_device) {
        device_destroy(advmem_class, MKDEV(major_number, 0));
        advmem_debug("دستگاه حذف شد! 🗑️");
    }

    if (advmem_class) {
        class_unregister(advmem_class);
        class_destroy(advmem_class);
        advmem_debug("کلاس حذف شد! 🗑️");
    }

    if (major_number > 0) {
        unregister_chrdev(major_number, DEVICE_NAME);
        advmem_debug("character device لغو ثبت شد! 🗑️");
    }

    // اطمینان از عدم وجود عملیات در حال انتظار
    mutex_destroy(&advmem_mutex);

    advmem_info("ماژول Advanced Memory Toolkit با ایمنی حذف شد! 👋");
    advmem_info("تا دیدار دوباره! 🌟");
}

// معرفی ماژول به کرنل
module_init(advmem_init);   // تولد! 🎂
module_exit(advmem_exit);   // مرگ! ⚰️

// اطلاعات ماژول - شناسنامه! 🆔
MODULE_LICENSE("GPL");      // مجوز آزاد - همه می‌تونن استفاده کنن! 🆓
MODULE_AUTHOR("mohammad_amin"); // منم دیگه
MODULE_DESCRIPTION("AMT-Toolkit");
MODULE_VERSION("3.1");      // نسخه جدید، باگ‌های کمتر! 🐛➡️✨

// پایان کد - تمام! 🏁
// امیدوارم این کد کارتون رو راه بندازه و سیستم‌تون کرش نکنه! 😅
// اگه کرش کرد، یادتون باشه من هشدار داده بودم! 🤭
