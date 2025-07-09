
# Advanced Memory Toolkit (AMT)

🔬 **ابزار پیشرفته مدیریت حافظه سطح کرنل** - فریمورک قدرتمند برای عملیات حافظه فیزیکی

## ویژگی‌های کلیدی 🚀

### 🔧 قابلیت‌های اصلی:
1. **خواندن/نوشتن حافظه فیزیکی** - دسترسی مستقیم به حافظه فیزیکی با امنیت بالا
2. **تبدیل آدرس** - تبدیل آدرس مجازی به فیزیکی و بالعکس
3. **تحلیل صفحات** - اطلاعات تفصیلی درباره صفحات حافظه
4. **رمزنگاری حافظه** - رمزنگاری/رمزگشایی با الگوریتم‌های AES-256 و ChaCha20
5. **امنیت پیشرفته** - محافظت CAP_SYS_ADMIN و چک‌های امنیتی

### 🏗️ معماری:
- **کرنل درایور (C)**: عملیات سطح کرنل با امنیت بالا
- **Python Interface**: رابط کاربری آسان و قدرتمند
- **IOCTL Commands**: ارتباط ایمن و بهینه
- **Multi-threading Safety**: پشتیبانی از mutex و thread safety

## نصب و راه‌اندازی ⚡

### پیش‌نیازهای سیستم:
```bash
sudo apt update
sudo apt install linux-headers-$(uname -r) build-essential python3 python3-pip
```

### نصب خودکار:
```bash
sudo bash setup.sh
```

### نصب دستی:

1. **ساخت ماژول کرنل:**
```bash
make -f driver_Makefile clean
make -f driver_Makefile
```

2. **بارگذاری ماژول:**
```bash
sudo insmod memory_driver.ko
sudo chmod 666 /dev/advanced_memory
```

3. **تست عملکرد:**
```bash
sudo python3 test_toolkit.py
```

## IOCTL Commands 📋

### 1. IOCTL_READ_PHYS_MEM (0x80006D01)
**کاربرد:** خواندن داده از آدرس فیزیکی
**پارامترها:**
- `phys_addr`: آدرس فیزیکی
- `size`: اندازه داده (حداکثر 8192 بایت)
- `data`: بافر خروجی

**امنیت:** چک pfn_valid، PageReserved، multi-page support

### 2. IOCTL_WRITE_PHYS_MEM (0x40006D02)
**کاربرد:** نوشتن داده به آدرس فیزیکی
**پارامترها:**
- `phys_addr`: آدرس فیزیکی مقصد
- `data`: داده ورودی
- `size`: اندازه داده

**امنیت:** محافظت از صفحات reserved/locked، memory barrier

### 3. IOCTL_VIRT_TO_PHYS (0xC0106D03)
**کاربرد:** تبدیل آدرس مجازی به فیزیکی
**پارامترها:**
- `input_addr`: آدرس مجازی
- `pid`: شناسه پروسه (0 برای کرنل)
- `output_addr`: آدرس فیزیکی خروجی

**عملکرد:** Page table walking با پشتیبانی کامل 5-level

### 4. IOCTL_PHYS_TO_VIRT (0xC0106D04)
**کاربرد:** تبدیل آدرس فیزیکی به مجازی (محدود)
**هشدار:** این عملیات محدودیت‌های اساسی دارد

### 5. IOCTL_GET_PAGE_INFO (0xC0186D05)
**کاربرد:** دریافت اطلاعات تفصیلی صفحه
**اطلاعات:**
- Page frame number
- Present/Writable/User flags
- Access/Dirty bits
- Protection flags

### 6. IOCTL_ENCRYPT_MEMORY (0xC0236D06)
**کاربرد:** رمزنگاری ناحیه حافظه
**الگوریتم‌ها:**
- AES-256-CBC (algorithm=0)
- ChaCha20 (algorithm=1)

**ویژگی‌ها:**
- PKCS#7 padding
- Random IV generation
- Secure key handling

### 7. IOCTL_DECRYPT_MEMORY (0xC0236D07)
**کاربرد:** رمزگشایی ناحیه حافظه
**ویژگی‌ها:**
- Padding validation
- IV management
- Secure memory clearing

## راهنمای استفاده 🌟

### 1. خواندن حافظه فیزیکی:
```python
from memory_toolkit import AdvancedMemoryToolkit

amt = AdvancedMemoryToolkit()
data = amt.read_physical_memory(0x1000, 256)
if data:
    print(f"Read {len(data)} bytes")
```

### 2. نوشتن حافظه فیزیکی:
```python
test_data = b"Hello, Memory!"
success = amt.write_physical_memory(0x1000, test_data)
if success:
    print("Write successful")
```

### 3. تبدیل آدرس:
```python
phys_addr = amt.virtual_to_physical(0x7fff12345000)
if phys_addr:
    print(f"Physical address: 0x{phys_addr:x}")
```

### 4. تحلیل صفحه:
```python
page_info = amt.get_page_info(0x1000)
if page_info:
    print(f"Page present: {page_info['present']}")
    print(f"Page writable: {page_info['writable']}")
```

### 5. رمزنگاری:
```python
key = b"SecretKey123456789012345678901234"  # 32 bytes
encrypted = amt.encrypt_memory(0x1000, 256, key, 'aes')
if encrypted:
    print("Encryption successful")
```

## امنیت و محدودیت‌ها ⚠️

### الزامات امنیتی:
- **CAP_SYS_ADMIN**: مجوز مدیریت سیستم الزامی
- **Root Access**: اجرا با دسترسی root
- **Kernel Module**: بارگذاری ماژول کرنل

### محدودیت‌ها:
- **Buffer Size**: حداکثر 8192 بایت در هر عملیات
- **Physical Memory**: فقط آدرس‌های معتبر فیزیکی
- **Thread Safety**: یک عملیات همزمان (mutex protected)

### هشدارهای حیاتی:
- **⚠️ کاربرد در محیط تولید ممنوع**
- **⚠️ تغییرات غیرقابل بازگشت ممکن**
- **⚠️ تأثیر بر پایداری سیستم**
- **⚠️ نیاز به backup کامل**

## Debug و Troubleshooting 🔧

### Debug Levels:
```bash
# تنظیم سطح debug
echo 2 > /sys/module/memory_driver/parameters/debug_level
```

**سطوح:**
- 0: فقط خطاها
- 1: اطلاعات عمومی
- 2: اطلاعات تفصیلی debug

### بررسی لاگ‌ها:
```bash
# لاگ‌های کرنل
dmesg | grep -i "advanced memory"

# وضعیت ماژول
lsmod | grep memory_driver

# اطلاعات دستگاه
ls -la /dev/advanced_memory
```

### خطاهای رایج:
- **Permission denied**: نیاز به CAP_SYS_ADMIN
- **Invalid address**: آدرس فیزیکی نامعتبر
- **Buffer too large**: اندازه بیش از 8192 بایت
- **Memory allocation failed**: کمبود حافظه کرنل

## Performance و Optimization 🚀

### بهینه‌سازی عملکرد:
```bash
# تنظیم memory compaction
echo 1 > /proc/sys/vm/compact_memory

# Clear page cache
echo 3 > /proc/sys/vm/drop_caches
```

### نظارت عملکرد:
```bash
# استفاده از حافظه
cat /proc/meminfo | grep -E "MemTotal|MemFree|MemAvailable"

# آمار عملیات
cat /proc/modules | grep memory_driver
```

## مثال‌های پیشرفته 🔬

### 1. Memory Forensics:
```python
# اسکن برای یافتن الگوهای خاص
for addr in range(0x1000, 0x10000, 0x1000):
    data = amt.read_physical_memory(addr, 1024)
    if data and b"kernel" in data:
        print(f"Found kernel signature at 0x{addr:x}")
```

### 2. Secure Memory Operations:
```python
# رمزنگاری امن داده‌های حساس
sensitive_data = b"TOP_SECRET_INFORMATION"
key = os.urandom(32)
iv = os.urandom(16)

# پشتیبان‌گیری
backup = amt.read_physical_memory(0x1000, len(sensitive_data))

# رمزنگاری
if amt.encrypt_memory(0x1000, len(sensitive_data), key, 'aes', iv):
    print("Data encrypted successfully")
```

### 3. System Analysis:
```python
# تحلیل جامع صفحات حافظه
def analyze_memory_region(start, end):
    for addr in range(start, end, 0x1000):
        info = amt.get_page_info(addr)
        if info and info['present']:
            print(f"Page 0x{addr:x}: PFN={info['page_frame']}, "
                  f"W={info['writable']}, U={info['user']}")
```

## Testing Framework 🧪

### تست‌های خودکار:
```bash
# اجرای تست‌های کامل
sudo python3 test_toolkit.py

# تست عملکرد
sudo python3 test_toolkit.py --performance

# تست امنیت
sudo python3 test_toolkit.py --security
```

### تست دستی:
```bash
# تست IOCTL commands
sudo python3 -c "
from memory_toolkit import AdvancedMemoryToolkit
amt = AdvancedMemoryToolkit()
amt.test_basic_operations()
"
```

## نسخه و مجوز 📄

**Advanced Memory Toolkit v3.0**
- مجوز: GPL v3
- توسعه‌دهنده: Advanced Memory Development Team
- تاریخ: 2024

### تغییرات نسخه 3.0:
- رفع مشکل mutex unlocking
- بهبود امنیت و error handling
- پشتیبانی multi-page operations
- رمزنگاری پیشرفته با AES/ChaCha20
- مستندات کامل

## پشتیبانی 🤝

برای پشتیبانی فنی، باگ‌ها و پیشنهادات:
- مشکلات را با جزئیات گزارش دهید
- لاگ‌های مربوطه را ضمیمه کنید
- نسخه کرنل و توزیع را مشخص کنید

---

**⚡ Advanced Memory Toolkit - Professional Memory Operations**
