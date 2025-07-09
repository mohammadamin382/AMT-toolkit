
# 🚀 Advanced Memory Toolkit - راهنمای کاربری جامع 

**نسخه 3.1**

---

## 📋 فهرست مطالب

1. [معرفی کلی](#معرفی-کلی) 🌟
2. [نصب و راه‌اندازی](#نصب-و-راهاندازی) ⚡
3. [نکات ایمنی](#نکات-ایمنی) ⚠️
4. [ساختار پروژه](#ساختار-پروژه) 📁
5. [راهنمای استفاده](#راهنمای-استفاده) 🛠️
6. [API Reference](#api-reference) 📚
7. [مثال‌های عملی](#مثالهای-عملی) 💡
8. [عیب‌یابی](#عیبیابی) 🐛
9. [سؤالات متداول](#سؤالات-متداول) ❓
10. [مشارکت در پروژه](#مشارکت-در-پروژه) 🤝

---

## 🌟 معرفی کلی

خوش اومدید به **AMT-Toolkit**! 🎉

این پروژه یه ابزار فوق‌العاده قدرتمند برای کار با حافظه سطح کرنل هست که:

- 🔍 **حافظه فیزیکی رو می‌خونه و می‌نویسه** (مثل یه هکر حرفه‌ای!)
- 🔄 **آدرس مجازی رو به فیزیکی تبدیل می‌کنه** (و برعکس!)
- 📊 **اطلاعات تفصیلی صفحات حافظه رو میده**
- 🔐 **رمزنگاری حافظه** (البته ساده!)
- 🛡️ **سطوح مختلف امنیت** (از YOLO تا paranoid!)

### 🎯 مخاطب

این ابزار برای شماست اگر:
- 👨‍💻 توسعه‌دهنده کرنل هستید
- 🔬 محقق امنیت هستید  
- 🎓 دانشجو و می‌خواید یاد بگیرید
- 😈 کنجکاو هستید و دوست دارید ببینید پشت پرده چه خبره!

### ⚠️ هشدار مهم

**این ابزار می‌تونه سیستم‌تون رو کرش کنه!** 💥

فقط در محیط‌های تست استفاده کنید. تو production استفاده نکنید مگر اینکه دوست دارید شغل‌تون رو از دست بدید! 😅

---

## ⚡ نصب و راه‌اندازی

### 🔧 پیش‌نیازها

قبل از شروع، این چیزها رو نیاز دارید:

```bash
# سیستم‌عامل: لینوکس (واضحه!)
# کرنل: 4.4+ (هرچی جدیدتر بهتر)
# دسترسی: root (بدون این هیچی نمیشه!)
# مغز: فعال و بیدار 🧠
# قهوه: اختیاری ولی توصیه میشه! ☕
```

### 🚀 نصب خودکار (توصیه میشه!)

ساده‌ترین راه استفاده از اسکریپت خودکاره:

```bash
# دانلود پروژه
git clone https://github.com/mohammadamin382/AMT-toolkit
cd AMT-toolkit

# اجرای اسکریپت نصب (با sudo!)
sudo bash setup.sh
```

اسکریپت setup.sh خودش همه چیز رو انجام میده:
- ✅ بررسی نسخه کرنل
- ✅ نصب kernel headers
- ✅ نصب dependencies
- ✅ کامپایل ماژول کرنل
- ✅ بارگذاری ماژول
- ✅ تنظیم مجوزها
- ✅ تست اولیه

### 🔨 نصب دستی (برای حرفه‌ای‌ها!)

اگه دوست دارید خودتون کنترل داشته باشید:

```bash
# 1. نصب پیش‌نیازها
sudo apt-get update
sudo apt-get install linux-headers-$(uname -r) build-essential python3 python3-pip

# 2. کامپایل ماژول کرنل
make -f driver_Makefile clean
make -f driver_Makefile

# 3. بارگذاری ماژول
sudo insmod memory_driver.ko

# 4. تنظیم مجوزها
sudo chmod 666 /dev/advanced_memory

# 5. تست (پیشنهاد نمیشه به هیچ وجه تا اپدیت جدید)
sudo python3 test_toolkit.py
```

### 🔍 بررسی نصب

برای اطمینان از درست نصب شدن:

```bash
# بررسی وجود ماژول
lsmod | grep memory_driver

# بررسی device file
ls -la /dev/advanced_memory

# بررسی لاگ‌ها
dmesg | grep -i "advanced memory" | tail -10

# تست سریع پایتون
sudo python3 -c "from memory_toolkit import AdvancedMemoryToolkit; print('✅ همه چی آماده!')"
```

---

## ⚠️ نکات ایمنی

### 🚨 خطرات

این ابزار **واقعاً خطرناکه!** می‌تونه:

- 💥 سیستم رو کرش کنه
- 🔥 داده‌ها رو خراب کنه  
- 🌪️ kernel panic ایجاد کنه
- 😵 سیستم رو منجمد کنه

### 🛡️ سطوح امنیت

پروژه 4 تا سطح امنیت داره:

#### Level 0: YOLO Mode 😈
```python
# همه چیز مجازه، هیچ محدودیتی نیست!
# فقط برای کسایی که عاشق خطرن! 💀
safe_mode = 0
```

#### Level 1: Basic Protection 🔰
```python
# محدودیت‌های پایه
# ممنوعیت دسترسی به نواحی حیاتی
safe_mode = 1
```

#### Level 2: Standard Safety 🛡️ (پیش‌فرض)
```python
# محدودیت‌های متوسط
# بررسی‌های اضافی امنیت
safe_mode = 2
```

#### Level 3: Paranoid Mode 🔒
```python
# حداکثر امنیت
# فقط عملیات کاملاً ایمن
safe_mode = 3
```

### 🔧 تنظیم سطح امنیت

```bash
# تغییر سطح امنیت در زمان اجرا
echo 3 > /sys/module/memory_driver/parameters/safe_mode

# یا موقع بارگذاری ماژول
sudo insmod memory_driver.ko safe_mode=3
```

---

## 📁 ساختار پروژه

```
advanced-memory-toolkit/
├── 📄 memory_driver.c        # ماژول کرنل (قلب پروژه!)
├── 🐍 memory_toolkit.py      # رابط پایتون (مغز پروژه!)
├── 🧪 test_toolkit.py        # تست‌ها (برای اطمینان!)
├── 🔧 driver_Makefile        # Makefile ماژول کرنل
├── ⚙️ setup.sh              # اسکریپت نصب خودکار
├── 📖 README.md             # توضیحات
└── 🗑️ uninstall.sh          # اسکریپت حذف (بعد از نصب ایجاد میشه)
```

### 📄 memory_driver.c

ماژول کرنل که کارهای اصلی رو انجام میده:
- 🔧 IOCTL handlers
- 🛡️ بررسی‌های امنیتی
- 🔍 عملیات حافظه
- 🔐 رمزنگاری ساده

### 🐍 memory_toolkit.py

رابط پایتون که استفاده رو راحت می‌کنه:
- 📞 wrapper برای IOCTL calls
- 🎨 خروجی رنگی و زیبا
- 🛠️ ابزارهای کاربردی
- 💻 حالت تعاملی

---

## 🛠️ راهنمای استفاده

### 🐍 استفاده از API پایتون

```python
from memory_toolkit import AdvancedMemoryToolkit

# ایجاد instance
amt = AdvancedMemoryToolkit()

# خواندن حافظه فیزیکی
data = amt.read_physical_memory(0x1000, 256)
if data:
    print(f"خوندم: {len(data)} بایت")
    print(amt.hex_dump(data, 0x1000))

# نوشتن حافظه فیزیکی  
test_data = b"Hello, Memory World!"
success = amt.write_physical_memory(0x2000, test_data)

# تبدیل آدرس
virt_addr = 0xffffffff81000000
phys_addr = amt.virtual_to_physical(virt_addr)
print(f"آدرس مجازی {hex(virt_addr)} = آدرس فیزیکی {hex(phys_addr)}")

# اطلاعات صفحه
info = amt.get_page_info(0x1000)
if info:
    for key, value in info.items():
        print(f"{key}: {value}")

# رمزنگاری
key = b"SuperSecretKey123456789012345678901"  # 32 بایت
encrypted = amt.encrypt_memory(0x3000, 1024, key, 'aes')

# بستن toolkit
amt.close()
```

### 💻 استفاده از Command Line

```bash
# خواندن حافظه فیزیکی
sudo python3 memory_toolkit.py --read-phys 0x1000 256

# نوشتن حافظه فیزیکی
sudo python3 memory_toolkit.py --write-phys 0x2000 48656c6c6f

# تبدیل آدرس مجازی به فیزیکی
sudo python3 memory_toolkit.py --v2p 0xffffffff81000000

# تبدیل آدرس فیزیکی به مجازی
sudo python3 memory_toolkit.py --p2v 0x1000

# اطلاعات صفحه
sudo python3 memory_toolkit.py --page-info 0x1000

# رمزنگاری
sudo python3 memory_toolkit.py --encrypt 0x3000 1024 0123456789abcdef0123456789abcdef

# کپی حافظه
sudo python3 memory_toolkit.py --copy-memory 0x1000 0x2000 256

# مقایسه حافظه
sudo python3 memory_toolkit.py --compare-memory 0x1000 0x2000 256

# گزارش استفاده
sudo python3 memory_toolkit.py --report

# حالت تعاملی (خیلی باحاله!)
sudo python3 memory_toolkit.py --interactive
```

### 🎮 حالت تعاملی

حالت تعاملی برای کار راحت‌تر:

```bash
sudo python3 memory_toolkit.py --interactive
```

دستورات موجود:
```
memory> read 0x1000 256          # خواندن حافظه
memory> write 0x2000 deadbeef     # نوشتن حافظه  
memory> v2p 0xffffffff81000000   # تبدیل آدرس
memory> info 0x1000              # اطلاعات صفحه
memory> encrypt 0x3000 1024 key  # رمزنگاری
memory> help                     # راهنما
memory> quit                     # خروج
```

---

## 📚 API Reference

### کلاس AdvancedMemoryToolkit

#### `__init__(self)`
```python
# ایجاد instance جدید و اتصال به kernel module
amt = AdvancedMemoryToolkit()
```

#### `read_physical_memory(phys_addr, size)`
```python
"""
خواندن داده از حافظه فیزیکی

Args:
    phys_addr (int): آدرس فیزیکی (هگزا)
    size (int): تعداد بایت برای خواندن

Returns:
    bytes: داده خوانده شده یا None در صورت خطا

مثال:
    data = amt.read_physical_memory(0x1000, 256)
"""
```

#### `write_physical_memory(phys_addr, data)`
```python
"""
نوشتن داده به حافظه فیزیکی

Args:
    phys_addr (int): آدرس فیزیکی مقصد
    data (bytes): داده برای نوشتن

Returns:
    bool: True اگه موفق، False اگه ناموفق

مثال:
    success = amt.write_physical_memory(0x2000, b"Hello!")
"""
```

#### `virtual_to_physical(virt_addr, pid=0)`
```python
"""
تبدیل آدرس مجازی به فیزیکی

Args:
    virt_addr (int): آدرس مجازی
    pid (int): شناسه پروسه (0 برای کرنل)

Returns:
    int: آدرس فیزیکی یا None در صورت خطا

مثال:
    phys = amt.virtual_to_physical(0xffffffff81000000)
"""
```

#### `physical_to_virtual(phys_addr, pid=0)`
```python
"""
تبدیل آدرس فیزیکی به مجازی (محدود!)

توجه: این تابع محدودیت‌هایی داره چون نگاشت 
      فیزیکی به مجازی یکتا نیست!

Args:
    phys_addr (int): آدرس فیزیکی  
    pid (int): شناسه پروسه

Returns:
    int: آدرس مجازی یا None
"""
```

#### `get_page_info(addr)`
```python
"""
دریافت اطلاعات تفصیلی صفحه

Args:
    addr (int): آدرس حافظه

Returns:
    dict: اطلاعات صفحه شامل:
        - present: آیا صفحه حاضر است؟
        - writable: آیا قابل نوشتن است؟
        - user: آیا کاربر دسترسی دارد؟
        - accessed: آیا اخیراً استفاده شده؟
        - dirty: آیا تغییر کرده؟
        - page_frame: شماره فریم صفحه
        و...

مثال:
    info = amt.get_page_info(0x1000)
    print(f"حاضر: {info['present']}")
"""
```

#### `encrypt_memory(addr, size, key, algorithm='aes', iv=None)`
```python
"""
رمزنگاری ناحیه حافظه

Args:
    addr (int): آدرس شروع
    size (int): اندازه ناحیه
    key (bytes): کلید رمزنگاری (32 بایت)
    algorithm (str): 'aes' یا 'chacha20' 
    iv (bytes): بردار اولیه (16 بایت، اختیاری)

Returns:
    bytes: داده رمزشده یا None

توجه: در نسخه‌های قدیمی کرنل فقط XOR ساده!
"""
```

#### `decrypt_memory(addr, size, key, algorithm='aes', iv=None)`
```python
"""
رمزگشایی ناحیه حافظه

Args:
    مثل encrypt_memory ولی iv الزامی!

Returns:
    bytes: داده رمزگشایی شده یا None
"""
```

#### `hex_dump(data, addr=0, width=16)`
```python
"""
نمایش hex dump زیبا از داده

Args:
    data (bytes): داده برای نمایش
    addr (int): آدرس شروع برای نمایش
    width (int): تعداد بایت در هر خط

Returns:
    str: رشته hex dump فرمت شده

مثال:
    dump = amt.hex_dump(data, 0x1000)
    print(dump)
"""
```

#### `memory_copy(src_addr, dst_addr, size)`
```python
"""
کپی حافظه از مبدا به مقصد

Args:
    src_addr (int): آدرس مبدا
    dst_addr (int): آدرس مقصد  
    size (int): تعداد بایت

Returns:
    bool: موفقیت عملیات
"""
```

#### `memory_compare(addr1, addr2, size)`
```python
"""
مقایسه دو ناحیه حافظه

Args:
    addr1 (int): آدرس اول
    addr2 (int): آدرس دوم
    size (int): تعداد بایت

Returns:
    list: لیست offset های متفاوت
"""
```

#### `generate_report()`
```python
"""
گزارش آمار استفاده

Returns:
    dict: آمار شامل:
        - session_id: شناسه جلسه
        - total_operations: تعداد عملیات
        - capabilities: قابلیت‌ها
        و...
"""
```

#### `close()`
```python
"""
بستن toolkit و آزادسازی منابع

همیشه در پایان فراخوانی کنید!
"""
```

---

## 💡 مثال‌های عملی

### 🔍 جستجوی الگو در حافظه

```python
def search_pattern_in_memory(amt, pattern, start_addr=0x1000, end_addr=0x10000):
    """جستجوی یک الگو در حافظه"""
    print(f"🔍 جستجوی '{pattern}' در حافظه...")
    
    chunk_size = 4096  # 4KB chunks
    found_addresses = []
    
    for addr in range(start_addr, end_addr, chunk_size):
        try:
            data = amt.read_physical_memory(addr, chunk_size)
            if data and pattern in data:
                offset = data.find(pattern)
                found_addr = addr + offset
                found_addresses.append(found_addr)
                print(f"✅ پیدا شد در آدرس: 0x{found_addr:x}")
        except:
            continue
    
    return found_addresses

# استفاده
amt = AdvancedMemoryToolkit()
addresses = search_pattern_in_memory(amt, b"Linux")
print(f"الگو در {len(addresses)} جا پیدا شد!")
amt.close()
```

### 🛡️ بررسی امنیت صفحات

```python
def security_audit_pages(amt, start_addr, num_pages):
    """بررسی امنیت صفحات حافظه"""
    print(f"🛡️ بررسی امنیت {num_pages} صفحه...")
    
    issues = []
    
    for i in range(num_pages):
        addr = start_addr + (i * 4096)  # هر صفحه 4KB
        info = amt.get_page_info(addr)
        
        if info:
            # بررسی مسائل امنیتی
            if info['writable'] and info['user']:
                issues.append(f"⚠️ صفحه 0x{addr:x}: قابل نوشتن توسط کاربر!")
            
            if not info['nx'] and info['user']:
                issues.append(f"⚠️ صفحه 0x{addr:x}: قابل اجرا توسط کاربر!")
    
    return issues

# استفاده
amt = AdvancedMemoryToolkit()
security_issues = security_audit_pages(amt, 0x1000, 100)
for issue in security_issues:
    print(issue)
amt.close()
```

### 🔐 رمزنگاری امن فایل

```python
def secure_file_encryption(amt, file_path, mem_addr):
    """رمزنگاری امن یک فایل در حافظه"""
    import os
    
    # خواندن فایل
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    if len(file_data) > 8192:  # حداکثر buffer size
        print("❌ فایل خیلی بزرگه!")
        return False
    
    print(f"🔐 رمزنگاری فایل {file_path}...")
    
    # نوشتن به حافظه
    if not amt.write_physical_memory(mem_addr, file_data):
        print("❌ نوشتن به حافظه ناموفق!")
        return False
    
    # تولید کلید تصادفی
    key = os.urandom(32)
    iv = os.urandom(16)
    
    # رمزنگاری
    encrypted = amt.encrypt_memory(mem_addr, len(file_data), key, 'aes', iv)
    
    if encrypted:
        # ذخیره کلید و داده رمزشده
        with open(f"{file_path}.encrypted", 'wb') as f:
            f.write(iv + encrypted)
        
        with open(f"{file_path}.key", 'wb') as f:
            f.write(key)
        
        print("✅ رمزنگاری موفق!")
        return True
    
    return False

# استفاده
amt = AdvancedMemoryToolkit()
success = secure_file_encryption(amt, "secret.txt", 0x10000)
amt.close()
```

### 📊 پروفایلینگ حافظه

```python
def memory_profiling(amt, process_name):
    """پروفایل حافظه یک پروسه"""
    import subprocess
    
    # پیدا کردن PID پروسه
    try:
        pid = int(subprocess.check_output(['pgrep', process_name]).strip())
        print(f"🔍 پروفایل پروسه {process_name} (PID: {pid})")
    except:
        print(f"❌ پروسه {process_name} پیدا نشد!")
        return
    
    # خواندن /proc/PID/maps برای آدرس‌های مجازی
    try:
        with open(f'/proc/{pid}/maps', 'r') as f:
            maps = f.read()
    except:
        print("❌ نمی‌تونم maps رو بخونم!")
        return
    
    print("📊 نقشه حافظه:")
    total_size = 0
    
    for line in maps.split('\n'):
        if line.strip():
            parts = line.split()
            if len(parts) >= 6:
                addr_range = parts[0]
                perms = parts[1]
                name = parts[5] if len(parts) > 5 else "[anonymous]"
                
                # محاسبه اندازه
                start, end = addr_range.split('-')
                start_addr = int(start, 16)
                end_addr = int(end, 16)
                size = end_addr - start_addr
                total_size += size
                
                print(f"  📍 {addr_range} ({perms}) {size//1024}KB - {name}")
                
                # تبدیل به فیزیکی (نمونه)
                phys_addr = amt.virtual_to_physical(start_addr, pid)
                if phys_addr:
                    print(f"     🔄 فیزیکی: 0x{phys_addr:x}")
    
    print(f"📏 مجموع حافظه مجازی: {total_size//1024//1024}MB")

# استفاده
amt = AdvancedMemoryToolkit()
memory_profiling(amt, "firefox")
amt.close()
```

---

## 🐛 عیب‌یابی

### 🚨 مشکلات رایج

#### 1. ماژول کامپایل نمیشه
```bash
❌ خطا: "No such file or directory: /lib/modules/X.X.X/build"
```

**راه حل:**
```bash
# نصب kernel headers
sudo apt-get install linux-headers-$(uname -r)

# یا برای CentOS/RHEL:
sudo yum install kernel-devel-$(uname -r)

# یا برای Fedora:
sudo dnf install kernel-devel-$(uname -r)
```

#### 2. ماژول بارگذاری نمیشه
```bash
❌ خطا: "Operation not permitted"
```

**راه حل:**
```bash
# بررسی Secure Boot
mokutil --sb-state

# اگه Secure Boot فعاله، غیرفعالش کنید یا ماژول رو sign کنید
# یا از VM استفاده کنید

# بررسی مجوزها
sudo dmesg | grep -i "advanced memory"
```

#### 3. Device file ایجاد نمیشه
```bash
❌ مشکل: /dev/advanced_memory وجود نداره
```

**راه حل:**
```bash
# بررسی وضعیت ماژول
lsmod | grep memory_driver

# اگه بارگذاری شده، مجوزها رو چک کنید
ls -la /dev/advanced_memory

# اگه وجود نداره، ماژول رو دوباره بارگذاری کنید
sudo rmmod memory_driver
sudo insmod memory_driver.ko
```

#### 4. Python import error
```bash
❌ خطا: "No module named 'memory_toolkit'"
```

**راه حل:**
```bash
# مطمئن شید که تو همون پوشه هستید
pwd
ls -la memory_toolkit.py

# یا path رو اضافه کنید
export PYTHONPATH=$PYTHONPATH:.
```

#### 5. Permission denied
```bash
❌ خطا: "Permission denied"
```

**راه حل:**
```bash
# همیشه با sudo اجرا کنید
sudo python3 memory_toolkit.py

# مجوزهای device رو چک کنید
ls -la /dev/advanced_memory
sudo chmod 666 /dev/advanced_memory
```

### 📊 Debug کردن

#### فعال کردن debug logs
```bash
# تنظیم سطح debug
echo 2 > /sys/module/memory_driver/parameters/debug_level

# مشاهده لاگ‌ها
dmesg | grep -i "advanced memory" | tail -20

# یا real-time monitoring
sudo tail -f /var/log/kern.log | grep "Advanced Memory"
```

#### بررسی وضعیت سیستم
```bash
# اطلاعات حافظه
cat /proc/meminfo | head -10

# اطلاعات ماژول
cat /proc/modules | grep memory_driver

# اطلاعات device
cat /proc/devices | grep advanced

# آمار slab
cat /proc/slabinfo | grep -i memory
```

#### تست‌های تشخیصی
```python
# تست سریع
def quick_diagnostic():
    try:
        amt = AdvancedMemoryToolkit()
        print("✅ اتصال موفق!")
        
        # تست خواندن ساده
        data = amt.read_physical_memory(0x1000, 16)
        if data:
            print("✅ خواندن حافظه موفق!")
        else:
            print("❌ خواندن حافظه ناموفق!")
        
        amt.close()
        print("✅ بستن موفق!")
        
    except Exception as e:
        print(f"❌ خطا: {e}")

quick_diagnostic()
```

---

## ❓ سؤالات متداول

### Q: آیا روی Raspberry Pi کار می‌کنه?
**A:** بله! ولی حافظه کمه و ممکنه محدودیت داشته باشه. سطح امنیت 3 رو توصیه می‌کنم! 🍓

### Q: می‌تونم توی virtual machine استفاده کنم?
**A:** حتماً! حتی امن‌تر هم هست. VMware، VirtualBox، و QEMU همه ساپورت می‌کنن. 🖥️

### Q: چطور می‌تونم کدهای خودم رو اضافه کنم?
**A:** خیلی راحت! memory_toolkit.py رو extend کنید یا توابع جدید به memory_driver.c اضافه کنید. 🛠️

### Q: رمزنگاری چقدر امنه?
**A:** در نسخه‌های جدید کرنل AES-256 واقعی هست، ولی در قدیمی‌ها فقط XOR ساده! برای تست خوبه ولی برای کارهای واقعی استفاده نکنید! 🔐

### Q: چطور performance رو بهتر کنم?
**A:** 
- کم‌ترین safe_mode رو استفاده کنید
- عملیات رو batch کنید  
- از chunks کوچک‌تر استفاده کنید
- debug_level رو 0 بذارید 🚀

### Q: اگه سیستم کرش کرد چیکار کنم?
**A:** 
1. نگران نباشید، طبیعیه! 😅
2. Reboot کنید
3. از backup استفاده کنید
4. سطح امنیت رو بالاتر بذارید
5. دفعه بعد احتیاط بیشتری کنید! 💀

### Q: روی کرنل‌های ARM کار می‌کنه?
**A:** بله! کد برای compatibility نوشته شده. روی ARM64 تست شده. 💪

### Q: می‌تونم چندتا instance همزمان داشته باشم?
**A:** نه! فقط یکی در هر زمان. mutex استفاده می‌کنیم برای thread safety. 🔒

### Q: چطور می‌فهمم کدوم آدرس‌ها امنن?
**A:** 
- از /proc/iomem استفاده کنید
- آدرس‌های کمتر از 1MB رو اجتناب کنید
- سطح امنیت 2+ رو فعال کنید
- اول تست کنید! 🛡️

---

## 🤝 مشارکت در پروژه

خوشحال میشیم مشارکت کنید! 🎉

### 🐛 گزارش باگ

اگه باگ پیدا کردید:

1. **قبل از گزارش بررسی کنید** که قبلاً گزارش نشده باشه
2. **جزئیات کامل بدین:**
   - نسخه کرنل
   - توزیع لینوکس  
   - پیام خطا کامل
   - مراحل تکرار مشکل
3. **لاگ‌ها رو ضمیمه کنید:**
   ```bash
   dmesg | grep -i "advanced memory" > bug_report.log
   ```

### ✨ پیشنهاد ویژگی

ایده جدید دارید؟

1. **شرح کامل بدین** که چه کاری می‌خواد انجام بده
2. **مورد استفاده** رو توضیح بدین
3. **در نظر بگیرید** که امنیت مهمه!

### 🔧 Contributing کد

می‌خواید کد بنویسید؟

1. **Fork کنید** repository رو
2. **Branch جدید بسازید:**
   ```bash
   git checkout -b feature/amazing-new-feature
   ```
3. **کد تمیز بنویسید**
4. **تست کنید** حتماً!
5. **Pull request بفرستید**

### 📝 استانداردهای کد

#### برای C (kernel module):
```c
// متغیرها clear باشن
// error handling کامل
// compatibility checks برای نسخه‌های مختلف
```

#### برای Python:
```python
# Type hints استفاده کنید
# Docstring های کامل
# Exception handling مناسب
```
### 🎭 راهنمای کامنت‌نویسی

کامنت‌ها باید:
- 🎯 **واضح باشن**

### 🏆 contributors

تشکر از همه کسایی که کمک کردن:
- شما! (به زودی!) 😉

---

## 📞 پشتیبانی

نیاز به کمک دارید؟

### 📧 ارتباط
- **GitHub Issues:** برای باگ‌ها و سؤالات فنی

### 🆘 اورژانسی
اگه سیستم‌تون کرش کرد:
1. **نفس عمیق بکشید** 😮‍💨
2. **Reboot کنید** 🔄
3. **از backup استفاده کنید** 💾
4. **درس بگیرید** 📚
5. **دوباره امتحان کنید** (احتیاط بیشتر!) 🎯

---

## 📜 مجوز و قوانین

### 🆓 مجوز
این پروژه تحت مجوز **GPL v3** منتشر شده. یعنی:
- ✅ استفاده آزاد
- ✅ تغییر و اصلاح  
- ✅ توزیع مجدد
- ❌ استفاده تجاری بدون ذکر منبع
- ❌ حذف copyright

### ⚠️ سلب مسئولیت

**این ابزار صرفاً برای آموزش و تست است!**

- 💀 ممکنه سیستم‌تون رو کرش کنه
- 🔥 ممکنه داده‌ها رو خراب کنه  
- 😵 ممکنه کل شبکه رو ببره
- 🤯 ممکنه همسرتون رو عصبانی کنه!

**ما مسئولیتی نداریم!** 🤷‍♂️

### 🏛️ قوانین استفاده

1. **فقط در محیط تست** استفاده کنید
2. **هرگز در production** استفاده نکنید  
3. **backup کامل** از سیستم‌تون داشته باشید
4. **مسئولیت خودتونه** اگه چیزی خراب شد
5. **به دیگران یاد بدین** که محتاط باشن!

---

## 🎉 پایان

**تبریک! 🎊**

حالا شما آماده‌اید برای:
- 🔍 کاوش در اعماق حافظه سیستم
- 🧙‍♂️ انجام جادوهای کرنل‌سطح  
- 💥 کرش کردن سیستم (نه، این جایزه نیست! 😅)
- 🎓 یادگیری مفاهیم پیشرفته

### 🌟 آخرین نصایح

1. **همیشه backup داشته باشید** 💾
2. **سطح امنیت مناسب انتخاب کنید** 🛡️
3. **اول تو VM تست کنید** 🖥️
4. **لاگ‌ها رو بخونید** 📋
5. **صبور باشید** ⏳
6. **از کارتون لذت ببرید** 😄

### 🚀 قدم‌های بعدی

حالا که master شدید، می‌تونید:
- کدهای خودتون رو اضافه کنید
- ویژگی‌های جدید توسعه بدین
- به دیگران کمک کنید
- سیستم‌های جدید رو تست کنید

### 🎪 خداحافظی

امیدواریم این راهنما مفید بوده! اگه سؤالی دارید، خجالت نکشید و بپرسید. 

**یادتون باشه:** *"With great power comes great responsibility!"* 🕷️

**موفق باشید و حافظه‌تون همیشه پایدار! 🧠✨**

---

*راهنما تمام شد - ولی ماجراجویی تازه شروع شده! 🎬*

**نسخه راهنما:** 3.1  
**تاریخ آخرین به‌روزرسانی:** امروز! 📅  
**نوشته شده با:** ❤️ + ☕ + 🤪

*P.S: اگه این راهنما رو مفید دیدید، یه ⭐ بدین! 😉
