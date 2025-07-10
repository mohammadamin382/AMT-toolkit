
#!/bin/bash
# 🚀 Advanced Memory Toolkit Setup Script 🚀

echo "🎭 خوش اومدید به نصب AMT!"
echo "🎪 این اسکریپت قراره سیستم‌تون رو آماده کنه برای کارهای خطرناک!"
echo "⚠️  اگه نمی‌دونید چیکار می‌کنید، بهتره فرار کنید! 🏃‍♂️💨"
echo ""

# color 🌈
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # no color 

# func

print_step() {
    echo -e "${BLUE}🔧 $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

# بررسی دسترسی root - باید ادمین باشید! 👑
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "این اسکریپت باید با root اجرا بشه! (sudo استفاده کنید)"
        print_info "مثل این: sudo bash setup.sh"
        print_warning "بدون root نمی‌تونم کاری انجام بدم! 🤷‍♂️"
        exit 1
    fi
    print_success "دسترسی root تایید شد! شما ادمین هستید! 👑"
}

# بررسی نسخه کرنل - مهم‌ترین قسمت! 🐧
check_kernel() {
    print_step "بررسی نسخه کرنل..."
    KERNEL_VERSION=$(uname -r)
    print_info "نسخه کرنل فعلی: $KERNEL_VERSION"
    
    # بررسی وجود kernel headers
    HEADERS_PATH="/lib/modules/$KERNEL_VERSION/build"
    if [ ! -d "$HEADERS_PATH" ]; then
        print_warning "Kernel headers پیدا نشد! 😱"
        print_info "تلاش برای نصب..."
        
        # شناسایی توزیع لینوکس - هر کدوم یه روش داره! 🐧
        if command -v apt-get &> /dev/null; then
            # Ubuntu/Debian - محبوب‌ترین! 💜
            print_info "Ubuntu/Debian شناسایی شد!"
            apt-get update
            apt-get install -y linux-headers-$(uname -r) || {
                print_error "نصب kernel headers شکست خورد!"
                print_warning "ممکنه نسخه کرنل‌تون خیلی جدید یا قدیمی باشه!"
                exit 1
            }
        elif command -v yum &> /dev/null; then
            # CentOS/RHEL - سنگین ولی قوی! 💪
            print_info "CentOS/RHEL شناسایی شد!"
            yum install -y kernel-devel-$(uname -r) || {
                print_error "نصب kernel headers شکست خورد!"
                exit 1
            }
        elif command -v dnf &> /dev/null; then
            # Fedora - همیشه آپدیت! 🚀
            print_info "Fedora شناسایی شد!"
            dnf install -y kernel-devel-$(uname -r) || {
                print_error "نصب kernel headers شکست خورد!"
                exit 1
            }
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            print_info "Arch Linux شناسایی شد! (BTW, I use Arch 😏)"
            pacman -S --noconfirm linux-headers || {
                print_error "نصب kernel headers شکست خورد!"
                exit 1
            }
        else
            print_error "توزیع لینوکس شناسایی نشد! 🤷‍♂️"
            print_warning "باید خودتون kernel headers رو نصب کنید!"
            exit 1
        fi
    else
        print_success "Kernel headers موجوده! 🎉"
    fi
}

# نصب ابزارهای ضروری - بدون اینا کار نمیشه! 🛠️
install_dependencies() {
    print_step "نصب ابزارهای ضروری..."
    
    if command -v apt-get &> /dev/null; then
        print_info "استفاده از apt-get..."
        apt-get update && apt-get install -y \
            build-essential \
            gcc \
            make \
            python3 \
            python3-pip \
            git \
            curl \
            vim \
            htop || {
            print_error "نصب dependencies شکست خورد!"
            exit 1
        }
    elif command -v yum &> /dev/null; then
        print_info "استفاده از yum..."
        yum groupinstall -y "Development Tools"
        yum install -y python3 python3-pip git curl vim htop
    elif command -v dnf &> /dev/null; then
        print_info "استفاده از dnf..."
        dnf groupinstall -y "Development Tools"
        dnf install -y python3 python3-pip git curl vim htop
    elif command -v pacman &> /dev/null; then
        print_info "استفاده از pacman..."
        pacman -S --noconfirm base-devel python python-pip git curl vim htop
    fi
    
    print_success "همه ابزارها نصب شد! 🔧"
}

# بررسی فایل‌های پروژه - همه چی سر جاش باشه! 📁
check_project_files() {
    print_step "بررسی فایل‌های پروژه..."
    
    REQUIRED_FILES=("memory_driver.c" "memory_toolkit.py" "driver_Makefile")
    
    for file in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            print_error "فایل ضروری پیدا نشد: $file 😰"
            print_warning "مطمئن شید که تو پوشه درست هستید!"
            exit 1
        else
            print_info "فایل $file پیدا شد! ✅"
        fi
    done
    
    print_success "همه فایل‌های ضروری موجودن! 📂"
}

# ساخت ماژول کرنل - قسمت هیجان‌انگیز! 🏗️
build_kernel_module() {
    print_step "ساخت ماژول کرنل..."
    print_warning "این قسمت ممکنه کمی طول بکشه، صبر کنید! ⏳"
    
    # پاک کردن فایل‌های قبلی
    print_info "پاک کردن فایل‌های قبلی..."
    make -f driver_Makefile clean 2>/dev/null || true
    
    # ساخت ماژول جدید
    print_info "ساخت ماژول جدید..."
    if make -f driver_Makefile; then
        print_success "ماژول کرنل با موفقیت ساخته شد! 🎉"
    else
        print_error "ساخت ماژول شکست خورد! 💥"
        print_warning "ممکنه مشکل از kernel headers یا نسخه gcc باشه!"
        print_info "سعی کنید kernel headers رو دوباره نصب کنید"
        exit 1
    fi
    
    # بررسی وجود فایل .ko
    if [ ! -f "memory_driver.ko" ]; then
        print_error "فایل memory_driver.ko ایجاد نشد! 😱"
        exit 1
    fi
    
    print_success "فایل memory_driver.ko آماده شد! 🚀"
}

# بارگذاری ماژول کرنل - لحظه حقیقت! ⚡
load_kernel_module() {
    print_step "بارگذاری ماژول کرنل..."
    
    # بررسی ماژول قبلی
    if lsmod | grep -q "memory_driver"; then
        print_warning "ماژول قبلی پیدا شد، حذف می‌کنم..."
        rmmod memory_driver 2>/dev/null || {
            print_error "نمی‌تونم ماژول قبلی رو حذف کنم!"
            print_info "ممکنه در حال استفاده باشه"
            exit 1
        }
        print_success "ماژول قبلی حذف شد! 🗑️"
    fi
    
    # بارگذاری ماژول جدید
    print_info "بارگذاری ماژول جدید..."
    if insmod memory_driver.ko; then
        print_success "ماژول با موفقیت بارگذاری شد! 🎊"
    else
        print_error "بارگذاری ماژول شکست خورد! 💥"
        print_warning "ممکنه مشکل از نسخه کرنل یا مجوزها باشه!"
        exit 1
    fi
    
    # بررسی وجود device file
    sleep 1  # کمی صبر می‌کنیم که device ایجاد بشه
    
    if [ -e "/dev/advanced_memory" ]; then
        print_success "Device file ایجاد شد: /dev/advanced_memory 📱"
    else
        print_error "Device file ایجاد نشد! 😰"
        print_warning "ممکنه مشکل از udev باشه"
        exit 1
    fi
}

# تنظیم مجوزها - همه بتونن استفاده کنن! 🔓
setup_permissions() {
    print_step "تنظیم مجوزها..."
    
    if [ -e "/dev/advanced_memory" ]; then
        chmod 666 /dev/advanced_memory
        print_success "مجوزهای device تنظیم شد! 🔐"
        
        # نمایش اطلاعات device
        ls -la /dev/advanced_memory
    else
        print_error "Device file پیدا نشد! 👻"
        exit 1
    fi
    
    # تنظیم مجوزهای فایل‌های پایتون
    if [ -f "memory_toolkit.py" ]; then
        chmod +x memory_toolkit.py
        print_success "اسکریپت پایتون قابل اجرا شد! 🐍"
    fi
    
    if [ -f "test_toolkit.py" ]; then
        chmod +x test_toolkit.py
        print_success "اسکریپت تست قابل اجرا شد! 🧪"
    fi
}

# تست سریع - ببینیم کار می‌کنه یا نه! 🧪
quick_test() {
    print_step "تست سریع سیستم..."
    
    # بررسی وضعیت ماژول
    if lsmod | grep -q "memory_driver"; then
        print_success "ماژول در لیست ماژول‌های بارگذاری شده! ✅"
    else
        print_warning "ماژول در لیست پیدا نشد! 🤔"
    fi
    
    # بررسی لاگ‌های کرنل
    print_info "آخرین لاگ‌های کرنل:"
    dmesg | grep -i "advanced memory" | tail -5 || {
        print_warning "لاگ خاصی پیدا نشد!"
    }
    
    # تست ساده پایتون
    if command -v python3 &> /dev/null && [ -f "memory_toolkit.py" ]; then
        print_info "تست import کردن ماژول پایتون..."
        if python3 -c "
import sys
sys.path.append('.')
try:
    from memory_toolkit import AdvancedMemoryToolkit
    print('✅ Import موفق!')
except ImportError as e:
    print(f'❌ Import شکست خورد: {e}')
except Exception as e:
    print(f'⚠️ خطای دیگر: {e}')
"; then
            print_success "تست پایتون موفق! 🐍"
        else
            print_warning "مشکل در import پایتون! 🤷‍♂️"
        fi
    fi
}

# ایجاد اسکریپت راحت برای حذف! 🗑️
create_uninstall_script() {
    print_step "ایجاد اسکریپت حذف..."
    
    cat > uninstall.sh << 'EOF'
#!/bin/bash
# 🗑️ اسکریپت حذف Advanced Memory Toolkit
# برای وقتی که از دست ما خسته شدید! 😢

echo "🗑️ حذف Advanced Memory Toolkit..."

# حذف ماژول
if lsmod | grep -q "memory_driver"; then
    echo "⏹️ حذف ماژول کرنل..."
    rmmod memory_driver 2>/dev/null && echo "✅ ماژول حذف شد!" || echo "❌ مشکل در حذف ماژول!"
else
    echo "ℹ️ ماژول بارگذاری نشده"
fi

# پاک کردن فایل‌های ساخته شده
echo "🧹 پاک کردن فایل‌های ساخته شده..."
make -f driver_Makefile clean 2>/dev/null || true
rm -f *.ko *.o *.mod.c *.mod *.symvers *.order 2>/dev/null

echo "✅ حذف کامل شد!"
echo "👋 تا دیدار دوباره!"
EOF

    chmod +x uninstall.sh
    print_success "اسکریپت حذف ایجاد شد: uninstall.sh 🗑️"
}

# نمایش راهنمای استفاده - آموزش سریع! 📚
show_usage_guide() {
    print_step "راهنمای استفاده:"
    echo ""
    print_info "🐍 برای تست کامل پایتون:"
    echo "   sudo python3 test_toolkit.py"
    echo ""
    print_info "🔧 برای استفاده از command line:"
    echo "   sudo python3 memory_toolkit.py --help"
    echo ""
    print_info "📖 برای خواندن حافظه:"
    echo "   sudo python3 memory_toolkit.py --read-phys 0x1000 256"
    echo ""
    print_info "🔄 برای تبدیل آدرس:"
    echo "   sudo python3 memory_toolkit.py --v2p 0xffffffff81000000"
    echo ""
    print_info "🗑️ برای حذف کامل:"
    echo "   sudo bash uninstall.sh"
    echo ""
    print_warning "⚠️ همیشه با sudo اجرا کنید!"
    print_warning "⚠️ فقط در محیط تست استفاده کنید!"
    echo ""
}

# تابع اصلی - شروع ماجراجویی! 🎬
main() {
    echo "🎪 شروع نصب Advanced Memory Toolkit!"
    echo "🕐 $(date)"
    echo ""
    
    print_warning "⚠️ هشدار: این ابزار فقط برای تست و آموزش است!"
    print_warning "⚠️ در محیط تولید استفاده نکنید!"
    echo ""
    
    # 5 ثانیه فرصت برای فکر کردن! 🤔
    print_info "5 ثانیه فرصت دارید برای فرار! 🏃‍♂️"
    for i in {5..1}; do
        echo -ne "\r⏰ $i ثانیه... "
        sleep 1
    done
    echo -e "\r✅ بریم! 🚀        "
    echo ""
    
    # مراحل نصب - یکی یکی! 📋
    check_root
    check_kernel
    install_dependencies
    check_project_files
    build_kernel_module
    load_kernel_module
    setup_permissions
    quick_test
    create_uninstall_script
    
    echo ""
    print_success "🎉 نصب با موفقیت تمام شد!"
    print_success "🚀 Advanced Memory Toolkit آماده استفاده!"
    echo ""
    
    show_usage_guide
    
    print_warning "⚠️ یادتون باشه: With great power comes great responsibility!"
    print_info "💡 اگه مشکلی پیش اومد، از dmesg استفاده کنید"
    print_info "🐛 برای debug: echo 2 > /sys/module/memory_driver/parameters/debug_level"
    echo ""
    print_success "🎊 موفق باشید!"
}

# اجرای تابع اصلی - Let's Go! 🚀
main "$@"

# پایان اسکریپت - تمام! 🏁
# امیدوارم همه چی درست پیش رفته باشه! 🤞
# اگه نه... خب، حداقل سعی کردیم! 😅
