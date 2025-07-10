
#!/bin/bash
# 🚀 Advanced Memory Toolkit Installation Script v2.0 🚀

echo "🎭 خوش اومدید به نصب AMT v2.0!"
echo "🎪 این اسکریپت قراره سیستم‌تون رو آماده کنه برای کارهای خطرناک!"
echo "⚠️  اگه نمی‌دونید چیکار می‌کنید، بهتره فرار کنید! 🏃‍♂️💨"
echo ""

# Global variables
REPO_URL="https://github.com/mohammadamin382/AMT-toolkit.git"
CURRENT_DIR=$(pwd)
VERSION_FILE=".amt_version"
INSTALL_FILE=".amt_installed"
CURRENT_VERSION="2.0.0"

# Color variables 🌈
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # no color 

# Enhanced functions
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

print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    AMT Installation Script v2.0             ║"
    echo "║              Advanced Memory Toolkit Installer              ║"
    echo "║                                                              ║"
    echo "║  🚀 Professional Installation System                         ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if already installed
check_installation_status() {
    if [ -f "$INSTALL_FILE" ]; then
        INSTALLED_VERSION=$(cat "$INSTALL_FILE" 2>/dev/null || echo "unknown")
        print_warning "AMT قبلاً نصب شده است! (نسخه: $INSTALLED_VERSION)"
        print_info "برای آپدیت از فایل update.sh استفاده کنید"
        print_info "برای نصب مجدد ابتدا uninstall.sh را اجرا کنید"
        echo ""
        echo "گزینه‌های موجود:"
        echo "1) خروج"
        echo "2) نصب مجدد (خطرناک)"
        echo "3) نمایش وضعیت فعلی"
        echo ""
        echo -n "انتخاب کنید: "
        read -r choice
        
        case $choice in
            1)
                print_info "خروج... 👋"
                exit 0
                ;;
            2)
                print_warning "شما انتخاب کردید که مجدداً نصب کنید..."
                print_error "⚠️ این کار ممکن است خطرناک باشد!"
                echo -n "آیا مطمئن هستید؟ (yes/no): "
                read -r confirm
                if [ "$confirm" != "yes" ]; then
                    print_info "نصب لغو شد"
                    exit 0
                fi
                rm -f "$INSTALL_FILE"
                ;;
            3)
                show_current_status
                exit 0
                ;;
            *)
                print_error "گزینه نامعتبر!"
                exit 1
                ;;
        esac
    fi
}

# Show current status
show_current_status() {
    print_step "نمایش وضعیت فعلی..."
    
    if [ -f "$INSTALL_FILE" ]; then
        print_success "وضعیت: نصب شده ✅"
        print_info "نسخه نصب شده: $(cat $INSTALL_FILE)"
    else
        print_warning "وضعیت: نصب نشده ❌"
    fi
    
    if lsmod | grep -q "memory_driver"; then
        print_success "ماژول کرنل: فعال ✅"
    else
        print_warning "ماژول کرنل: غیرفعال ❌"
    fi
    
    if [ -e "/dev/advanced_memory" ]; then
        print_success "Device file: موجود ✅"
        ls -la /dev/advanced_memory
    else
        print_warning "Device file: ناموجود ❌"
    fi
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "این اسکریپت باید با root اجرا بشه! (sudo استفاده کنید)"
        print_info "مثل این: sudo bash setup.sh"
        print_warning "بدون root نمی‌تونم کاری انجام بدم! 🤷‍♂️"
        exit 1
    fi
    print_success "دسترسی root تایید شد! شما ادمین هستید! 👑"
}

# Enhanced kernel check with comprehensive compatibility
check_kernel() {
    print_step "بررسی جامع نسخه کرنل..."
    KERNEL_VERSION=$(uname -r)
    KERNEL_RELEASE=$(uname -v)
    KERNEL_ARCH=$(uname -m)
    
    print_info "نسخه کرنل فعلی: $KERNEL_VERSION"
    print_info "آرکیتکتور: $KERNEL_ARCH"
    print_info "Release: $KERNEL_RELEASE"
    
    # Extract version components
    MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
    MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
    PATCH=$(echo $KERNEL_VERSION | cut -d. -f3 | cut -d- -f1)
    
    print_info "تجزیه نسخه: $MAJOR.$MINOR.$PATCH"
    
    # Comprehensive kernel version support
    SUPPORTED_KERNELS=(
        "3.10" "3.11" "3.12" "3.13" "3.14" "3.15" "3.16" "3.17" "3.18" "3.19"
        "4.0" "4.1" "4.2" "4.3" "4.4" "4.5" "4.6" "4.7" "4.8" "4.9"
        "4.10" "4.11" "4.12" "4.13" "4.14" "4.15" "4.16" "4.17" "4.18" "4.19"
        "4.20" "5.0" "5.1" "5.2" "5.3" "5.4" "5.5" "5.6" "5.7" "5.8" "5.9"
        "5.10" "5.11" "5.12" "5.13" "5.14" "5.15" "5.16" "5.17" "5.18" "5.19"
        "6.0" "6.1" "6.2" "6.3" "6.4" "6.5" "6.6" "6.7" "6.8" "6.9"
    )
    
    # Check minimum kernel version (3.10+)
    if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 10 ]); then
        print_error "نسخه کرنل خیلی قدیمی است! حداقل 3.10 نیاز دارید"
        print_error "نسخه فعلی: $MAJOR.$MINOR - حداقل: 3.10"
        print_warning "لطفاً کرنل خودتان را به‌روزرسانی کنید"
        exit 1
    fi
    
    # Check if kernel version is supported
    KERNEL_MAJOR_MINOR="$MAJOR.$MINOR"
    KERNEL_SUPPORTED=0
    
    for supported in "${SUPPORTED_KERNELS[@]}"; do
        if [ "$KERNEL_MAJOR_MINOR" = "$supported" ]; then
            KERNEL_SUPPORTED=1
            break
        fi
    done
    
    if [ "$KERNEL_SUPPORTED" -eq 1 ]; then
        print_success "نسخه کرنل پشتیبانی می‌شود! ✅"
    else
        print_warning "نسخه کرنل تست نشده است ولی ممکن است کار کند"
        print_info "نسخه‌های تست شده: 3.10+ تا 6.9+"
        echo -n "آیا می‌خواهید ادامه دهید؟ (y/n): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check for headers with comprehensive paths
    HEADERS_PATHS=(
        "/lib/modules/$KERNEL_VERSION/build"
        "/usr/src/linux-headers-$KERNEL_VERSION"
        "/usr/src/kernels/$KERNEL_VERSION"
        "/lib/modules/$KERNEL_VERSION/source"
        "/usr/src/linux-source-$KERNEL_VERSION"
        "/usr/src/linux-$KERNEL_VERSION"
    )
    
    HEADERS_FOUND=0
    for headers_path in "${HEADERS_PATHS[@]}"; do
        if [ -d "$headers_path" ]; then
            print_success "Kernel headers پیدا شد: $headers_path"
            HEADERS_FOUND=1
            export KERNEL_HEADERS_PATH="$headers_path"
            break
        fi
    done
    
    if [ "$HEADERS_FOUND" -eq 0 ]; then
        print_warning "Kernel headers پیدا نشد! نصب می‌کنم..."
        install_kernel_headers
    fi
}

# Enhanced kernel headers installation with better distribution detection
install_kernel_headers() {
    print_step "نصب kernel headers..."
    
    # Comprehensive distribution detection
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        if grep -q "CentOS" /etc/redhat-release; then
            DISTRO="centos"
        elif grep -q "Red Hat" /etc/redhat-release; then
            DISTRO="rhel"
        else
            DISTRO="redhat"
        fi
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    else
        DISTRO="unknown"
    fi
    
    print_info "توزیع شناسایی شده: $DISTRO ($DISTRO_VERSION)"
    
    case $DISTRO in
        ubuntu|debian|linuxmint|pop)
            print_info "نصب برای Ubuntu/Debian based..."
            apt-get update -qq
            apt-get install -y linux-headers-$(uname -r) linux-headers-generic build-essential
            apt-get install -y gcc make libc6-dev module-assistant
            ;;
        centos|rhel|rocky|almalinux|fedora)
            print_info "نصب برای RHEL/CentOS/Fedora based..."
            if command -v dnf &> /dev/null; then
                dnf groupinstall -y "Development Tools"
                dnf install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r)
                dnf install -y gcc make glibc-devel
            else
                yum groupinstall -y "Development Tools"
                yum install -y kernel-devel-$(uname -r) kernel-headers-$(uname -r)
                yum install -y gcc make glibc-devel
            fi
            ;;
        arch|manjaro|endeavouros)
            print_info "نصب برای Arch Linux based..."
            pacman -S --noconfirm linux-headers gcc make base-devel
            ;;
        opensuse|sles)
            print_info "نصب برای openSUSE/SLES..."
            zypper install -y -t pattern devel_basis
            zypper install -y kernel-devel kernel-source gcc make
            ;;
        gentoo)
            print_info "نصب برای Gentoo..."
            emerge --ask=n sys-kernel/gentoo-sources sys-devel/gcc sys-devel/make
            ;;
        alpine)
            print_info "نصب برای Alpine Linux..."
            apk add --no-cache linux-headers gcc make musl-dev
            ;;
        *)
            print_error "توزیع ناشناخته: $DISTRO"
            print_warning "باید دستی kernel headers نصب کنید"
            print_info "معمولاً پکیج‌های مورد نیاز:"
            print_info "- kernel-headers / linux-headers"
            print_info "- kernel-devel / linux-headers-generic"
            print_info "- gcc, make, build-essential"
            exit 1
            ;;
    esac
    
    print_success "Kernel headers نصب شد! 🎉"
    
    # Verify installation
    for headers_path in "${HEADERS_PATHS[@]}"; do
        if [ -d "$headers_path" ]; then
            print_success "تایید: Headers در $headers_path موجود است"
            export KERNEL_HEADERS_PATH="$headers_path"
            return 0
        fi
    done
    
    print_error "هنوز هم headers پیدا نشد!"
    exit 1
}

# Enhanced dependency installation
install_dependencies() {
    print_step "نصب ابزارهای ضروری..."
    
    # Common packages for all distributions
    COMMON_PACKAGES="gcc make python3 python3-pip git curl vim htop dkms"
    
    if command -v apt-get &> /dev/null; then
        print_info "استفاده از apt-get..."
        apt-get update -qq
        apt-get install -y build-essential $COMMON_PACKAGES
        apt-get install -y python3-dev python3-venv linux-headers-generic
    elif command -v dnf &> /dev/null; then
        print_info "استفاده از dnf..."
        dnf groupinstall -y "Development Tools" -q
        dnf install -y $COMMON_PACKAGES python3-devel kernel-devel -q
    elif command -v yum &> /dev/null; then
        print_info "استفاده از yum..."
        yum groupinstall -y "Development Tools" -q
        yum install -y $COMMON_PACKAGES python3-devel kernel-devel -q
    elif command -v pacman &> /dev/null; then
        print_info "استفاده از pacman..."
        pacman -S --noconfirm base-devel $COMMON_PACKAGES linux-headers
    elif command -v zypper &> /dev/null; then
        print_info "استفاده از zypper..."
        zypper install -y -t pattern devel_basis
        zypper install -y $COMMON_PACKAGES kernel-devel
    elif command -v apk &> /dev/null; then
        print_info "استفاده از apk..."
        apk add --no-cache $COMMON_PACKAGES linux-headers musl-dev
    fi
    
    print_success "همه ابزارها نصب شد! 🔧"
}

# Enhanced project files check
check_project_files() {
    print_step "بررسی فایل‌های پروژه..."
    
    REQUIRED_FILES=(
        "memory_driver.c"
        "memory_toolkit.py"
        "driver_Makefile"
        "test1.py"
        "example.py"
    )
    
    MISSING_FILES=()
    
    for file in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$file" ]; then
            MISSING_FILES+=("$file")
            print_warning "فایل ناموجود: $file 😰"
        else
            print_info "فایل $file موجود ✅"
        fi
    done
    
    if [ ${#MISSING_FILES[@]} -gt 0 ]; then
        print_error "فایل‌های ضروری ناموجود هستند!"
        print_info "فایل‌های ناموجود: ${MISSING_FILES[*]}"
        print_error "لطفاً پروژه را مجدداً دانلود کنید"
        exit 1
    fi
    
    print_success "همه فایل‌های ضروری موجودند! 📂"
}

# Enhanced kernel module build with better error handling
build_kernel_module() {
    print_step "ساخت ماژول کرنل..."
    print_warning "این قسمت ممکنه کمی طول بکشه، صبر کنید! ⏳"
    
    # Clean previous builds
    print_info "پاک کردن فایل‌های قبلی..."
    make -f driver_Makefile clean 2>/dev/null || true
    rm -f *.ko *.o *.mod.c *.mod *.symvers *.order .*.cmd 2>/dev/null || true
    rm -rf .tmp_versions/ 2>/dev/null || true
    
    # Set kernel build directory
    if [ -n "${KERNEL_HEADERS_PATH:-}" ]; then
        export KERNEL_DIR="$KERNEL_HEADERS_PATH"
    fi
    
    # Build with verbose output for better debugging
    print_info "ساخت ماژول جدید..."
    print_info "استفاده از Makefile: driver_Makefile"
    
    if make -f driver_Makefile V=1; then
        print_success "ماژول کرنل با موفقیت ساخته شد! 🎉"
    else
        print_error "ساخت ماژول شکست خورد! 💥"
        print_warning "بررسی لاگ‌های خطا:"
        echo "--- Make Error Output ---"
        make -f driver_Makefile V=1 2>&1 | tail -20
        echo "--- Kernel Messages ---"
        dmesg | tail -10
        print_info "احتمالاً مشکل از kernel headers یا نسخه gcc است"
        print_info "برای حل مشکل:"
        print_info "1. مطمئن شوید kernel headers نصب است"
        print_info "2. بررسی کنید gcc نسخه مناسب دارد"
        print_info "3. سیستم را ریبوت کنید و مجدداً تلاش کنید"
        exit 1
    fi
    
    # Verify module file
    if [ ! -f "memory_driver.ko" ]; then
        print_error "فایل memory_driver.ko ایجاد نشد! 😱"
        print_info "لیست فایل‌های موجود:"
        ls -la *.ko 2>/dev/null || echo "هیچ فایل .ko پیدا نشد"
        exit 1
    fi
    
    # Check module info
    print_info "اطلاعات ماژول:"
    modinfo memory_driver.ko || true
    
    print_success "فایل memory_driver.ko آماده شد! 🚀"
}

# Enhanced module loading with comprehensive error handling
load_kernel_module() {
    print_step "بارگذاری ماژول کرنل..."
    
    # Check if module is already loaded
    if lsmod | grep -q "memory_driver"; then
        print_warning "ماژول قبلی پیدا شد، حذف می‌کنم..."
        rmmod memory_driver 2>/dev/null || {
            print_error "نمی‌تونم ماژول قبلی رو حذف کنم!"
            print_info "ممکنه در حال استفاده باشه"
            print_info "لیست process های استفاده کننده:"
            lsof /dev/advanced_memory 2>/dev/null || echo "هیچ process پیدا نشد"
            echo -n "آیا می‌خواهید force کنید؟ (y/n): "
            read -r response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                rmmod -f memory_driver 2>/dev/null || {
                    print_error "حذف اجباری هم کار نکرد!"
                    print_warning "ممکن است نیاز به ریبوت باشد"
                    exit 1
                }
            else
                exit 1
            fi
        }
        print_success "ماژول قبلی حذف شد! 🗑️"
    fi
    
    # Load new module
    print_info "بارگذاری ماژول جدید..."
    if insmod memory_driver.ko; then
        print_success "ماژول با موفقیت بارگذاری شد! 🎊"
    else
        print_error "بارگذاری ماژول شکست خورد! 💥"
        print_warning "بررسی لاگ‌های کرنل:"
        dmesg | grep -i "advanced memory\|memory_driver" | tail -10
        print_warning "بررسی علت شکست:"
        echo "--- Module verification ---"
        file memory_driver.ko
        echo "--- Module dependencies ---"
        modprobe --dry-run memory_driver.ko 2>&1 || true
        exit 1
    fi
    
    # Wait for device creation
    print_info "انتظار برای ایجاد device..."
    sleep 3
    
    # Check device file
    DEVICE_WAIT_COUNT=0
    while [ ! -e "/dev/advanced_memory" ] && [ $DEVICE_WAIT_COUNT -lt 10 ]; do
        sleep 1
        DEVICE_WAIT_COUNT=$((DEVICE_WAIT_COUNT + 1))
        print_info "انتظار... ($DEVICE_WAIT_COUNT/10)"
    done
    
    if [ -e "/dev/advanced_memory" ]; then
        print_success "Device file ایجاد شد: /dev/advanced_memory 📱"
    else
        print_error "Device file ایجاد نشد! 😰"
        print_warning "بررسی لاگ‌های سیستم:"
        journalctl -n 20 | grep -i "memory\|device" || true
        print_info "بررسی دستی:"
        echo "ls -la /dev/ | grep memory"
        ls -la /dev/ | grep memory || echo "هیچ device memory پیدا نشد"
        exit 1
    fi
}

# Enhanced permissions setup
setup_permissions() {
    print_step "تنظیم مجوزها..."
    
    if [ -e "/dev/advanced_memory" ]; then
        chmod 666 /dev/advanced_memory
        chown root:users /dev/advanced_memory 2>/dev/null || chown root:root /dev/advanced_memory
        print_success "مجوزهای device تنظیم شد! 🔐"
        
        # Show device info
        print_info "اطلاعات device:"
        ls -la /dev/advanced_memory
        
        # Test device accessibility
        if [ -r "/dev/advanced_memory" ] && [ -w "/dev/advanced_memory" ]; then
            print_success "Device قابل خواندن و نوشتن است ✅"
        else
            print_warning "مشکل در دسترسی device ⚠️"
        fi
    else
        print_error "Device file پیدا نشد! 👻"
        exit 1
    fi
    
    # Set permissions for Python scripts
    for script in memory_toolkit.py test1.py example.py; do
        if [ -f "$script" ]; then
            chmod +x "$script"
            print_success "اسکریپت $script قابل اجرا شد! 🐍"
        fi
    done
}

# Comprehensive testing with detailed checks
comprehensive_test() {
    print_step "تست جامع سیستم..."
    
    local test_passed=0
    local test_total=6
    
    # Test 1: Module status
    print_info "تست 1/6: وضعیت ماژول..."
    if lsmod | grep -q "memory_driver"; then
        print_success "✅ ماژول در لیست بارگذاری شده"
        test_passed=$((test_passed + 1))
    else
        print_error "❌ ماژول در لیست پیدا نشد"
    fi
    
    # Test 2: Device file
    print_info "تست 2/6: فایل device..."
    if [ -e "/dev/advanced_memory" ]; then
        print_success "✅ Device file موجود است"
        test_passed=$((test_passed + 1))
    else
        print_error "❌ Device file ناموجود"
    fi
    
    # Test 3: Permissions
    print_info "تست 3/6: مجوزها..."
    if [ -r "/dev/advanced_memory" ] && [ -w "/dev/advanced_memory" ]; then
        print_success "✅ مجوزهای خواندن/نوشتن صحیح"
        test_passed=$((test_passed + 1))
    else
        print_warning "⚠️ مجوزها ممکن است صحیح نباشند"
    fi
    
    # Test 4: Python availability
    print_info "تست 4/6: دسترسی Python..."
    if command -v python3 &> /dev/null; then
        print_success "✅ Python3 موجود است"
        test_passed=$((test_passed + 1))
    else
        print_error "❌ Python3 یافت نشد"
    fi
    
    # Test 5: Python import
    print_info "تست 5/6: تست import Python..."
    if command -v python3 &> /dev/null && [ -f "memory_toolkit.py" ]; then
        python3 -c "
import sys
sys.path.append('.')
try:
    from memory_toolkit import AdvancedMemoryToolkit
    print('✅ Python import موفق!')
    exit(0)
except Exception as e:
    print(f'❌ Python import شکست خورد: {e}')
    exit(1)
" && {
            print_success "✅ Python API کار می‌کند"
            test_passed=$((test_passed + 1))
        } || {
            print_error "❌ Python import ناموفق"
        }
    else
        print_warning "⚠️ Python یا memory_toolkit.py ناموجود"
    fi
    
    # Test 6: Basic functionality
    print_info "تست 6/6: عملکرد پایه..."
    if [ -e "/dev/advanced_memory" ] && command -v python3 &> /dev/null; then
        timeout 10 python3 -c "
import sys
sys.path.append('.')
try:
    from memory_toolkit import AdvancedMemoryToolkit
    amt = AdvancedMemoryToolkit()
    print('✅ اتصال اولیه موفق!')
    exit(0)
except Exception as e:
    print(f'❌ تست اتصال شکست خورد: {e}')
    exit(1)
" && {
            print_success "✅ عملکرد پایه کار می‌کند"
            test_passed=$((test_passed + 1))
        } || {
            print_error "❌ تست عملکرد پایه ناموفق"
        }
    else
        print_warning "⚠️ امکان تست عملکرد وجود ندارد"
    fi
    
    # Test summary
    echo ""
    print_step "نتیجه تست‌ها:"
    print_info "تست‌های موفق: $test_passed از $test_total"
    
    if [ $test_passed -eq $test_total ]; then
        print_success "🎉 همه تست‌ها موفق بود! سیستم آماده است"
        return 0
    elif [ $test_passed -ge 4 ]; then
        print_warning "⚠️ اکثر تست‌ها موفق بود، احتمالاً کار می‌کند"
        return 0
    else
        print_error "❌ تعداد زیادی تست شکست خورد!"
        print_warning "سیستم ممکن است درست کار نکند"
        return 1
    fi
    
    # Kernel logs
    print_info "آخرین لاگ‌های کرنل:"
    dmesg | grep -i "advanced memory\|memory_driver" | tail -5 || {
        print_warning "لاگ خاصی پیدا نشد"
    }
}

# Create update script
create_update_script() {
    print_step "ایجاد اسکریپت آپدیت..."
    
    cat > update.sh << 'EOF'
#!/bin/bash
# 🔄 Advanced Memory Toolkit Update Script v2.0

# Color variables
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables
REPO_URL="https://github.com/mohammadamin382/AMT-toolkit.git"
CURRENT_DIR=$(pwd)
BACKUP_DIR="$HOME/.amt_backup"
VERSION_FILE=".amt_version"
INSTALL_FILE=".amt_installed"
CURRENT_VERSION="2.0.0"

print_step() { echo -e "${BLUE}🔧 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }
print_info() { echo -e "${CYAN}ℹ️  $1${NC}"; }

print_banner() {
    echo -e "${PURPLE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    AMT Update Script v2.0                   ║"
    echo "║              Advanced Memory Toolkit Updater                ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "این اسکریپت باید با root اجرا بشه!"
        print_info "استفاده: sudo bash update.sh"
        exit 1
    fi
}

# Check if AMT is installed
check_installation() {
    if [ ! -f "$INSTALL_FILE" ]; then
        print_error "AMT نصب نشده است!"
        print_info "ابتدا setup.sh را اجرا کنید"
        exit 1
    fi
    
    INSTALLED_VERSION=$(cat "$INSTALL_FILE" 2>/dev/null || echo "unknown")
    print_info "نسخه فعلی: $INSTALLED_VERSION"
}

# Check internet connectivity
check_internet() {
    print_step "بررسی اتصال اینترنت..."
    if ping -c 1 8.8.8.8 &> /dev/null; then
        print_success "اتصال اینترنت فعال! 🌐"
        return 0
    else
        print_error "اتصال اینترنت برقرار نیست! 📡"
        return 1
    fi
}

# Check for updates
check_for_updates() {
    print_step "بررسی آپدیت‌های جدید..."
    
    if ! check_internet; then
        print_error "نمی‌تونم آپدیت رو چک کنم بدون اینترنت!"
        exit 1
    fi
    
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    print_info "دانلود اطلاعات آپدیت..."
    if git clone --depth 1 "$REPO_URL" update_check &> /dev/null; then
        cd update_check
        if [ -f "setup.sh" ]; then
            NEW_VERSION=$(grep 'CURRENT_VERSION=' setup.sh | cut -d'"' -f2)
            OLD_VERSION=$(cat "$CURRENT_DIR/$INSTALL_FILE" 2>/dev/null || echo "unknown")
            
            print_info "نسخه فعلی: $OLD_VERSION"
            print_info "نسخه جدید: $NEW_VERSION"
            
            if [ "$NEW_VERSION" != "$OLD_VERSION" ]; then
                print_success "آپدیت جدید موجود است! 🎉"
                cd "$CURRENT_DIR"
                rm -rf "$TEMP_DIR"
                return 0
            else
                print_success "شما آخرین نسخه رو دارید! ✨"
                cd "$CURRENT_DIR"
                rm -rf "$TEMP_DIR"
                return 1
            fi
        fi
    fi
    
    cd "$CURRENT_DIR"
    rm -rf "$TEMP_DIR"
    print_error "نمی‌تونم آپدیت رو چک کنم!"
    return 1
}

# Perform update
perform_update() {
    print_step "شروع آپدیت..."
    
    # Create backup
    print_info "ایجاد نسخه پشتیبان..."
    mkdir -p "$BACKUP_DIR"
    BACKUP_NAME="amt_backup_$(date +%Y%m%d_%H%M%S)"
    cp -r "$CURRENT_DIR" "$BACKUP_DIR/$BACKUP_NAME"
    print_success "نسخه پشتیبان: $BACKUP_DIR/$BACKUP_NAME"
    
    # Download latest version
    print_info "دانلود آخرین نسخه..."
    TEMP_UPDATE_DIR=$(mktemp -d)
    cd "$TEMP_UPDATE_DIR"
    
    if git clone "$REPO_URL" amt_update; then
        print_success "دانلود موفقیت‌آمیز! 📥"
        
        # Stop current module
        if lsmod | grep -q "memory_driver"; then
            print_info "متوقف کردن ماژول فعلی..."
            rmmod memory_driver 2>/dev/null || true
        fi
        
        # Clean old build files
        cd "$CURRENT_DIR"
        make -f driver_Makefile clean 2>/dev/null || true
        
        # Backup important files
        cp "$INSTALL_FILE" "${INSTALL_FILE}.bak" 2>/dev/null || true
        
        # Copy new files (exclude .git and preserve some files)
        print_info "کپی فایل‌های جدید..."
        rsync -av --exclude='.git' --exclude="$INSTALL_FILE" "$TEMP_UPDATE_DIR/amt_update/" "$CURRENT_DIR/"
        chmod +x "$CURRENT_DIR/setup.sh"
        chmod +x "$CURRENT_DIR/update.sh"
        
        # Update version
        NEW_VERSION=$(grep 'CURRENT_VERSION=' setup.sh | cut -d'"' -f2)
        echo "$NEW_VERSION" > "$INSTALL_FILE"
        
        print_success "آپدیت فایل‌ها کامل شد! 🎉"
        
        # Rebuild and reinstall
        print_info "ریبیلد و نصب مجدد..."
        
        # Source the new setup functions
        . "./setup.sh" --source-only 2>/dev/null || {
            print_warning "نمی‌تونم setup.sh جدید رو لود کنم، از روش قدیمی استفاده می‌کنم"
            # Fallback: basic reinstallation
            make -f driver_Makefile clean
            make -f driver_Makefile
            insmod memory_driver.ko
            chmod 666 /dev/advanced_memory 2>/dev/null || true
        }
        
        # Cleanup
        rm -rf "$TEMP_UPDATE_DIR"
        
        print_success "آپدیت کامل شد! 🚀"
        print_info "نسخه جدید: $NEW_VERSION"
        
    else
        print_error "دانلود آپدیت شکست خورد! 💥"
        cd "$CURRENT_DIR"
        rm -rf "$TEMP_UPDATE_DIR"
        exit 1
    fi
}

# Main function
main() {
    print_banner
    
    check_root
    check_installation
    
    if check_for_updates; then
        echo -n "آیا می‌خواهید آپدیت کنید؟ (y/n): "
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            perform_update
        else
            print_info "آپدیت لغو شد"
        fi
    else
        print_info "آپدیت جدیدی موجود نیست"
    fi
}

# Handle command line arguments
case "${1:-}" in
    --check)
        check_root
        check_installation
        check_for_updates
        ;;
    --force)
        check_root
        check_installation
        perform_update
        ;;
    --help)
        echo "استفاده: sudo bash update.sh [options]"
        echo "Options:"
        echo "  --check    فقط بررسی آپدیت"
        echo "  --force    آپدیت اجباری"
        echo "  --help     نمایش راهنما"
        ;;
    *)
        main
        ;;
esac
EOF

    chmod +x update.sh
    print_success "اسکریپت آپدیت ایجاد شد: update.sh 🔄"
}

# Create enhanced uninstall script
create_uninstall_script() {
    print_step "ایجاد اسکریپت حذف..."
    
    cat > uninstall.sh << 'EOF'
#!/bin/bash
# 🗑️ Advanced Memory Toolkit Uninstaller v2.0

# Color variables
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_step() { echo -e "${BLUE}🔧 $1${NC}"; }
print_success() { echo -e "${GREEN}✅ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
print_error() { echo -e "${RED}❌ $1${NC}"; }

echo "🗑️ شروع حذف Advanced Memory Toolkit..."

# Check root
if [[ $EUID -ne 0 ]]; then
    print_error "این اسکریپت باید با root اجرا بشه!"
    exit 1
fi

# Remove module
if lsmod | grep -q "memory_driver"; then
    print_step "حذف ماژول کرنل..."
    rmmod memory_driver 2>/dev/null && print_success "ماژول حذف شد!" || print_warning "مشکل در حذف ماژول!"
else
    print_step "ماژول بارگذاری نشده"
fi

# Clean build files
print_step "پاک کردن فایل‌های ساخته شده..."
make -f driver_Makefile clean 2>/dev/null || true
rm -f *.ko *.o *.mod.c *.mod *.symvers *.order .*.cmd 2>/dev/null || true
rm -rf .tmp_versions/ 2>/dev/null || true

# Remove installation markers
rm -f .amt_version .amt_installed 2>/dev/null || true

# Remove scripts
echo -n "آیا می‌خواهید اسکریپت‌های مدیریتی را هم حذف کنید؟ (y/n): "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    rm -f update.sh 2>/dev/null || true
    print_success "اسکریپت‌های مدیریتی حذف شدند"
fi

# Remove backup directories
echo -n "آیا می‌خواهید پشتیبان‌ها را هم حذف کنید؟ (y/n): "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    rm -rf "$HOME/.amt_backup" 2>/dev/null || true
    print_success "پشتیبان‌ها حذف شدند"
fi

print_success "حذف کامل شد!"
print_warning "فایل‌های اصلی پروژه (.c, .py) حفظ شدند"
print_step "👋 تا دیدار دوباره!"
EOF

    chmod +x uninstall.sh
    print_success "اسکریپت حذف ایجاد شد: uninstall.sh 🗑️"
}

# Mark installation as successful
mark_installation_successful() {
    echo "$CURRENT_VERSION" > "$INSTALL_FILE"
    echo "$CURRENT_VERSION" > "$VERSION_FILE"
    print_success "نصب به عنوان موفق ثبت شد! 📝"
}

# Show usage guide
show_usage_guide() {
    print_step "راهنمای استفاده:"
    echo ""
    print_info "🐍 برای تست کامل:"
    echo "   sudo python3 test1.py"
    echo ""
    print_info "🔧 برای استفاده CLI:"
    echo "   sudo python3 memory_toolkit.py --help"
    echo ""
    print_info "📖 خواندن حافظه:"
    echo "   sudo python3 memory_toolkit.py --read-phys 0x1000 256"
    echo ""
    print_info "🔄 تبدیل آدرس:"
    echo "   sudo python3 memory_toolkit.py --v2p 0xffffffff81000000"
    echo ""
    print_info "🔄 آپدیت سیستم:"
    echo "   sudo bash update.sh"
    echo ""
    print_info "🗑️ حذف کامل:"
    echo "   sudo bash uninstall.sh"
    echo ""
    print_warning "⚠️ همیشه با sudo اجرا کنید!"
}

# Main installation function
install_amt() {
    check_root
    check_installation_status
    check_kernel
    install_dependencies
    check_project_files
    build_kernel_module
    load_kernel_module
    setup_permissions
    
    if comprehensive_test; then
        create_update_script
        create_uninstall_script
        mark_installation_successful
        
        print_success "🎊 نصب کامل و موفقیت‌آمیز بود!"
        show_usage_guide
    else
        print_error "تست‌ها شکست خوردند!"
        print_warning "نصب ممکن است ناقص باشد"
        exit 1
    fi
}

# Main execution
main() {
    print_banner
    
    echo "🎪 Advanced Memory Toolkit Installation v2.0"
    echo "🕐 $(date)"
    echo ""
    
    print_warning "⚠️ هشدار: این ابزار فقط برای تست و آموزش است!"
    print_warning "⚠️ در محیط تولید استفاده نکنید!"
    echo ""
    
    # If sourced, don't run main installation
    if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
        install_amt
        
        echo ""
        print_success "🎊 نصب تمام شد!"
        print_info "💡 برای آپدیت: sudo bash update.sh"
        print_info "💡 برای حذف: sudo bash uninstall.sh"
        print_warning "⚠️ With great power comes great responsibility!"
    fi
}

# Handle special arguments
case "${1:-}" in
    --status)
        check_root
        show_current_status
        ;;
    --help)
        show_usage_guide
        ;;
    --source-only)
        # Don't run main when sourced
        ;;
    *)
        main "$@"
        ;;
esac
