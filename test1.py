from memory_toolkit import AdvancedMemoryToolkit
import os
import random

def pretty_result(name, ok, msg=''):
    mark = "✅" if ok else "❌"
    print(f"{mark} {name}")
    if not ok:
        print(f"   ⮑ {msg}")

def random_bytes(n):
    return os.urandom(n)

def main():
    addr = 0x300000
    test_size = 32
    test_data = random_bytes(test_size)
    failed = False
    results = []

    print("🚀 شروع تست جامع Advanced Memory Toolkit")
    toolkit = AdvancedMemoryToolkit()

    # 1. تست نوشتن حافظه
    try:
        ok = toolkit.write_physical_memory(addr, test_data)
        pretty_result("نوشتن حافظه فیزیکی", ok)
        results.append(("نوشتن حافظه فیزیکی", ok))
    except Exception as e:
        pretty_result("نوشتن حافظه فیزیکی", False, str(e))
        results.append(("نوشتن حافظه فیزیکی", False))
        failed = True

    # 2. تست خواندن حافظه
    try:
        data = toolkit.read_physical_memory(addr, test_size)
        ok = (data == test_data)
        pretty_result("خواندن حافظه فیزیکی", ok, "" if ok else f"داده متفاوت است! خوانده شده: {data.hex()}")
        results.append(("خواندن حافظه فیزیکی", ok))
    except Exception as e:
        pretty_result("خواندن حافظه فیزیکی", False, str(e))
        results.append(("خواندن حافظه فیزیکی", False))
        failed = True

    # 3. تست تبدیل آدرس مجازی به فیزیکی و بالعکس
    try:
        import mmap
        import ctypes
        # یک بافر حافظه بساز و آدرسش رو بگیر
        mm = mmap.mmap(-1, test_size)
        mm.write(test_data)
        buf_addr = ctypes.addressof(ctypes.c_char.from_buffer(mm))
        v2p = toolkit.virtual_to_physical(buf_addr, os.getpid())
        if v2p is not None:
            pretty_result("تبدیل مجازی به فیزیکی", True)
            # حالا تست برعکس
            p2v = toolkit.physical_to_virtual(v2p, os.getpid())
            pretty_result("تبدیل فیزیکی به مجازی", p2v is not None)
            results.extend([("تبدیل مجازی به فیزیکی", True), ("تبدیل فیزیکی به مجازی", p2v is not None)])
        else:
            pretty_result("تبدیل مجازی به فیزیکی", False, "آدرس فیزیکی به دست نیامد")
            results.extend([("تبدیل مجازی به فیزیکی", False), ("تبدیل فیزیکی به مجازی", False)])
    except Exception as e:
        pretty_result("تبدیل آدرس‌ها", False, str(e))
        results.extend([("تبدیل مجازی به فیزیکی", False), ("تبدیل فیزیکی به مجازی", False)])
        failed = True

    # 4. تست اطلاعات صفحه
    try:
        page_info = toolkit.get_page_info(addr)
        ok = bool(page_info and 'page_frame' in page_info)
        pretty_result("دریافت اطلاعات صفحه", ok)
        results.append(("دریافت اطلاعات صفحه", ok))
    except Exception as e:
        pretty_result("دریافت اطلاعات صفحه", False, str(e))
        results.append(("دریافت اطلاعات صفحه", False))
        failed = True

    # 5. تست رمزنگاری و رمزگشایی
    try:
        key = os.urandom(32)
        iv = os.urandom(16)
        # حتماً اول داده رو بنویس تو حافظه
        toolkit.write_physical_memory(addr, test_data)
        encrypted = toolkit.encrypt_memory(addr, test_size, key, 'aes', iv)
        ok = encrypted is not None
        pretty_result("رمزنگاری حافظه", ok)
        results.append(("رمزنگاری حافظه", ok))
        if not ok:
            raise Exception("رمزنگاری شکست خورد")
        # حالا تست دیکریپت
        decrypted = toolkit.decrypt_memory(addr, test_size, key, 'aes', iv)
        ok = decrypted is not None
        pretty_result("رمزگشایی حافظه", ok)
        results.append(("رمزگشایی حافظه", ok))
    except Exception as e:
        pretty_result("رمزنگاری/رمزگشایی حافظه", False, str(e))
        results.extend([("رمزنگاری حافظه", False), ("رمزگشایی حافظه", False)])
        failed = True

    # 6. تست کپی حافظه
    try:
        src_addr = addr
        dst_addr = addr + 0x10000
        ok = toolkit.memory_copy(src_addr, dst_addr, test_size)
        pretty_result("کپی حافظه", ok)
        results.append(("کپی حافظه", ok))
        # تست بخونیم ببینیم درست کپی شده
        src_data = toolkit.read_physical_memory(src_addr, test_size)
        dst_data = toolkit.read_physical_memory(dst_addr, test_size)
        ok2 = (src_data == dst_data)
        pretty_result("بررسی صحت کپی", ok2)
        results.append(("بررسی صحت کپی", ok2))
    except Exception as e:
        pretty_result("کپی حافظه", False, str(e))
        results.extend([("کپی حافظه", False), ("بررسی صحت کپی", False)])
        failed = True

    # 7. تست مقایسه حافظه
    try:
        differences = toolkit.memory_compare(src_addr, dst_addr, test_size)
        ok = (differences == [])
        pretty_result("مقایسه حافظه", ok, "" if ok else f"تفاوت در offsetها: {differences}")
        results.append(("مقایسه حافظه", ok))
    except Exception as e:
        pretty_result("مقایسه حافظه", False, str(e))
        results.append(("مقایسه حافظه", False))
        failed = True

    # 8. تست گزارش
    try:
        report = toolkit.generate_report()
        ok = (report and 'total_operations' in report)
        pretty_result("گزارش toolkit", ok)
        results.append(("گزارش toolkit", ok))
    except Exception as e:
        pretty_result("گزارش toolkit", False, str(e))
        results.append(("گزارش toolkit", False))
        failed = True

    toolkit.close()
    print("\n==== جمع‌بندی نتایج ====")
    all_ok = True
    for name, ok in results:
        mark = "✅" if ok else "❌"
        print(f"{mark} {name}")
        if not ok:
            all_ok = False
    if all_ok:
        print("\n🎉 همه قابلیت‌ها با موفقیت تست شد!")
    else:
        print("\n⚠️ برخی قابلیت‌ها درست کار نکردند. خروجی بالا را بررسی کن.")

if __name__ == "__main__":
    main()
