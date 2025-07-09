from memory_toolkit import AdvancedMemoryToolkit

def main():
    # ایجاد instance از toolkit
    amt = AdvancedMemoryToolkit()

    # آدرس آزمایشی برای تست (مطابق محدوده امن ماژول خودت قرار بده!)
    addr = 0x200000

    # داده تستی
    data = b"MemoryTest123456"

    print("📤 نوشتن داده تستی در حافظه...")
    ok = amt.write_physical_memory(addr, data)
    if ok:
        print("✅ نوشتن موفقیت‌آمیز بود!")

    print("📥 خواندن داده از حافظه...")
    read = amt.read_physical_memory(addr, len(data))
    if read:
        print("🔍 داده خوانده شده:", read)
        print("🔍 hex dump:")
        print(amt.hex_dump(read, addr))

    print("🎯 مقایسه با داده اصلی:", "مطابقت دارد!" if read == data else "تفاوت دارد!")

    amt.close()

if __name__ == "__main__":
    main()
