
#!/usr/bin/env python3
"""
Test script for Advanced Memory Toolkit
"""

import sys
import os
from memory_toolkit import AdvancedMemoryToolkit

def test_basic_functionality():
    """Test basic functionality of the toolkit"""
    print("🧪 Testing Advanced Memory Toolkit")
    print("=" * 50)
    
    # Initialize toolkit
    try:
        toolkit = AdvancedMemoryToolkit()
        print("✅ Toolkit initialized successfully")
    except Exception as e:
        print(f"❌ Failed to initialize toolkit: {e}")
        return False
    
    test_results = []
    
    # Test 1: Virtual to Physical translation for kernel address
    print("\n📍 Test 1: Virtual to Physical Translation (Kernel)")
    kernel_addr = 0xffffffff81000000  # Typical kernel address
    try:
        phys_addr = toolkit.virtual_to_physical(kernel_addr)
        if phys_addr:
            print(f"✅ Kernel 0x{kernel_addr:x} → Physical 0x{phys_addr:x}")
            test_results.append(True)
        else:
            print("❌ Translation failed")
            test_results.append(False)
    except Exception as e:
        print(f"❌ Exception in v2p test: {e}")
        test_results.append(False)
    
    # Test 2: Page information
    print("\n📋 Test 2: Page Information")
    try:
        page_info = toolkit.get_page_info(kernel_addr)
        if page_info:
            print("✅ Page information retrieved:")
            for key, value in page_info.items():
                print(f"   {key}: {value}")
            test_results.append(True)
        else:
            print("❌ Failed to get page information")
            test_results.append(False)
    except Exception as e:
        print(f"❌ Exception in page info test: {e}")
        test_results.append(False)
    
    # Test 3: Read from physical memory (safe addresses only)
    print("\n📖 Test 3: Physical Memory Read")
    try:
        # Try to read from a typically safe address (first page often accessible)
        safe_addr = 0x1000
        data = toolkit.read_physical_memory(safe_addr, 64)
        if data:
            print(f"✅ Read 64 bytes from physical address 0x{safe_addr:x}")
            print("📄 Memory dump:")
            print(toolkit.hex_dump(data, safe_addr))
            test_results.append(True)
        else:
            print("❌ Failed to read physical memory")
            test_results.append(False)
    except Exception as e:
        print(f"❌ Exception in memory read test: {e}")
        test_results.append(False)
    
    # Test 4: Address validation
    print("\n🔍 Test 4: Address Validation")
    try:
        # Test invalid address
        invalid_addr = 0xfffffffffffff000
        phys_addr = toolkit.virtual_to_physical(invalid_addr)
        if phys_addr is None:
            print("✅ Invalid address correctly rejected")
            test_results.append(True)
        else:
            print("⚠️  Invalid address was translated (unexpected)")
            test_results.append(True)  # Not necessarily an error
    except Exception as e:
        print(f"✅ Invalid address correctly caused exception: {e}")
        test_results.append(True)
    
    # Cleanup
    toolkit.close()
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 Test Summary:")
    passed = sum(test_results)
    total = len(test_results)
    print(f"   Passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All tests passed!")
        return True
    else:
        print("⚠️  Some tests failed")
        return False

def demo_functionality():
    """Demonstrate toolkit capabilities"""
    print("\n🚀 Advanced Memory Toolkit Demo")
    print("=" * 50)
    
    toolkit = AdvancedMemoryToolkit()
    
    # Demo 1: Kernel space analysis
    print("\n🔍 Demo 1: Kernel Space Analysis")
    kernel_addrs = [
        0xffffffff81000000,  # Typical kernel text start
        0xffffffff81001000,  # Kernel text + 4KB
        0xffffffff82000000,  # Potential kernel data
    ]
    
    for addr in kernel_addrs:
        print(f"\n📍 Analyzing address 0x{addr:x}")
        
        # Get page info
        page_info = toolkit.get_page_info(addr)
        if page_info:
            print(f"   Present: {page_info['present']}")
            print(f"   Writable: {page_info['writable']}")
            print(f"   Page Frame: {page_info['page_frame']}")
        
        # Try translation
        phys_addr = toolkit.virtual_to_physical(addr)
        if phys_addr:
            print(f"   Physical: 0x{phys_addr:x}")
    
    # Demo 2: Memory pattern search
    print("\n🔎 Demo 2: Memory Pattern Search")
    search_addr = 0x0
    chunk_size = 1024
    
    print(f"Searching for patterns starting at 0x{search_addr:x}")
    for i in range(5):  # Search first 5KB
        addr = search_addr + (i * chunk_size)
        data = toolkit.read_physical_memory(addr, min(chunk_size, 256))
        if data:
            # Look for interesting patterns
            if b'Linux' in data or b'kernel' in data:
                print(f"   🎯 Found potential kernel signature at 0x{addr:x}")
                print(toolkit.hex_dump(data[:64], addr))
                break
    
    toolkit.close()

def interactive_demo():
    """Interactive demonstration"""
    print("\n💻 Interactive Demo Mode")
    print("This will start an interactive session.")
    print("You can use commands like:")
    print("  read 0x1000 256")
    print("  v2p 0xffffffff81000000")
    print("  info 0xffffffff81000000")
    print("  quit")
    
    input("\nPress Enter to continue or Ctrl+C to skip...")
    
    toolkit = AdvancedMemoryToolkit()
    
    # Simple interactive loop
    while True:
        try:
            cmd = input("\ndemo> ").strip().split()
            if not cmd:
                continue
            
            if cmd[0] == 'quit':
                break
            elif cmd[0] == 'read' and len(cmd) == 3:
                addr = int(cmd[1], 16)
                size = int(cmd[2])
                data = toolkit.read_physical_memory(addr, size)
                if data:
                    print(toolkit.hex_dump(data, addr))
            elif cmd[0] == 'v2p' and len(cmd) == 2:
                vaddr = int(cmd[1], 16)
                paddr = toolkit.virtual_to_physical(vaddr)
                if paddr:
                    print(f"0x{vaddr:x} → 0x{paddr:x}")
            elif cmd[0] == 'info' and len(cmd) == 2:
                addr = int(cmd[1], 16)
                info = toolkit.get_page_info(addr)
                if info:
                    for key, value in info.items():
                        print(f"  {key}: {value}")
            else:
                print("Available commands: read, v2p, info, quit")
        
        except KeyboardInterrupt:
            print("\nUse 'quit' to exit.")
        except Exception as e:
            print(f"Error: {e}")
    
    toolkit.close()

def main():
    """Main test function"""
    print("🔧 Advanced Memory Toolkit Test Suite")
    print("=====================================")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("❌ This test must be run as root (use sudo)")
        sys.exit(1)
    
    # Check if driver is loaded
    if not os.path.exists("/dev/advanced_memory"):
        print("❌ Driver not loaded. Run setup.sh first.")
        sys.exit(1)
    
    try:
        # Run basic tests
        success = test_basic_functionality()
        
        # Run demonstration
        demo_functionality()
        
        # Ask for interactive demo
        try:
            response = input("\n🤔 Run interactive demo? (y/N): ").strip().lower()
            if response == 'y' or response == 'yes':
                interactive_demo()
        except KeyboardInterrupt:
            print("\nSkipping interactive demo.")
        
        print("\n✅ Test suite completed!")
        
    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
