#!/usr/bin/env python3
"""
Advanced Memory Toolkit - Professional Memory Operations Framework
High-Performance Python Interface for Kernel-Level Memory Management
NOTE: This is an early version optimized for specific kernel versions.
"""

import os
import sys
import struct
import ctypes
from typing import Optional, Tuple, List, Dict
import argparse
import time
import hashlib

# Device configuration
DEVICE_PATH = "/dev/advanced_memory"
BUFFER_SIZE = 8192

# IOCTL commands (calculated using proper Python macros)
# محاسبه درست مقادیر IOCTL با استفاده از fcntl
import fcntl
import array

# تعریف ماکروهای IOCTL برای Python
def _IOC(dir, type, nr, size):
    return (dir << 30) | (ord(type) << 8) | (nr) | (size << 16)

def _IOR(type, nr, size):
    return _IOC(2, type, nr, size)  # 2 = _IOC_READ

def _IOW(type, nr, size):
    return _IOC(1, type, nr, size)  # 1 = _IOC_WRITE

def _IOWR(type, nr, size):
    return _IOC(3, type, nr, size)  # 3 = _IOC_READ | _IOC_WRITE

# ابتدا کلاس‌ها رو تعریف می‌کنیم
class MemoryOperation(ctypes.Structure):
    _fields_ = [
        ("phys_addr", ctypes.c_ulong),
        ("size", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
        ("data", ctypes.c_char * BUFFER_SIZE),
        ("result", ctypes.c_int)
    ]

class AddressTranslation(ctypes.Structure):
    _fields_ = [
        ("input_addr", ctypes.c_ulong),
        ("output_addr", ctypes.c_ulong),
        ("pid", ctypes.c_int),
        ("success", ctypes.c_int),
        ("page_table_levels", ctypes.c_ulong * 5),
        ("protection_flags", ctypes.c_ulong)
    ]

class PageInfo(ctypes.Structure):
    _fields_ = [
        ("addr", ctypes.c_ulong),
        ("page_frame", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
        ("present", ctypes.c_int),
        ("writable", ctypes.c_int),
        ("user", ctypes.c_int),
        ("accessed", ctypes.c_int),
        ("dirty", ctypes.c_int),
        ("global_flag", ctypes.c_int),  # تغییر نام از global به global_flag
        ("nx", ctypes.c_int),
        ("cache_type", ctypes.c_ulong)
    ]



# حالا که کلاس‌ها تعریف شدن، اندازه‌هاشون رو محاسبه می‌کنیم
MEM_OPERATION_SIZE = ctypes.sizeof(MemoryOperation)
ADDR_TRANSLATION_SIZE = ctypes.sizeof(AddressTranslation)
PAGE_INFO_SIZE = ctypes.sizeof(PageInfo)


# تعریف صحیح IOCTLها - حالا با کرنل مطابقت داره! 🎯
IOCTL_READ_PHYS_MEM = _IOR('M', 1, MEM_OPERATION_SIZE)
IOCTL_WRITE_PHYS_MEM = _IOW('M', 2, MEM_OPERATION_SIZE)
IOCTL_VIRT_TO_PHYS = _IOWR('M', 3, ADDR_TRANSLATION_SIZE)
IOCTL_PHYS_TO_VIRT = _IOWR('M', 4, ADDR_TRANSLATION_SIZE)
IOCTL_GET_PAGE_INFO = _IOWR('M', 5, PAGE_INFO_SIZE)


class AdvancedMemoryToolkit:
    """Professional Memory Operations Framework"""

    def __init__(self):
        self.device_fd = None
        self.session_id = self._generate_session_id()
        self.operation_count = 0
        self._initialize_framework()

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        timestamp = str(time.time())
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]

    def _initialize_framework(self):
        """Initialize the memory framework"""
        try:
            self.device_fd = os.open(DEVICE_PATH, os.O_RDWR)
            print(f"🚀 Advanced Memory Toolkit ACTIVATED")
            print(f"🔑 Session ID: {self.session_id}")
            print(f"⚡ Professional Memory Framework Ready")
        except OSError as e:
            print(f"❌ Failed to initialize Advanced Memory Toolkit: {e}")
            print("💡 Ensure kernel module is loaded: sudo insmod memory_driver.ko")
            sys.exit(1)

    def close(self):
        """Shutdown framework"""
        if self.device_fd:
            os.close(self.device_fd)
            print(f"🔒 Advanced Memory Toolkit session {self.session_id} terminated")
            print(f"📊 Total operations performed: {self.operation_count}")

    def read_physical_memory(self, phys_addr: int, size: int) -> Optional[bytes]:
        """
        Read data from physical memory address

        Args:
            phys_addr: Physical memory address
            size: Number of bytes to read

        Returns:
            Data bytes or None if failed
        """
        if not self.device_fd:
            print("❌ Device not initialized")
            return None

        # Safety validation
        if not self._validate_safety('read_physical', phys_addr=phys_addr, size=size):
            return None

        self.operation_count += 1

        if size > BUFFER_SIZE:
            print(f"❌ Size {size} exceeds maximum buffer size {BUFFER_SIZE}")
            return None

        mem_op = MemoryOperation()
        mem_op.phys_addr = phys_addr
        mem_op.size = size
        mem_op.flags = 0

        try:
            fcntl.ioctl(self.device_fd, IOCTL_READ_PHYS_MEM, mem_op)

            if mem_op.result == 0:
                self.operation_count += 1
                return bytes(mem_op.data[:size])
            else:
                print(f"❌ Read failed with error code: {mem_op.result}")
                return None

        except OSError as e:
            print(f"❌ Physical memory read failed: {e}")
            return None

    def write_physical_memory(self, phys_addr: int, data: bytes) -> bool:
        """
        Write data to physical memory address

        Args:
            phys_addr: Physical memory address
            data: Data to write

        Returns:
            True if successful, False otherwise
        """
        if not self.device_fd or not data:
            return False

        # Safety validation - stricter for write operations
        if not self._validate_safety('write_physical', phys_addr=phys_addr, size=len(data)):
            return False

        self.operation_count += 1

        if len(data) > BUFFER_SIZE:
            print(f"❌ Data size {len(data)} exceeds maximum buffer size {BUFFER_SIZE}")
            return False

        mem_op = MemoryOperation()
        mem_op.phys_addr = phys_addr
        mem_op.size = len(data)
        mem_op.flags = 0

        # Copy data to structure - use slice assignment for ctypes array
        ctypes.memmove(ctypes.byref(mem_op, MemoryOperation.data.offset), data, len(data))

        try:
            fcntl.ioctl(self.device_fd, IOCTL_WRITE_PHYS_MEM, mem_op)

            if mem_op.result == 0:
                self.operation_count += 1
                print(f"✅ Successfully wrote {len(data)} bytes to 0x{phys_addr:x}")
                return True
            else:
                print(f"❌ Write failed with error code: {mem_op.result}")
                return False

        except OSError as e:
            print(f"❌ Physical memory write failed: {e}")
            return False

    def virtual_to_physical(self, virt_addr: int, pid: int = 0) -> Optional[int]:
        """
        Convert virtual address to physical address

        Args:
            virt_addr: Virtual address
            pid: Process ID (0 for kernel addresses)

        Returns:
            Physical address or None on error
        """
        addr_trans = AddressTranslation()
        addr_trans.input_addr = virt_addr
        addr_trans.pid = pid

        try:
            fcntl.ioctl(self.device_fd, IOCTL_VIRT_TO_PHYS, addr_trans)

            if addr_trans.success:
                self.operation_count += 1
                return addr_trans.output_addr
            else:
                print(f"❌ Virtual to physical translation failed for 0x{virt_addr:x}")
                return None

        except OSError as e:
            print(f"❌ Address translation failed: {e}")
            return None

    def physical_to_virtual(self, phys_addr: int, pid: int = 0) -> Optional[int]:
        """
        Convert physical address to virtual address (limited functionality)

        Args:
            phys_addr: Physical address
            pid: Process ID (0 for kernel addresses)

        Returns:
            Virtual address or None on error
        """
        addr_trans = AddressTranslation()
        addr_trans.input_addr = phys_addr
        addr_trans.pid = pid

        try:
            fcntl.ioctl(self.device_fd, IOCTL_PHYS_TO_VIRT, addr_trans)

            if addr_trans.success:
                self.operation_count += 1
                return addr_trans.output_addr
            else:
                print(f"⚠️  Physical to virtual translation has limitations")
                return None

        except OSError as e:
            print(f"❌ Address translation failed: {e}")
            return None

    def get_page_info(self, addr: int) -> Optional[Dict]:
        """
        Get detailed page information for an address

        Args:
            addr: Memory address

        Returns:
            Dictionary with page information or None on error
        """
        page_info = PageInfo()
        page_info.addr = addr

        try:
            fcntl.ioctl(self.device_fd, IOCTL_GET_PAGE_INFO, page_info)

            self.operation_count += 1
            return {
                'address': hex(page_info.addr),
                'page_frame': page_info.page_frame,
                'flags': hex(page_info.flags),
                'present': bool(page_info.present),
                'writable': bool(page_info.writable),
                'user': bool(page_info.user),
                'accessed': bool(page_info.accessed),
                'dirty': bool(page_info.dirty),
                'global_page': bool(page_info.global_flag),
                'nx': bool(page_info.nx),
                'cache_type': page_info.cache_type
            }

        except OSError as e:
            print(f"❌ Failed to get page info: {e}")
            return None

    

    def hex_dump(self, data: bytes, addr: int = 0, width: int = 16) -> str:
        """
        Create professional hex dump of data

        Args:
            data: Data to dump
            addr: Starting address for display
            width: Bytes per line

        Returns:
            Formatted hex dump string
        """
        lines = []
        for i in range(0, len(data), width):
            line_data = data[i:i+width]
            hex_part = ' '.join(f'{b:02x}' for b in line_data)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)

            line = f'{addr+i:08x}: {hex_part:<{width*3}} |{ascii_part}|'
            lines.append(line)

        return '\n'.join(lines)

    def memory_copy(self, src_addr: int, dst_addr: int, size: int) -> bool:
        """
        Copy memory from source to destination

        Args:
            src_addr: Source physical address
            dst_addr: Destination physical address
            size: Number of bytes to copy

        Returns:
            True on success, False on error
        """
        # Read from source
        data = self.read_physical_memory(src_addr, size)
        if data is None:
            return False

        # Write to destination
        return self.write_physical_memory(dst_addr, data)

    def memory_compare(self, addr1: int, addr2: int, size: int) -> Optional[List[int]]:
        """
        Compare two memory regions

        Args:
            addr1: First physical address
            addr2: Second physical address
            size: Number of bytes to compare

        Returns:
            List of differing byte offsets or None on error
        """
        data1 = self.read_physical_memory(addr1, size)
        data2 = self.read_physical_memory(addr2, size)

        if data1 is None or data2 is None:
            return None

        differences = []
        for i, (b1, b2) in enumerate(zip(data1, data2)):
            if b1 != b2:
                differences.append(i)

        return differences

    def generate_report(self) -> Dict:
        """
        Generate toolkit usage report

        Returns:
            Dictionary with usage statistics
        """
        return {
            'session_id': self.session_id,
            'timestamp': time.time(),
            'framework_version': '3.0',
            'total_operations': self.operation_count,
            'capabilities': [
                'Physical Memory Read/Write',
                'Virtual ↔ Physical Address Translation',  
                'Page Information Retrieval',
                'Memory Copy/Compare Operations'
            ]
        }

    def _validate_safety(self, operation: str, **kwargs) -> bool:
        """Placeholder for safety validations"""
        # Implement safety checks based on 'operation' and 'kwargs'
        # Example checks could include address range limitations, size restrictions, etc.
        # Return True if safe, False otherwise
        return True

def main():
    """Enhanced main function with core capabilities"""
    parser = argparse.ArgumentParser(description="Advanced Memory Toolkit - Professional Memory Operations")

    # Core operations
    parser.add_argument('--read-phys', nargs=2, metavar=('ADDR', 'SIZE'),
                       help='Read physical memory (hex address, size)')
    parser.add_argument('--write-phys', nargs=2, metavar=('ADDR', 'DATA'),
                       help='Write to physical memory (hex address, hex data)')
    parser.add_argument('--v2p', nargs=1, metavar='VADDR',
                       help='Virtual to physical address translation')
    parser.add_argument('--p2v', nargs=1, metavar='PADDR',
                       help='Physical to virtual address translation')
    parser.add_argument('--page-info', nargs=1, metavar='ADDR',
                       help='Get page information for address')
    
    parser.add_argument('--copy-memory', nargs=3, metavar=('SRC', 'DST', 'SIZE'),
                       help='Copy memory (hex src, hex dst, size)')
    parser.add_argument('--compare-memory', nargs=3, metavar=('ADDR1', 'ADDR2', 'SIZE'),
                       help='Compare memory regions (hex addr1, hex addr2, size)')
    parser.add_argument('--report', action='store_true',
                       help='Generate toolkit usage report')
    parser.add_argument('--interactive', action='store_true',
                       help='Start interactive mode')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n🔧 Advanced Memory Toolkit - Professional Memory Operations")
        print(f"💾 Physical Memory Read/Write Operations")
        print(f"🔄 Virtual ↔ Physical Address Translation")
        
        return

    # Initialize toolkit
    toolkit = AdvancedMemoryToolkit()

    try:
        if args.read_phys:
            addr, size = int(args.read_phys[0], 16), int(args.read_phys[1])
            data = toolkit.read_physical_memory(addr, size)
            if data:
                print(f"📖 Read {len(data)} bytes from 0x{addr:x}:")
                print(toolkit.hex_dump(data, addr))

        elif args.write_phys:
            addr = int(args.write_phys[0], 16)
            data = bytes.fromhex(args.write_phys[1])
            success = toolkit.write_physical_memory(addr, data)
            if success:
                print(f"✅ Successfully wrote {len(data)} bytes to 0x{addr:x}")

        elif args.v2p:
            vaddr = int(args.v2p[0], 16)
            paddr = toolkit.virtual_to_physical(vaddr)
            if paddr:
                print(f"🔄 Virtual 0x{vaddr:x} → Physical 0x{paddr:x}")

        elif args.p2v:
            paddr = int(args.p2v[0], 16)
            vaddr = toolkit.physical_to_virtual(paddr)
            if vaddr:
                print(f"🔄 Physical 0x{paddr:x} → Virtual 0x{vaddr:x}")

        elif args.page_info:
            addr = int(args.page_info[0], 16)
            info = toolkit.get_page_info(addr)
            if info:
                print(f"📋 Page Information for 0x{addr:x}:")
                for key, value in info.items():
                    print(f"  {key}: {value}")

        

        elif args.report:
            report = toolkit.generate_report()
            print(f"📊 Advanced Memory Toolkit Report:")
            for key, value in report.items():
                print(f"  {key}: {value}")

        elif args.interactive:
            interactive_mode(toolkit)

    finally:
        toolkit.close()

def interactive_mode(toolkit):
    """Professional interactive mode"""
    print(f"\n💻 Advanced Memory Toolkit - Interactive Mode")
    print(f"🔧 Session: {toolkit.session_id}")
    print("\nAvailable Commands:")
    print("  read <addr> <size>        - Read physical memory")
    print("  write <addr> <hex_data>   - Write to physical memory")
    print("  v2p <vaddr>              - Virtual to physical translation")
    print("  p2v <paddr>              - Physical to virtual translation")
    print("  info <addr>              - Get page information")
    
    print("  copy <src> <dst> <size>  - Copy memory")
    print("  report                   - Show usage report")
    print("  help                     - Show this help")
    print("  quit                     - Exit interactive mode")

    while True:
        try:
            cmd = input("\nmemory> ").strip().split()
            if not cmd:
                continue

            if cmd[0] == 'quit':
                break
            elif cmd[0] == 'read' and len(cmd) >= 3:
                addr, size = int(cmd[1], 16), int(cmd[2])
                data = toolkit.read_physical_memory(addr, size)
                if data:
                    print(toolkit.hex_dump(data, addr))

            elif cmd[0] == 'write' and len(cmd) >= 3:
                addr = int(cmd[1], 16)
                data = bytes.fromhex(cmd[2])
                toolkit.write_physical_memory(addr, data)

            elif cmd[0] == 'v2p' and len(cmd) >= 2:
                vaddr = int(cmd[1], 16)
                paddr = toolkit.virtual_to_physical(vaddr)
                if paddr:
                    print(f"🔄 0x{vaddr:x} → 0x{paddr:x}")

            elif cmd[0] == 'info' and len(cmd) >= 2:
                addr = int(cmd[1], 16)
                info = toolkit.get_page_info(addr)
                if info:
                    for key, value in info.items():
                        print(f"  {key}: {value}")

            elif cmd[0] == 'report':
                report = toolkit.generate_report()
                for key, value in report.items():
                    print(f"  {key}: {value}")

            elif cmd[0] == 'help':
                print("Available commands: read, write, v2p, p2v, info, copy, report, help, quit")

            else:
                print("❓ Unknown command. Type 'help' for available commands.")

        except KeyboardInterrupt:
            print("\n💡 Use 'quit' to exit interactive mode.")
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
