
#!/usr/bin/env python3
"""
🧪 Advanced Memory Toolkit - Comprehensive Test Suite
"""

import sys
import os
import json
import time
import traceback
import random
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from memory_toolkit import AdvancedMemoryToolkit
except ImportError as e:
    print(f"❌ خطا در import: {e}")
    print("💡 مطمئن شوید که memory_toolkit.py در مسیر صحیح قرار دارد")
    sys.exit(1)


class ComprehensiveTestSuite:
    """مجموعه تست جامع برای AMT"""
    
    def __init__(self):
        self.toolkit = None
        self.test_results = []
        self.session_start_time = time.time()
        self.session_id = f"test_{int(time.time())}"
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.skipped_tests = 0
        
        # Test configuration
        self.test_addresses = [
            0x200000,   # Safe test address 1
            0x300000,   # Safe test address 2
            0x400000,   # Safe test address 3
            0x500000,   # Safe test address 4
        ]
        self.test_sizes = [16, 32, 64, 128, 256, 512, 1024]
        self.max_safe_size = 4096
        
    def setup_toolkit(self) -> bool:
        """راه‌اندازی toolkit"""
        try:
            self.toolkit = AdvancedMemoryToolkit()
            return True
        except Exception as e:
            self.log_error("toolkit_setup", f"Failed to initialize toolkit: {e}")
            return False
    
    def cleanup_toolkit(self):
        """پاکسازی toolkit"""
        if self.toolkit:
            try:
                self.toolkit.close()
            except:
                pass
    
    def log_test_result(self, test_name: str, success: bool, 
                       details: Dict = None, error_msg: str = None,
                       execution_time: float = 0, test_data: Dict = None):
        """ثبت نتیجه تست"""
        self.total_tests += 1
        
        if success:
            self.passed_tests += 1
            status = "PASS"
        else:
            self.failed_tests += 1
            status = "FAIL"
        
        result = {
            "test_name": test_name,
            "status": status,
            "timestamp": datetime.now().isoformat(),
            "execution_time_ms": round(execution_time * 1000, 2),
            "details": details or {},
            "test_data": test_data or {},
            "error_message": error_msg
        }
        
        self.test_results.append(result)
        
        # Console output
        status_icon = "✅" if success else "❌"
        print(f"{status_icon} {test_name} ({execution_time*1000:.1f}ms)")
        if error_msg:
            print(f"   ⮑ {error_msg}")
        if details:
            for key, value in details.items():
                print(f"   • {key}: {value}")
    
    def log_error(self, test_name: str, error_msg: str):
        """ثبت خطا"""
        self.log_test_result(test_name, False, error_msg=error_msg)
    
    def generate_random_data(self, size: int) -> bytes:
        """تولید داده تصادفی"""
        return bytes([random.randint(0, 255) for _ in range(size)])
    
    def test_basic_memory_operations(self):
        """تست عملیات پایه حافظه"""
        print("\n🔬 تست عملیات پایه حافظه...")
        
        for addr in self.test_addresses:
            for size in [s for s in self.test_sizes if s <= 1024]:
                test_data = self.generate_random_data(size)
                
                # Test write
                start_time = time.time()
                try:
                    write_success = self.toolkit.write_physical_memory(addr, test_data)
                    exec_time = time.time() - start_time
                    
                    self.log_test_result(
                        f"write_memory_0x{addr:x}_{size}bytes",
                        write_success,
                        details={"address": f"0x{addr:x}", "size": size},
                        execution_time=exec_time,
                        test_data={"data_hash": hash(test_data)}
                    )
                    
                    if not write_success:
                        continue
                        
                    # Test read
                    start_time = time.time()
                    read_data = self.toolkit.read_physical_memory(addr, size)
                    exec_time = time.time() - start_time
                    
                    read_success = (read_data == test_data)
                    
                    self.log_test_result(
                        f"read_memory_0x{addr:x}_{size}bytes",
                        read_success,
                        details={
                            "address": f"0x{addr:x}",
                            "size": size,
                            "data_match": read_success
                        },
                        execution_time=exec_time,
                        test_data={
                            "expected_hash": hash(test_data),
                            "actual_hash": hash(read_data) if read_data else None
                        }
                    )
                    
                except Exception as e:
                    exec_time = time.time() - start_time
                    self.log_test_result(
                        f"memory_operation_0x{addr:x}_{size}bytes",
                        False,
                        error_msg=str(e),
                        execution_time=exec_time
                    )
    
    def test_address_translation(self):
        """تست تبدیل آدرس"""
        print("\n🔄 تست تبدیل آدرس...")
        
        # Test virtual to physical translation
        test_vaddrs = [
            0xffffffff81000000,  # Kernel space
            0xffffffff82000000,
            0x7fff00000000,      # User space high
            0x400000,            # User space low
        ]
        
        for vaddr in test_vaddrs:
            start_time = time.time()
            try:
                paddr = self.toolkit.virtual_to_physical(vaddr)
                exec_time = time.time() - start_time
                
                success = paddr is not None
                
                self.log_test_result(
                    f"v2p_translation_0x{vaddr:x}",
                    success,
                    details={
                        "virtual_addr": f"0x{vaddr:x}",
                        "physical_addr": f"0x{paddr:x}" if paddr else None,
                        "translation_valid": success
                    },
                    execution_time=exec_time,
                    test_data={"vaddr": vaddr, "paddr": paddr}
                )
                
                # Test reverse translation if forward succeeded
                if success and paddr:
                    start_time = time.time()
                    try:
                        reverse_vaddr = self.toolkit.physical_to_virtual(paddr)
                        exec_time = time.time() - start_time
                        
                        reverse_success = reverse_vaddr is not None
                        
                        self.log_test_result(
                            f"p2v_translation_0x{paddr:x}",
                            reverse_success,
                            details={
                                "physical_addr": f"0x{paddr:x}",
                                "virtual_addr": f"0x{reverse_vaddr:x}" if reverse_vaddr else None,
                                "reverse_translation_valid": reverse_success
                            },
                            execution_time=exec_time,
                            test_data={"paddr": paddr, "reverse_vaddr": reverse_vaddr}
                        )
                    except Exception as e:
                        exec_time = time.time() - start_time
                        self.log_test_result(
                            f"p2v_translation_0x{paddr:x}",
                            False,
                            error_msg=str(e),
                            execution_time=exec_time
                        )
                        
            except Exception as e:
                exec_time = time.time() - start_time
                self.log_test_result(
                    f"v2p_translation_0x{vaddr:x}",
                    False,
                    error_msg=str(e),
                    execution_time=exec_time
                )
    
    def test_page_information(self):
        """تست اطلاعات صفحه"""
        print("\n📋 تست اطلاعات صفحه...")
        
        test_addresses = self.test_addresses + [
            0x0,                # Null page
            0x1000,             # First user page
            0xffffffff81000000, # Kernel address
        ]
        
        for addr in test_addresses:
            start_time = time.time()
            try:
                page_info = self.toolkit.get_page_info(addr)
                exec_time = time.time() - start_time
                
                success = page_info is not None
                
                self.log_test_result(
                    f"page_info_0x{addr:x}",
                    success,
                    details={
                        "address": f"0x{addr:x}",
                        "page_info_available": success,
                        "page_present": page_info.get('present') if page_info else None,
                        "page_writable": page_info.get('writable') if page_info else None,
                        "page_user": page_info.get('user') if page_info else None
                    },
                    execution_time=exec_time,
                    test_data={"addr": addr, "page_info": page_info}
                )
                
            except Exception as e:
                exec_time = time.time() - start_time
                self.log_test_result(
                    f"page_info_0x{addr:x}",
                    False,
                    error_msg=str(e),
                    execution_time=exec_time
                )
    
    def test_memory_operations(self):
        """تست عملیات پیشرفته حافظه"""
        print("\n🔧 تست عملیات پیشرفته حافظه...")
        
        # Test memory copy
        src_addr = self.test_addresses[0]
        dst_addr = self.test_addresses[1]
        test_sizes = [32, 64, 128, 256]
        
        for size in test_sizes:
            test_data = self.generate_random_data(size)
            
            # Write test data to source
            if not self.toolkit.write_physical_memory(src_addr, test_data):
                continue
            
            # Test memory copy
            start_time = time.time()
            try:
                copy_success = self.toolkit.memory_copy(src_addr, dst_addr, size)
                exec_time = time.time() - start_time
                
                # Verify copy
                if copy_success:
                    dst_data = self.toolkit.read_physical_memory(dst_addr, size)
                    copy_valid = (dst_data == test_data)
                else:
                    copy_valid = False
                
                self.log_test_result(
                    f"memory_copy_{size}bytes",
                    copy_success and copy_valid,
                    details={
                        "src_addr": f"0x{src_addr:x}",
                        "dst_addr": f"0x{dst_addr:x}",
                        "size": size,
                        "copy_executed": copy_success,
                        "data_integrity": copy_valid
                    },
                    execution_time=exec_time,
                    test_data={"size": size, "data_hash": hash(test_data)}
                )
                
            except Exception as e:
                exec_time = time.time() - start_time
                self.log_test_result(
                    f"memory_copy_{size}bytes",
                    False,
                    error_msg=str(e),
                    execution_time=exec_time
                )
        
        # Test memory compare
        addr1 = self.test_addresses[0]
        addr2 = self.test_addresses[1]
        
        for size in test_sizes:
            start_time = time.time()
            try:
                differences = self.toolkit.memory_compare(addr1, addr2, size)
                exec_time = time.time() - start_time
                
                success = differences is not None
                
                self.log_test_result(
                    f"memory_compare_{size}bytes",
                    success,
                    details={
                        "addr1": f"0x{addr1:x}",
                        "addr2": f"0x{addr2:x}",
                        "size": size,
                        "differences_count": len(differences) if differences else None,
                        "identical": len(differences) == 0 if differences is not None else None
                    },
                    execution_time=exec_time,
                    test_data={"size": size, "differences": differences}
                )
                
            except Exception as e:
                exec_time = time.time() - start_time
                self.log_test_result(
                    f"memory_compare_{size}bytes",
                    False,
                    error_msg=str(e),
                    execution_time=exec_time
                )
    
    def test_hex_dump_functionality(self):
        """تست عملکرد hex dump"""
        print("\n🔍 تست عملکرد hex dump...")
        
        test_data_sets = [
            b"Hello World!",
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            self.generate_random_data(64),
            self.generate_random_data(256)
        ]
        
        for i, test_data in enumerate(test_data_sets):
            start_time = time.time()
            try:
                hex_dump = self.toolkit.hex_dump(test_data, 0x1000 + i * 0x100)
                exec_time = time.time() - start_time
                
                success = hex_dump is not None and len(hex_dump) > 0
                
                self.log_test_result(
                    f"hex_dump_test_{i}",
                    success,
                    details={
                        "data_size": len(test_data),
                        "dump_lines": len(hex_dump.split('\n')) if hex_dump else 0,
                        "dump_length": len(hex_dump) if hex_dump else 0
                    },
                    execution_time=exec_time,
                    test_data={"data_size": len(test_data)}
                )
                
            except Exception as e:
                exec_time = time.time() - start_time
                self.log_test_result(
                    f"hex_dump_test_{i}",
                    False,
                    error_msg=str(e),
                    execution_time=exec_time
                )
    
    def test_error_handling(self):
        """تست مدیریت خطاها"""
        print("\n⚠️ تست مدیریت خطاها...")
        
        # Test invalid addresses
        invalid_addresses = [0xffffffffffffffff, 0xdeadbeef00000000]
        
        for addr in invalid_addresses:
            start_time = time.time()
            try:
                data = self.toolkit.read_physical_memory(addr, 32)
                exec_time = time.time() - start_time
                
                # Should handle gracefully (return None or empty)
                handled_gracefully = data is None or len(data) == 0
                
                self.log_test_result(
                    f"invalid_address_handling_0x{addr:x}",
                    handled_gracefully,
                    details={
                        "address": f"0x{addr:x}",
                        "graceful_handling": handled_gracefully,
                        "returned_data": data is not None
                    },
                    execution_time=exec_time
                )
                
            except Exception as e:
                exec_time = time.time() - start_time
                # Exception handling is also acceptable
                self.log_test_result(
                    f"invalid_address_handling_0x{addr:x}",
                    True,  # Exception is acceptable for invalid address
                    details={"handled_with_exception": True},
                    execution_time=exec_time
                )
        
        # Test oversized operations
        oversized_requests = [8192 + 1, 16384, 32768]
        
        for size in oversized_requests:
            start_time = time.time()
            try:
                data = self.toolkit.read_physical_memory(self.test_addresses[0], size)
                exec_time = time.time() - start_time
                
                # Should handle gracefully
                handled_gracefully = data is None
                
                self.log_test_result(
                    f"oversized_request_handling_{size}bytes",
                    handled_gracefully,
                    details={
                        "requested_size": size,
                        "graceful_handling": handled_gracefully
                    },
                    execution_time=exec_time
                )
                
            except Exception as e:
                exec_time = time.time() - start_time
                # Exception is also acceptable
                self.log_test_result(
                    f"oversized_request_handling_{size}bytes",
                    True,
                    details={"handled_with_exception": True},
                    execution_time=exec_time
                )
    
    def test_performance_characteristics(self):
        """تست مشخصات عملکرد"""
        print("\n🚀 تست مشخصات عملکرد...")
        
        # Test various sizes for performance
        performance_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
        
        performance_data = {
            "read_times": [],
            "write_times": [],
            "sizes": performance_sizes
        }
        
        for size in performance_sizes:
            test_data = self.generate_random_data(size)
            addr = self.test_addresses[0]
            
            # Measure write performance
            start_time = time.time()
            write_success = self.toolkit.write_physical_memory(addr, test_data)
            write_time = time.time() - start_time
            
            # Measure read performance
            start_time = time.time()
            read_data = self.toolkit.read_physical_memory(addr, size)
            read_time = time.time() - start_time
            
            performance_data["write_times"].append(write_time * 1000)  # ms
            performance_data["read_times"].append(read_time * 1000)    # ms
            
            # Calculate throughput
            write_throughput = size / write_time / 1024 if write_time > 0 else 0  # KB/s
            read_throughput = size / read_time / 1024 if read_time > 0 else 0     # KB/s
            
            self.log_test_result(
                f"performance_test_{size}bytes",
                write_success and (read_data == test_data),
                details={
                    "size_bytes": size,
                    "write_time_ms": round(write_time * 1000, 2),
                    "read_time_ms": round(read_time * 1000, 2),
                    "write_throughput_kbps": round(write_throughput, 2),
                    "read_throughput_kbps": round(read_throughput, 2)
                },
                execution_time=write_time + read_time,
                test_data=performance_data
            )
    
    def test_concurrent_operations(self):
        """تست عملیات همزمان (شبیه‌سازی)"""
        print("\n🔄 تست عملیات متوالی...")
        
        # Simulate rapid consecutive operations
        addr = self.test_addresses[0]
        test_data = self.generate_random_data(64)
        
        operations = []
        
        start_time = time.time()
        
        # Rapid write operations
        for i in range(10):
            op_start = time.time()
            success = self.toolkit.write_physical_memory(addr + i * 0x100, test_data)
            op_time = time.time() - op_start
            operations.append(("write", success, op_time))
        
        # Rapid read operations
        for i in range(10):
            op_start = time.time()
            data = self.toolkit.read_physical_memory(addr + i * 0x100, 64)
            op_time = time.time() - op_start
            operations.append(("read", data is not None, op_time))
        
        total_time = time.time() - start_time
        
        successful_ops = sum(1 for _, success, _ in operations if success)
        total_ops = len(operations)
        
        self.log_test_result(
            "concurrent_operations_simulation",
            successful_ops == total_ops,
            details={
                "total_operations": total_ops,
                "successful_operations": successful_ops,
                "success_rate": round(successful_ops / total_ops * 100, 2),
                "total_time_ms": round(total_time * 1000, 2),
                "avg_operation_time_ms": round(sum(t for _, _, t in operations) / total_ops * 1000, 2)
            },
            execution_time=total_time,
            test_data={"operations": operations}
        )
    
    def test_report_generation(self):
        """تست تولید گزارش"""
        print("\n📊 تست تولید گزارش...")
        
        start_time = time.time()
        try:
            report = self.toolkit.generate_report()
            exec_time = time.time() - start_time
            
            success = isinstance(report, dict) and len(report) > 0
            
            self.log_test_result(
                "report_generation",
                success,
                details={
                    "report_keys": list(report.keys()) if report else [],
                    "report_size": len(str(report)) if report else 0,
                    "has_session_id": 'session_id' in report if report else False,
                    "has_operations_count": 'total_operations' in report if report else False
                },
                execution_time=exec_time,
                test_data={"report": report}
            )
            
        except Exception as e:
            exec_time = time.time() - start_time
            self.log_test_result(
                "report_generation",
                False,
                error_msg=str(e),
                execution_time=exec_time
            )
    
    def run_all_tests(self):
        """اجرای همه تست‌ها"""
        print("🚀 شروع تست جامع Advanced Memory Toolkit")
        print(f"📅 زمان شروع: {datetime.now().isoformat()}")
        print(f"🆔 شناسه جلسه: {self.session_id}")
        print("=" * 60)
        
        if not self.setup_toolkit():
            print("❌ خطا در راه‌اندازی toolkit")
            return self.generate_final_report()
        
        try:
            # Run all test suites
            self.test_basic_memory_operations()
            self.test_address_translation()
            self.test_page_information()
            self.test_memory_operations()
            self.test_hex_dump_functionality()
            self.test_error_handling()
            self.test_performance_characteristics()
            self.test_concurrent_operations()
            self.test_report_generation()
            
        finally:
            self.cleanup_toolkit()
        
        return self.generate_final_report()
    
    def generate_final_report(self) -> Dict[str, Any]:
        """تولید گزارش نهایی"""
        session_end_time = time.time()
        total_session_time = session_end_time - self.session_start_time
        
        # Calculate statistics
        success_rate = (self.passed_tests / self.total_tests * 100) if self.total_tests > 0 else 0
        
        # Group results by category
        categories = {}
        for result in self.test_results:
            category = result['test_name'].split('_')[0]
            if category not in categories:
                categories[category] = {'passed': 0, 'failed': 0, 'total': 0}
            
            categories[category]['total'] += 1
            if result['status'] == 'PASS':
                categories[category]['passed'] += 1
            else:
                categories[category]['failed'] += 1
        
        # Generate comprehensive report
        final_report = {
            "session_info": {
                "session_id": self.session_id,
                "start_time": datetime.fromtimestamp(self.session_start_time).isoformat(),
                "end_time": datetime.fromtimestamp(session_end_time).isoformat(),
                "total_duration_seconds": round(total_session_time, 2),
                "toolkit_version": "3.0"
            },
            "test_summary": {
                "total_tests": self.total_tests,
                "passed_tests": self.passed_tests,
                "failed_tests": self.failed_tests,
                "skipped_tests": self.skipped_tests,
                "success_rate_percent": round(success_rate, 2)
            },
            "category_breakdown": categories,
            "performance_metrics": {
                "avg_test_execution_time_ms": round(
                    sum(r.get('execution_time_ms', 0) for r in self.test_results) / max(self.total_tests, 1), 2
                ),
                "fastest_test_ms": min((r.get('execution_time_ms', 0) for r in self.test_results), default=0),
                "slowest_test_ms": max((r.get('execution_time_ms', 0) for r in self.test_results), default=0)
            },
            "detailed_results": self.test_results,
            "system_info": {
                "platform": sys.platform,
                "python_version": sys.version,
                "test_addresses_used": [f"0x{addr:x}" for addr in self.test_addresses],
                "max_test_size": self.max_safe_size
            }
        }
        
        return final_report


def main():
    """تابع اصلی"""
    print("🧪 AMT Comprehensive Test Suite v1.0")
    print("=" * 50)
    
    # Initialize test suite
    test_suite = ComprehensiveTestSuite()
    
    # Run all tests
    final_report = test_suite.run_all_tests()
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 خلاصه نتایج:")
    print(f"✅ تست‌های موفق: {final_report['test_summary']['passed_tests']}")
    print(f"❌ تست‌های ناموفق: {final_report['test_summary']['failed_tests']}")
    print(f"📈 درصد موفقیت: {final_report['test_summary']['success_rate_percent']}%")
    print(f"⏱️ مدت زمان کل: {final_report['session_info']['total_duration_seconds']} ثانیه")
    
    # Save JSON report
    report_filename = f"test_report_{final_report['session_info']['session_id']}.json"
    
    try:
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(final_report, f, ensure_ascii=False, indent=2)
        
        print(f"\n💾 گزارش JSON ذخیره شد: {report_filename}")
        print(f"📄 تعداد کل تست‌ها: {final_report['test_summary']['total_tests']}")
        print(f"📊 اندازه گزارش: {len(json.dumps(final_report, ensure_ascii=False))} بایت")
        
    except Exception as e:
        print(f"❌ خطا در ذخیره گزارش: {e}")
    
    # Category breakdown
    print("\n📋 تفکیک بر اساس دسته‌بندی:")
    for category, stats in final_report['category_breakdown'].items():
        success_rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
        print(f"  {category}: {stats['passed']}/{stats['total']} ({success_rate:.1f}%)")
    
    print("\n🎯 تست جامع به پایان رسید!")
    
    return final_report['test_summary']['success_rate_percent'] == 100.0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
