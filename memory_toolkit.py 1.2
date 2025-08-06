
#!/usr/bin/env python3
"""
Advanced Memory Toolkit (AMT) - Professional Python Interface
High-Performance Memory Operations Framework for Linux Kernel Module

This module provides a comprehensive Python interface for low-level memory
operations through a custom kernel module. It supports:

- Physical memory read/write operations
- Virtual to physical address translation
- Advanced page information retrieval
- Memory monitoring and debugging
- System information gathering
- Professional error handling and logging

Version: 4.0 Professional
Author: Mohammad Amin
License: GPL v2
"""

import os
import sys
import struct
import ctypes
import fcntl
import time
import hashlib
import threading
from typing import Optional, Dict, List, Tuple, Union, Any
from dataclasses import dataclass
from contextlib import contextmanager
import logging
from enum import IntEnum, Enum


# Device configuration
DEVICE_PATH = "/dev/amt_memory"
PROC_PATH = "/proc/amt_info"
MAX_BUFFER_SIZE = 64 * 1024  # 64KB maximum
DEFAULT_BUFFER_SIZE = 8 * 1024  # 8KB default


class AMTError(Exception):
    """Base exception for AMT operations"""
    pass


class AMTPermissionError(AMTError):
    """Permission denied error"""
    pass


class AMTInvalidAddressError(AMTError):
    """Invalid address error"""
    pass


class AMTDeviceError(AMTError):
    """Device operation error"""
    pass


class DebugLevel(IntEnum):
    """Debug level enumeration"""
    ERRORS_ONLY = 0
    INFO = 1
    DEBUG = 2
    VERBOSE = 3


class SafetyLevel(IntEnum):
    """Safety level enumeration"""
    DISABLED = 0
    BASIC = 1
    STANDARD = 2
    PARANOID = 3


class OperationType(Enum):
    """Operation type enumeration"""
    READ = "read"
    WRITE = "write"
    TRANSLATE = "translate"
    PAGE_INFO = "page_info"
    SYSTEM_INFO = "system_info"


# IOCTL command calculations
def _IOC(dir_val: int, type_val: str, nr: int, size: int) -> int:
    """Calculate IOCTL command value"""
    return (dir_val << 30) | (ord(type_val) << 8) | nr | (size << 16)


def _IOR(type_val: str, nr: int, size: int) -> int:
    """Read IOCTL command"""
    return _IOC(2, type_val, nr, size)


def _IOW(type_val: str, nr: int, size: int) -> int:
    """Write IOCTL command"""
    return _IOC(1, type_val, nr, size)


def _IOWR(type_val: str, nr: int, size: int) -> int:
    """Read/Write IOCTL command"""
    return _IOC(3, type_val, nr, size)


# Data structure definitions using ctypes
class AMTMemOperation(ctypes.Structure):
    """Memory operation structure"""
    _fields_ = [
        ("phys_addr", ctypes.c_uint64),
        ("size", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint64),
        ("result", ctypes.c_int32),
    ]


class AMTAddrTranslation(ctypes.Structure):
    """Address translation structure"""
    _fields_ = [
        ("input_addr", ctypes.c_uint64),
        ("output_addr", ctypes.c_uint64),
        ("pid", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
        ("success", ctypes.c_int32),
        ("page_table_entries", ctypes.c_uint64 * 5),
        ("protection_flags", ctypes.c_uint32),
        ("cache_type", ctypes.c_uint32),
    ]


class AMTPageInfo(ctypes.Structure):
    """Page information structure"""
    _fields_ = [
        ("addr", ctypes.c_uint64),
        ("page_frame_number", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("ref_count", ctypes.c_uint32),
        ("map_count", ctypes.c_uint32),
        ("present", ctypes.c_uint8, 1),
        ("writable", ctypes.c_uint8, 1),
        ("user_accessible", ctypes.c_uint8, 1),
        ("accessed", ctypes.c_uint8, 1),
        ("dirty", ctypes.c_uint8, 1),
        ("global_page", ctypes.c_uint8, 1),
        ("nx_bit", ctypes.c_uint8, 1),
        ("reserved", ctypes.c_uint8, 1),
        ("cache_type", ctypes.c_uint32),
        ("physical_addr", ctypes.c_uint64),
    ]


class AMTMemoryStats(ctypes.Structure):
    """Memory statistics structure"""
    _fields_ = [
        ("total_ram", ctypes.c_uint64),
        ("free_ram", ctypes.c_uint64),
        ("available_ram", ctypes.c_uint64),
        ("cached", ctypes.c_uint64),
        ("buffers", ctypes.c_uint64),
        ("slab", ctypes.c_uint64),
        ("operations_count", ctypes.c_uint32),
        ("error_count", ctypes.c_uint32),
        ("bytes_read", ctypes.c_uint64),
        ("bytes_written", ctypes.c_uint64),
    ]


class AMTSystemInfo(ctypes.Structure):
    """System information structure"""
    _fields_ = [
        ("kernel_version", ctypes.c_uint32),
        ("page_size", ctypes.c_uint32),
        ("page_offset", ctypes.c_uint64),
        ("vmalloc_start", ctypes.c_uint64),
        ("vmalloc_end", ctypes.c_uint64),
        ("cpu_count", ctypes.c_uint32),
        ("node_count", ctypes.c_uint32),
        ("arch", ctypes.c_char * 16),
        ("version_string", ctypes.c_char * 64),
    ]


# Calculate IOCTL commands
AMT_READ_PHYS = _IOWR('A', 1, ctypes.sizeof(AMTMemOperation))
AMT_WRITE_PHYS = _IOW('A', 2, ctypes.sizeof(AMTMemOperation))
AMT_VIRT_TO_PHYS = _IOWR('A', 3, ctypes.sizeof(AMTAddrTranslation))
AMT_PHYS_TO_VIRT = _IOWR('A', 4, ctypes.sizeof(AMTAddrTranslation))
AMT_GET_PAGE_INFO = _IOWR('A', 5, ctypes.sizeof(AMTPageInfo))
AMT_GET_MEMORY_STATS = _IOR('A', 6, ctypes.sizeof(AMTMemoryStats))
AMT_SET_DEBUG_LEVEL = _IOW('A', 7, ctypes.sizeof(ctypes.c_int))
AMT_GET_SYSTEM_INFO = _IOR('A', 8, ctypes.sizeof(AMTSystemInfo))


@dataclass
class OperationResult:
    """Result of a memory operation"""
    success: bool
    data: Optional[bytes] = None
    error_message: Optional[str] = None
    timestamp: Optional[float] = None
    operation_type: Optional[OperationType] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


@dataclass
class PageInformation:
    """Detailed page information"""
    address: int
    physical_address: int
    page_frame_number: int
    present: bool
    writable: bool
    user_accessible: bool
    accessed: bool
    dirty: bool
    global_page: bool
    nx_bit: bool
    ref_count: int
    map_count: int
    flags: int
    cache_type: int


@dataclass
class SystemInformation:
    """System information"""
    kernel_version: str
    page_size: int
    page_offset: int
    vmalloc_start: int
    vmalloc_end: int
    cpu_count: int
    node_count: int
    architecture: str


@dataclass
class MemoryStatistics:
    """Memory statistics"""
    total_ram: int
    free_ram: int
    available_ram: int
    cached: int
    buffers: int
    slab: int
    operations_count: int
    error_count: int
    bytes_read: int
    bytes_written: int
    
    @property
    def success_rate(self) -> float:
        """Calculate operation success rate"""
        total_ops = self.operations_count + self.error_count
        return (self.operations_count / total_ops * 100) if total_ops > 0 else 0.0


class AMTLogger:
    """Professional logging system for AMT"""
    
    def __init__(self, name: str = "AMT", level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        if not self.logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            
            # Formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
    
    def debug(self, message: str, *args, **kwargs):
        """Debug level logging"""
        self.logger.debug(message, *args, **kwargs)
    
    def info(self, message: str, *args, **kwargs):
        """Info level logging"""
        self.logger.info(message, *args, **kwargs)
    
    def warning(self, message: str, *args, **kwargs):
        """Warning level logging"""
        self.logger.warning(message, *args, **kwargs)
    
    def error(self, message: str, *args, **kwargs):
        """Error level logging"""
        self.logger.error(message, *args, **kwargs)
    
    def critical(self, message: str, *args, **kwargs):
        """Critical level logging"""
        self.logger.critical(message, *args, **kwargs)


class AdvancedMemoryToolkit:
    """
    Advanced Memory Toolkit - Professional Memory Operations Framework
    
    This class provides a comprehensive interface for low-level memory operations
    through a custom kernel module. It supports safe memory access, address
    translation, monitoring, and debugging capabilities.
    
    Features:
    - Physical memory read/write operations
    - Virtual to physical address translation
    - Advanced page information retrieval
    - Memory monitoring and statistics
    - Thread-safe operations
    - Professional error handling
    - Comprehensive logging
    
    Example:
        >>> amt = AdvancedMemoryToolkit(debug_level=DebugLevel.INFO)
        >>> with amt:
        >>>     data = amt.read_physical_memory(0x1000, 64)
        >>>     if data.success:
        >>>         print(f"Read {len(data.data)} bytes")
    """
    
    def __init__(self, 
                 debug_level: DebugLevel = DebugLevel.INFO,
                 safety_level: SafetyLevel = SafetyLevel.STANDARD,
                 max_buffer_size: int = DEFAULT_BUFFER_SIZE,
                 auto_connect: bool = True):
        """
        Initialize the Advanced Memory Toolkit
        
        Args:
            debug_level: Debug output level
            safety_level: Safety validation level
            max_buffer_size: Maximum buffer size for operations
            auto_connect: Automatically connect to device
        """
        self.debug_level = debug_level
        self.safety_level = safety_level
        self.max_buffer_size = min(max_buffer_size, MAX_BUFFER_SIZE)
        self.device_fd = None
        self.session_id = self._generate_session_id()
        self.operation_count = 0
        self.error_count = 0
        self._lock = threading.RLock()
        
        # Initialize logger
        log_level = {
            DebugLevel.ERRORS_ONLY: logging.ERROR,
            DebugLevel.INFO: logging.INFO,
            DebugLevel.DEBUG: logging.DEBUG,
            DebugLevel.VERBOSE: logging.DEBUG
        }.get(debug_level, logging.INFO)
        
        self.logger = AMTLogger("AMT", log_level)
        
        # Initialize system information cache
        self._system_info = None
        self._stats_cache = None
        self._cache_timeout = 5.0  # 5 seconds
        self._last_stats_update = 0
        
        if auto_connect:
            self.connect()
    
    def _generate_session_id(self) -> str:
        """Generate unique session identifier"""
        timestamp = str(time.time()).encode()
        pid = str(os.getpid()).encode()
        return hashlib.sha256(timestamp + pid).hexdigest()[:16]
    
    def connect(self) -> bool:
        """
        Connect to the AMT kernel module
        
        Returns:
            bool: True if connection successful, False otherwise
            
        Raises:
            AMTDeviceError: If device cannot be opened
            AMTPermissionError: If insufficient permissions
        """
        try:
            if self.device_fd is not None:
                self.logger.warning("Already connected to device")
                return True
            
            # Check if device exists
            if not os.path.exists(DEVICE_PATH):
                raise AMTDeviceError(f"Device {DEVICE_PATH} not found. Is the kernel module loaded?")
            
            # Check permissions
            if not os.access(DEVICE_PATH, os.R_OK | os.W_OK):
                raise AMTPermissionError(f"Insufficient permissions for {DEVICE_PATH}. Run as root?")
            
            # Open device
            self.device_fd = os.open(DEVICE_PATH, os.O_RDWR)
            
            # Set debug level in kernel module
            self._set_kernel_debug_level(self.debug_level)
            
            # Get system information
            self._system_info = self._get_system_information()
            
            self.logger.info(f"AMT Framework initialized successfully")
            self.logger.info(f"Session ID: {self.session_id}")
            self.logger.info(f"Kernel: {self._system_info.kernel_version}")
            self.logger.info(f"Architecture: {self._system_info.architecture}")
            self.logger.info(f"Page Size: {self._system_info.page_size} bytes")
            self.logger.info(f"Safety Level: {self.safety_level.name}")
            
            return True
            
        except OSError as e:
            error_msg = f"Failed to open device {DEVICE_PATH}: {e}"
            self.logger.error(error_msg)
            raise AMTDeviceError(error_msg) from e
    
    def disconnect(self):
        """Disconnect from the AMT kernel module"""
        with self._lock:
            if self.device_fd is not None:
                try:
                    os.close(self.device_fd)
                    self.logger.info(f"Session {self.session_id} disconnected")
                    self.logger.info(f"Operations performed: {self.operation_count}")
                    self.logger.info(f"Errors encountered: {self.error_count}")
                except OSError as e:
                    self.logger.error(f"Error closing device: {e}")
                finally:
                    self.device_fd = None
    
    def __enter__(self):
        """Context manager entry"""
        if self.device_fd is None:
            self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.disconnect()
    
    def __del__(self):
        """Destructor"""
        self.disconnect()
    
    def _check_connection(self):
        """Verify device connection"""
        if self.device_fd is None:
            raise AMTDeviceError("Not connected to device. Call connect() first.")
    
    def _validate_address(self, address: int, size: int = 0) -> bool:
        """
        Validate memory address according to safety level
        
        Args:
            address: Memory address to validate
            size: Size of operation (optional)
            
        Returns:
            bool: True if address is safe, False otherwise
        """
        if self.safety_level == SafetyLevel.DISABLED:
            return True
        
        # Basic validation
        if address == 0:
            self.logger.warning("NULL address detected")
            return False
        
        if size > self.max_buffer_size:
            self.logger.warning(f"Size {size} exceeds maximum {self.max_buffer_size}")
            return False
        
        # Check for overflow
        if size > 0 and address + size < address:
            self.logger.warning("Address overflow detected")
            return False
        
        # Level-specific checks would be implemented here
        # For now, basic validation is sufficient
        
        return True
    
    def _set_kernel_debug_level(self, level: DebugLevel):
        """Set debug level in kernel module"""
        try:
            level_val = ctypes.c_int(int(level))
            fcntl.ioctl(self.device_fd, AMT_SET_DEBUG_LEVEL, level_val)
            self.logger.debug(f"Kernel debug level set to {level.name}")
        except OSError as e:
            self.logger.warning(f"Failed to set kernel debug level: {e}")
    
    def _get_system_information(self) -> SystemInformation:
        """Get system information from kernel module"""
        self._check_connection()
        
        try:
            info = AMTSystemInfo()
            fcntl.ioctl(self.device_fd, AMT_GET_SYSTEM_INFO, info)
            
            # Parse kernel version
            version = info.kernel_version
            major = (version >> 16) & 0xff
            minor = (version >> 8) & 0xff
            patch = version & 0xff
            
            return SystemInformation(
                kernel_version=f"{major}.{minor}.{patch}",
                page_size=info.page_size,
                page_offset=info.page_offset,
                vmalloc_start=info.vmalloc_start,
                vmalloc_end=info.vmalloc_end,
                cpu_count=info.cpu_count,
                node_count=info.node_count,
                architecture=info.arch.decode('utf-8', errors='ignore').strip('\x00')
            )
            
        except OSError as e:
            self.logger.error(f"Failed to get system information: {e}")
            raise AMTDeviceError(f"System information query failed: {e}") from e
    
    def read_physical_memory(self, phys_addr: int, size: int) -> OperationResult:
        """
        Read data from physical memory address
        
        Args:
            phys_addr: Physical memory address
            size: Number of bytes to read
            
        Returns:
            OperationResult: Result containing data or error information
            
        Raises:
            AMTDeviceError: If device operation fails
            AMTInvalidAddressError: If address validation fails
        """
        self._check_connection()
        
        if not self._validate_address(phys_addr, size):
            error_msg = f"Invalid address: 0x{phys_addr:x} (size: {size})"
            self.logger.error(error_msg)
            self.error_count += 1
            return OperationResult(
                success=False,
                error_message=error_msg,
                operation_type=OperationType.READ
            )
        
        with self._lock:
            try:
                # Prepare operation structure
                op = AMTMemOperation()
                op.phys_addr = phys_addr
                op.size = size
                op.flags = 0
                
                # Allocate buffer for operation + data
                buffer_size = ctypes.sizeof(AMTMemOperation) + size
                buffer = ctypes.create_string_buffer(buffer_size)
                
                # Copy operation structure to buffer
                ctypes.memmove(buffer, ctypes.byref(op), ctypes.sizeof(AMTMemOperation))
                
                # Perform IOCTL
                fcntl.ioctl(self.device_fd, AMT_READ_PHYS, buffer)
                
                # Extract result
                result_op = AMTMemOperation.from_buffer_copy(buffer)
                
                if result_op.result == 0:
                    # Extract data
                    data_start = ctypes.sizeof(AMTMemOperation)
                    data = buffer.raw[data_start:data_start + size]
                    
                    self.operation_count += 1
                    self.logger.debug(f"Successfully read {size} bytes from 0x{phys_addr:x}")
                    
                    return OperationResult(
                        success=True,
                        data=data,
                        timestamp=result_op.timestamp / 1e9,  # Convert nanoseconds
                        operation_type=OperationType.READ
                    )
                else:
                    error_msg = f"Kernel operation failed with code: {result_op.result}"
                    self.logger.error(error_msg)
                    self.error_count += 1
                    
                    return OperationResult(
                        success=False,
                        error_message=error_msg,
                        operation_type=OperationType.READ
                    )
                    
            except OSError as e:
                error_msg = f"Physical memory read failed: {e}"
                self.logger.error(error_msg)
                self.error_count += 1
                
                return OperationResult(
                    success=False,
                    error_message=error_msg,
                    operation_type=OperationType.READ
                )
    
    def write_physical_memory(self, phys_addr: int, data: bytes) -> OperationResult:
        """
        Write data to physical memory address
        
        Args:
            phys_addr: Physical memory address
            data: Data to write
            
        Returns:
            OperationResult: Result of write operation
            
        Raises:
            AMTDeviceError: If device operation fails
            AMTInvalidAddressError: If address validation fails
        """
        self._check_connection()
        
        if not data:
            error_msg = "No data provided for write operation"
            self.logger.error(error_msg)
            return OperationResult(
                success=False,
                error_message=error_msg,
                operation_type=OperationType.WRITE
            )
        
        if not self._validate_address(phys_addr, len(data)):
            error_msg = f"Invalid address for write: 0x{phys_addr:x} (size: {len(data)})"
            self.logger.error(error_msg)
            self.error_count += 1
            return OperationResult(
                success=False,
                error_message=error_msg,
                operation_type=OperationType.WRITE
            )
        
        with self._lock:
            try:
                # Prepare operation structure
                op = AMTMemOperation()
                op.phys_addr = phys_addr
                op.size = len(data)
                op.flags = 0
                
                # Create buffer with operation + data
                buffer_size = ctypes.sizeof(AMTMemOperation) + len(data)
                buffer = ctypes.create_string_buffer(buffer_size)
                
                # Copy operation structure
                ctypes.memmove(buffer, ctypes.byref(op), ctypes.sizeof(AMTMemOperation))
                
                # Copy data
                data_start = ctypes.sizeof(AMTMemOperation)
                buffer.raw = buffer.raw[:data_start] + data + buffer.raw[data_start + len(data):]
                
                # Perform IOCTL
                fcntl.ioctl(self.device_fd, AMT_WRITE_PHYS, buffer)
                
                # Extract result
                result_op = AMTMemOperation.from_buffer_copy(buffer)
                
                if result_op.result == 0:
                    self.operation_count += 1
                    self.logger.debug(f"Successfully wrote {len(data)} bytes to 0x{phys_addr:x}")
                    
                    return OperationResult(
                        success=True,
                        timestamp=result_op.timestamp / 1e9,
                        operation_type=OperationType.WRITE
                    )
                else:
                    error_msg = f"Kernel write operation failed with code: {result_op.result}"
                    self.logger.error(error_msg)
                    self.error_count += 1
                    
                    return OperationResult(
                        success=False,
                        error_message=error_msg,
                        operation_type=OperationType.WRITE
                    )
                    
            except OSError as e:
                error_msg = f"Physical memory write failed: {e}"
                self.logger.error(error_msg)
                self.error_count += 1
                
                return OperationResult(
                    success=False,
                    error_message=error_msg,
                    operation_type=OperationType.WRITE
                )
    
    def virtual_to_physical(self, virt_addr: int, pid: int = 0) -> Optional[int]:
        """
        Convert virtual address to physical address
        
        Args:
            virt_addr: Virtual address to translate
            pid: Process ID (0 for kernel addresses)
            
        Returns:
            int: Physical address or None if translation failed
        """
        self._check_connection()
        
        if not self._validate_address(virt_addr):
            self.logger.error(f"Invalid virtual address: 0x{virt_addr:x}")
            self.error_count += 1
            return None
        
        with self._lock:
            try:
                trans = AMTAddrTranslation()
                trans.input_addr = virt_addr
                trans.pid = pid
                trans.flags = 0
                
                fcntl.ioctl(self.device_fd, AMT_VIRT_TO_PHYS, trans)
                
                if trans.success:
                    self.operation_count += 1
                    self.logger.debug(f"Translated 0x{virt_addr:x} -> 0x{trans.output_addr:x}")
                    return trans.output_addr
                else:
                    self.logger.warning(f"Translation failed for 0x{virt_addr:x}")
                    self.error_count += 1
                    return None
                    
            except OSError as e:
                self.logger.error(f"Address translation failed: {e}")
                self.error_count += 1
                return None
    
    def get_page_information(self, addr: int) -> Optional[PageInformation]:
        """
        Get detailed page information for an address
        
        Args:
            addr: Memory address
            
        Returns:
            PageInformation: Detailed page information or None if failed
        """
        self._check_connection()
        
        with self._lock:
            try:
                info = AMTPageInfo()
                info.addr = addr
                
                fcntl.ioctl(self.device_fd, AMT_GET_PAGE_INFO, info)
                
                self.operation_count += 1
                
                return PageInformation(
                    address=info.addr,
                    physical_address=info.physical_addr,
                    page_frame_number=info.page_frame_number,
                    present=bool(info.present),
                    writable=bool(info.writable),
                    user_accessible=bool(info.user_accessible),
                    accessed=bool(info.accessed),
                    dirty=bool(info.dirty),
                    global_page=bool(info.global_page),
                    nx_bit=bool(info.nx_bit),
                    ref_count=info.ref_count,
                    map_count=info.map_count,
                    flags=info.flags,
                    cache_type=info.cache_type
                )
                
            except OSError as e:
                self.logger.error(f"Failed to get page information: {e}")
                self.error_count += 1
                return None
    
    def get_memory_statistics(self, use_cache: bool = True) -> Optional[MemoryStatistics]:
        """
        Get comprehensive memory statistics
        
        Args:
            use_cache: Use cached statistics if available
            
        Returns:
            MemoryStatistics: Memory statistics or None if failed
        """
        self._check_connection()
        
        current_time = time.time()
        if (use_cache and self._stats_cache and 
            current_time - self._last_stats_update < self._cache_timeout):
            return self._stats_cache
        
        with self._lock:
            try:
                stats = AMTMemoryStats()
                fcntl.ioctl(self.device_fd, AMT_GET_MEMORY_STATS, stats)
                
                memory_stats = MemoryStatistics(
                    total_ram=stats.total_ram,
                    free_ram=stats.free_ram,
                    available_ram=stats.available_ram,
                    cached=stats.cached,
                    buffers=stats.buffers,
                    slab=stats.slab,
                    operations_count=stats.operations_count,
                    error_count=stats.error_count,
                    bytes_read=stats.bytes_read,
                    bytes_written=stats.bytes_written
                )
                
                # Update cache
                self._stats_cache = memory_stats
                self._last_stats_update = current_time
                
                return memory_stats
                
            except OSError as e:
                self.logger.error(f"Failed to get memory statistics: {e}")
                return None
    
    def get_system_information(self) -> Optional[SystemInformation]:
        """
        Get system information
        
        Returns:
            SystemInformation: System information or None if failed
        """
        if self._system_info:
            return self._system_info
        
        self._check_connection()
        try:
            self._system_info = self._get_system_information()
            return self._system_info
        except Exception as e:
            self.logger.error(f"Failed to get system information: {e}")
            return None
    
    def hex_dump(self, data: bytes, addr: int = 0, width: int = 16, 
                 show_ascii: bool = True) -> str:
        """
        Create professional hex dump of data
        
        Args:
            data: Data to dump
            addr: Starting address for display
            width: Bytes per line
            show_ascii: Show ASCII representation
            
        Returns:
            str: Formatted hex dump
        """
        if not data:
            return ""
        
        lines = []
        for i in range(0, len(data), width):
            line_data = data[i:i+width]
            hex_part = ' '.join(f'{b:02x}' for b in line_data)
            
            # Pad hex part to maintain alignment
            hex_part = hex_part.ljust(width * 3 - 1)
            
            line = f'{addr+i:08x}: {hex_part}'
            
            if show_ascii:
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in line_data)
                line += f' |{ascii_part}|'
            
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
            bool: True on success, False on error
        """
        self.logger.debug(f"Copying {size} bytes from 0x{src_addr:x} to 0x{dst_addr:x}")
        
        # Read from source
        result = self.read_physical_memory(src_addr, size)
        if not result.success:
            self.logger.error(f"Failed to read source address: {result.error_message}")
            return False
        
        # Write to destination
        result = self.write_physical_memory(dst_addr, result.data)
        if not result.success:
            self.logger.error(f"Failed to write to destination: {result.error_message}")
            return False
        
        self.logger.debug("Memory copy completed successfully")
        return True
    
    def memory_compare(self, addr1: int, addr2: int, size: int) -> Optional[List[int]]:
        """
        Compare two memory regions
        
        Args:
            addr1: First physical address
            addr2: Second physical address
            size: Number of bytes to compare
            
        Returns:
            List[int]: List of differing byte offsets or None on error
        """
        self.logger.debug(f"Comparing {size} bytes between 0x{addr1:x} and 0x{addr2:x}")
        
        # Read both regions
        result1 = self.read_physical_memory(addr1, size)
        result2 = self.read_physical_memory(addr2, size)
        
        if not result1.success or not result2.success:
            self.logger.error("Failed to read memory regions for comparison")
            return None
        
        # Compare data
        differences = []
        for i, (b1, b2) in enumerate(zip(result1.data, result2.data)):
            if b1 != b2:
                differences.append(i)
        
        self.logger.debug(f"Found {len(differences)} differences")
        return differences
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive toolkit usage report
        
        Returns:
            Dict: Detailed usage report
        """
        report = {
            'session_info': {
                'session_id': self.session_id,
                'timestamp': time.time(),
                'version': '4.0 Professional',
                'connected': self.device_fd is not None
            },
            'configuration': {
                'debug_level': self.debug_level.name,
                'safety_level': self.safety_level.name,
                'max_buffer_size': self.max_buffer_size
            },
            'statistics': {
                'local_operations': self.operation_count,
                'local_errors': self.error_count,
                'success_rate': (self.operation_count / (self.operation_count + self.error_count) * 100) 
                               if (self.operation_count + self.error_count) > 0 else 0.0
            },
            'capabilities': [
                'Physical Memory Read/Write',
                'Virtual ↔ Physical Address Translation',
                'Advanced Page Information Retrieval',
                'Memory Statistics and Monitoring',
                'System Information Gathering',
                'Professional Error Handling',
                'Thread-Safe Operations'
            ]
        }
        
        # Add system information if available
        sys_info = self.get_system_information()
        if sys_info:
            report['system_info'] = {
                'kernel_version': sys_info.kernel_version,
                'architecture': sys_info.architecture,
                'page_size': sys_info.page_size,
                'cpu_count': sys_info.cpu_count,
                'node_count': sys_info.node_count
            }
        
        # Add memory statistics if available
        mem_stats = self.get_memory_statistics()
        if mem_stats:
            report['memory_stats'] = {
                'total_ram_mb': mem_stats.total_ram // (1024 * 1024),
                'free_ram_mb': mem_stats.free_ram // (1024 * 1024),
                'kernel_operations': mem_stats.operations_count,
                'kernel_errors': mem_stats.error_count,
                'kernel_success_rate': mem_stats.success_rate
            }
        
        return report
    
    @contextmanager
    def operation_context(self, operation_name: str):
        """
        Context manager for operation timing and error handling
        
        Args:
            operation_name: Name of the operation for logging
        """
        start_time = time.time()
        self.logger.debug(f"Starting operation: {operation_name}")
        
        try:
            yield
            elapsed = time.time() - start_time
            self.logger.debug(f"Operation '{operation_name}' completed in {elapsed:.3f}s")
        except Exception as e:
            elapsed = time.time() - start_time
            self.logger.error(f"Operation '{operation_name}' failed after {elapsed:.3f}s: {e}")
            raise


def main():
    """
    Main function with enhanced capabilities and professional argument parsing
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Advanced Memory Toolkit - Professional Memory Operations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --read-phys 0x1000 256 --hex-dump
  %(prog)s --write-phys 0x2000 48656c6c6f
  %(prog)s --v2p 0xffffffff81000000
  %(prog)s --page-info 0x1000
  %(prog)s --stats --system-info
  %(prog)s --interactive --debug-level 2
        """
    )
    
    # Core operations
    parser.add_argument('--read-phys', nargs=2, metavar=('ADDR', 'SIZE'),
                       help='Read physical memory (hex address, size)')
    parser.add_argument('--write-phys', nargs=2, metavar=('ADDR', 'DATA'),
                       help='Write to physical memory (hex address, hex data)')
    parser.add_argument('--v2p', nargs=1, metavar='VADDR',
                       help='Virtual to physical address translation')
    parser.add_argument('--page-info', nargs=1, metavar='ADDR',
                       help='Get page information for address')
    parser.add_argument('--copy-memory', nargs=3, metavar=('SRC', 'DST', 'SIZE'),
                       help='Copy memory (hex src, hex dst, size)')
    parser.add_argument('--compare-memory', nargs=3, metavar=('ADDR1', 'ADDR2', 'SIZE'),
                       help='Compare memory regions')
    
    # Information and monitoring
    parser.add_argument('--stats', action='store_true',
                       help='Show memory statistics')
    parser.add_argument('--system-info', action='store_true',
                       help='Show system information')
    parser.add_argument('--report', action='store_true',
                       help='Generate comprehensive report')
    
    # Configuration
    parser.add_argument('--debug-level', type=int, choices=[0, 1, 2, 3], default=1,
                       help='Debug level (0=errors, 1=info, 2=debug, 3=verbose)')
    parser.add_argument('--safety-level', type=int, choices=[0, 1, 2, 3], default=2,
                       help='Safety level (0=disabled, 1=basic, 2=standard, 3=paranoid)')
    parser.add_argument('--max-buffer', type=int, default=DEFAULT_BUFFER_SIZE,
                       help='Maximum buffer size for operations')
    
    # Output options
    parser.add_argument('--hex-dump', action='store_true',
                       help='Show hex dump for read operations')
    parser.add_argument('--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--quiet', action='store_true',
                       help='Minimal output')
    
    # Interactive mode
    parser.add_argument('--interactive', action='store_true',
                       help='Start interactive mode')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        print("\n🔧 Advanced Memory Toolkit v4.0 Professional")
        print("💾 Professional Memory Operations Framework")
        print("🔒 Multi-level Safety and Monitoring")
        print("🐛 Advanced Debugging and Logging")
        return
    
    # Configure debug level
    debug_level = DebugLevel(args.debug_level)
    if args.verbose:
        debug_level = DebugLevel.VERBOSE
    elif args.quiet:
        debug_level = DebugLevel.ERRORS_ONLY
    
    # Initialize toolkit
    try:
        amt = AdvancedMemoryToolkit(
            debug_level=debug_level,
            safety_level=SafetyLevel(args.safety_level),
            max_buffer_size=args.max_buffer
        )
    except Exception as e:
        print(f"❌ Failed to initialize AMT: {e}")
        return 1
    
    try:
        with amt:
            if args.read_phys:
                addr, size = int(args.read_phys[0], 16), int(args.read_phys[1])
                result = amt.read_physical_memory(addr, size)
                if result.success:
                    print(f"✅ Read {len(result.data)} bytes from 0x{addr:x}")
                    if args.hex_dump:
                        print(amt.hex_dump(result.data, addr))
                else:
                    print(f"❌ Read failed: {result.error_message}")
            
            elif args.write_phys:
                addr = int(args.write_phys[0], 16)
                data = bytes.fromhex(args.write_phys[1])
                result = amt.write_physical_memory(addr, data)
                if result.success:
                    print(f"✅ Wrote {len(data)} bytes to 0x{addr:x}")
                else:
                    print(f"❌ Write failed: {result.error_message}")
            
            elif args.v2p:
                vaddr = int(args.v2p[0], 16)
                paddr = amt.virtual_to_physical(vaddr)
                if paddr:
                    print(f"🔄 Virtual 0x{vaddr:x} → Physical 0x{paddr:x}")
                else:
                    print(f"❌ Translation failed for 0x{vaddr:x}")
            
            elif args.page_info:
                addr = int(args.page_info[0], 16)
                info = amt.get_page_information(addr)
                if info:
                    print(f"📋 Page Information for 0x{addr:x}:")
                    print(f"  Physical Address: 0x{info.physical_address:x}")
                    print(f"  Page Frame: {info.page_frame_number}")
                    print(f"  Present: {info.present}")
                    print(f"  Writable: {info.writable}")
                    print(f"  User Accessible: {info.user_accessible}")
                    print(f"  Accessed: {info.accessed}")
                    print(f"  Dirty: {info.dirty}")
                    print(f"  Reference Count: {info.ref_count}")
                    print(f"  Map Count: {info.map_count}")
                else:
                    print(f"❌ Failed to get page information")
            
            elif args.stats:
                stats = amt.get_memory_statistics()
                if stats:
                    print("📊 Memory Statistics:")
                    print(f"  Total RAM: {stats.total_ram // (1024*1024)} MB")
                    print(f"  Free RAM: {stats.free_ram // (1024*1024)} MB")
                    print(f"  Operations: {stats.operations_count}")
                    print(f"  Errors: {stats.error_count}")
                    print(f"  Success Rate: {stats.success_rate:.1f}%")
                    print(f"  Bytes Read: {stats.bytes_read}")
                    print(f"  Bytes Written: {stats.bytes_written}")
                else:
                    print("❌ Failed to get statistics")
            
            elif args.system_info:
                info = amt.get_system_information()
                if info:
                    print("🖥️  System Information:")
                    print(f"  Kernel Version: {info.kernel_version}")
                    print(f"  Architecture: {info.architecture}")
                    print(f"  Page Size: {info.page_size} bytes")
                    print(f"  CPU Count: {info.cpu_count}")
                    print(f"  NUMA Nodes: {info.node_count}")
                    print(f"  Page Offset: 0x{info.page_offset:x}")
                else:
                    print("❌ Failed to get system information")
            
            elif args.report:
                report = amt.generate_report()
                print("📋 AMT Comprehensive Report:")
                print("=" * 50)
                
                for section, data in report.items():
                    print(f"\n{section.replace('_', ' ').title()}:")
                    if isinstance(data, dict):
                        for key, value in data.items():
                            print(f"  {key.replace('_', ' ').title()}: {value}")
                    elif isinstance(data, list):
                        for item in data:
                            print(f"  • {item}")
                    else:
                        print(f"  {data}")
            
            elif args.interactive:
                interactive_mode(amt)
    
    except KeyboardInterrupt:
        print("\n⚠️  Operation interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1
    
    return 0


def interactive_mode(amt: AdvancedMemoryToolkit):
    """Professional interactive mode with enhanced commands"""
    print(f"\n💻 Advanced Memory Toolkit - Interactive Mode")
    print(f"🔧 Session: {amt.session_id}")
    print(f"🛡️  Safety Level: {amt.safety_level.name}")
    print(f"📊 Debug Level: {amt.debug_level.name}")
    
    print("\nAvailable Commands:")
    commands = {
        'read <addr> <size>': 'Read physical memory',
        'write <addr> <hex_data>': 'Write to physical memory',
        'v2p <vaddr> [pid]': 'Virtual to physical translation',
        'pageinfo <addr>': 'Get page information',
        'copy <src> <dst> <size>': 'Copy memory regions',
        'compare <addr1> <addr2> <size>': 'Compare memory regions',
        'stats': 'Show memory statistics',
        'sysinfo': 'Show system information',
        'report': 'Generate comprehensive report',
        'debug <level>': 'Set debug level (0-3)',
        'help': 'Show this help',
        'quit': 'Exit interactive mode'
    }
    
    for cmd, desc in commands.items():
        print(f"  {cmd:<25} - {desc}")
    
    while True:
        try:
            cmd_line = input("\namt> ").strip()
            if not cmd_line:
                continue
            
            cmd_parts = cmd_line.split()
            cmd = cmd_parts[0].lower()
            
            if cmd == 'quit' or cmd == 'exit':
                break
            
            elif cmd == 'help':
                for cmd_help, desc in commands.items():
                    print(f"  {cmd_help:<25} - {desc}")
            
            elif cmd == 'read' and len(cmd_parts) >= 3:
                addr = int(cmd_parts[1], 16)
                size = int(cmd_parts[2])
                result = amt.read_physical_memory(addr, size)
                if result.success:
                    print(f"✅ Read {len(result.data)} bytes:")
                    print(amt.hex_dump(result.data, addr))
                else:
                    print(f"❌ Read failed: {result.error_message}")
            
            elif cmd == 'write' and len(cmd_parts) >= 3:
                addr = int(cmd_parts[1], 16)
                data = bytes.fromhex(cmd_parts[2])
                result = amt.write_physical_memory(addr, data)
                if result.success:
                    print(f"✅ Wrote {len(data)} bytes to 0x{addr:x}")
                else:
                    print(f"❌ Write failed: {result.error_message}")
            
            elif cmd == 'v2p' and len(cmd_parts) >= 2:
                vaddr = int(cmd_parts[1], 16)
                pid = int(cmd_parts[2]) if len(cmd_parts) > 2 else 0
                paddr = amt.virtual_to_physical(vaddr, pid)
                if paddr:
                    print(f"🔄 0x{vaddr:x} → 0x{paddr:x}")
                else:
                    print(f"❌ Translation failed")
            
            elif cmd == 'pageinfo' and len(cmd_parts) >= 2:
                addr = int(cmd_parts[1], 16)
                info = amt.get_page_information(addr)
                if info:
                    print(f"📋 Page info for 0x{addr:x}:")
                    print(f"  Physical: 0x{info.physical_address:x}")
                    print(f"  Present: {info.present}, Writable: {info.writable}")
                    print(f"  User: {info.user_accessible}, Dirty: {info.dirty}")
                else:
                    print(f"❌ Failed to get page info")
            
            elif cmd == 'stats':
                stats = amt.get_memory_statistics()
                if stats:
                    print(f"📊 Memory Statistics:")
                    print(f"  RAM: {stats.total_ram//1024//1024} MB total, "
                          f"{stats.free_ram//1024//1024} MB free")
                    print(f"  Operations: {stats.operations_count}, "
                          f"Errors: {stats.error_count}")
                    print(f"  Success Rate: {stats.success_rate:.1f}%")
                else:
                    print(f"❌ Failed to get statistics")
            
            elif cmd == 'sysinfo':
                info = amt.get_system_information()
                if info:
                    print(f"🖥️  System: {info.architecture} "
                          f"Kernel {info.kernel_version}")
                    print(f"  CPUs: {info.cpu_count}, "
                          f"Page Size: {info.page_size}")
                else:
                    print(f"❌ Failed to get system info")
            
            elif cmd == 'report':
                report = amt.generate_report()
                print(f"📋 Session Report:")
                print(f"  Operations: {report['statistics']['local_operations']}")
                print(f"  Success Rate: {report['statistics']['success_rate']:.1f}%")
            
            elif cmd == 'debug' and len(cmd_parts) >= 2:
                level = int(cmd_parts[1])
                if 0 <= level <= 3:
                    amt.debug_level = DebugLevel(level)
                    print(f"🐛 Debug level set to {level}")
                else:
                    print(f"❌ Invalid debug level. Use 0-3")
            
            else:
                print(f"❓ Unknown command: {cmd}. Type 'help' for available commands.")
        
        except KeyboardInterrupt:
            print(f"\n💡 Use 'quit' to exit interactive mode")
        except ValueError as e:
            print(f"❌ Invalid input: {e}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print(f"👋 Exiting interactive mode")


if __name__ == "__main__":
    sys.exit(main())
