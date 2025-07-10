
#!/usr/bin/env python3
"""
Advanced Memory Toolkit (AMT) - Professional Python Interface v4.0
High-Performance Memory Operations Framework for Linux Kernel Module

Enhanced for Kernel 6.12+ compatibility with comprehensive error handling,
advanced translation methods, and developer-friendly features.

Version: 4.0 Professional Enhanced
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


class AMTError(IntEnum):
    """AMT Error codes - matching kernel definitions"""
    SUCCESS = 0
    EFAULT = 14       # Bad address
    ENOTSUPP = 524    # Operation not supported
    EPERM = 1         # Permission denied
    EINVAL = 22       # Invalid argument
    ENOMEM = 12       # Out of memory
    ENODEV = 19       # No such device
    EBUSY = 16        # Device busy
    EACCES = 13       # Permission denied
    EIO = 5           # I/O error


class Architecture(Enum):
    """Supported architectures"""
    X86_64 = "x86_64"
    X86_32 = "i386"
    ARM64 = "aarch64"
    ARM32 = "arm"
    RISCV64 = "riscv64"
    RISCV32 = "riscv32"
    UNKNOWN = "unknown"


class TranslationMethod(Enum):
    """Address translation methods"""
    AUTO = "auto"
    FORCE_PTE = "force_pte"
    FORCE_GUP = "force_gup"
    KERNEL_ONLY = "kernel_only"


class AddressType(Enum):
    """Address space types"""
    KERNEL_SPACE = "kernel"
    USER_SPACE = "user"
    UNKNOWN = "unknown"


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


# Enhanced data structures
class AMTMemOperation(ctypes.Structure):
    """Memory operation structure - matching kernel definition"""
    _fields_ = [
        ("phys_addr", ctypes.c_uint64),
        ("size", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("timestamp", ctypes.c_uint64),
        ("result", ctypes.c_int32),
        ("kernel_errno", ctypes.c_int32),
    ]


class AMTAddrTranslation(ctypes.Structure):
    """Enhanced address translation structure"""
    _fields_ = [
        ("input_addr", ctypes.c_uint64),
        ("output_addr", ctypes.c_uint64),
        ("pid", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
        ("method", ctypes.c_uint32),
        ("success", ctypes.c_int32),
        ("kernel_restricted", ctypes.c_int32),
        ("fallback_used", ctypes.c_int32),
        ("address_type", ctypes.c_uint32),
        ("page_table_entries", ctypes.c_uint64 * 5),
        ("protection_flags", ctypes.c_uint32),
        ("cache_type", ctypes.c_uint32),
        ("error_code", ctypes.c_int32),
    ]


class AMTPageInfo(ctypes.Structure):
    """Enhanced page information structure"""
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
        ("error_code", ctypes.c_int32),
    ]


class AMTKernelCapabilities(ctypes.Structure):
    """Kernel capabilities structure"""
    _fields_ = [
        ("kernel_version", ctypes.c_uint32 * 3),  # major, minor, patch
        ("architecture", ctypes.c_uint32),
        ("page_size", ctypes.c_uint32),
        ("has_gup", ctypes.c_uint32),
        ("has_pte_offset_map", ctypes.c_uint32),
        ("gup_restricted", ctypes.c_uint32),
        ("supports_user_trans", ctypes.c_uint32),
        ("supports_pte_walk", ctypes.c_uint32),
        ("security_level", ctypes.c_uint32),
        ("supported_methods", ctypes.c_uint32),
        ("arch_name", ctypes.c_char * 16),
    ]


class AMTMemoryStats(ctypes.Structure):
    """Enhanced memory statistics structure"""
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
        ("translation_count", ctypes.c_uint32),
        ("gup_count", ctypes.c_uint32),
        ("pte_walk_count", ctypes.c_uint32),
        ("kernel_restricted_count", ctypes.c_uint32),
    ]


class AMTSystemInfo(ctypes.Structure):
    """Enhanced system information structure"""
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
        ("security_flags", ctypes.c_uint32),
        ("paranoid_mode", ctypes.c_uint32),
    ]


class AMTDevModeConfig(ctypes.Structure):
    """Developer mode configuration"""
    _fields_ = [
        ("enabled", ctypes.c_uint32),
        ("force_pte_walk", ctypes.c_uint32),
        ("debug_output", ctypes.c_uint32),
        ("performance_monitoring", ctypes.c_uint32),
        ("reserved", ctypes.c_uint32 * 4),
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
AMT_GET_KERNEL_CAPS = _IOR('A', 9, ctypes.sizeof(AMTKernelCapabilities))
AMT_SET_TRANSLATION_METHOD = _IOW('A', 10, ctypes.sizeof(ctypes.c_uint32))
AMT_SET_DEV_MODE = _IOW('A', 11, ctypes.sizeof(AMTDevModeConfig))
AMT_GET_STATS_ENHANCED = _IOR('A', 12, ctypes.sizeof(AMTMemoryStats))


@dataclass
class OperationResult:
    """Enhanced result of a memory operation"""
    success: bool
    data: Optional[bytes] = None
    error_message: Optional[str] = None
    error_code: Optional[AMTError] = None
    timestamp: Optional[float] = None
    operation_type: Optional[OperationType] = None
    kernel_errno: int = 0
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


@dataclass
class TranslationResult:
    """Enhanced address translation result"""
    success: bool
    physical_addr: int = 0
    method_used: Optional[TranslationMethod] = None
    address_type: Optional[AddressType] = None
    kernel_restricted: bool = False
    fallback_used: bool = False
    error_message: Optional[str] = None
    error_code: Optional[AMTError] = None
    page_table_entries: List[int] = None
    protection_flags: int = 0
    
    def __post_init__(self):
        if self.page_table_entries is None:
            self.page_table_entries = []


@dataclass
class KernelCapabilities:
    """Kernel capabilities information"""
    kernel_version: Tuple[int, int, int]
    architecture: Architecture
    arch_name: str
    page_size: int
    has_gup: bool
    has_pte_offset_map: bool
    gup_restricted: bool
    supports_user_trans: bool
    supports_pte_walk: bool
    security_level: int
    supported_methods: List[TranslationMethod]


@dataclass
class PageInformation:
    """Enhanced detailed page information"""
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
    error_code: Optional[AMTError] = None


@dataclass
class SystemInformation:
    """Enhanced system information"""
    kernel_version: str
    page_size: int
    page_offset: int
    vmalloc_start: int
    vmalloc_end: int
    cpu_count: int
    node_count: int
    architecture: str
    security_flags: int
    paranoid_mode: bool


@dataclass
class MemoryStatistics:
    """Enhanced memory statistics"""
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
    translation_count: int
    gup_count: int
    pte_walk_count: int
    kernel_restricted_count: int
    
    @property
    def success_rate(self) -> float:
        """Calculate operation success rate"""
        total_ops = self.operations_count + self.error_count
        return (self.operations_count / total_ops * 100) if total_ops > 0 else 0.0
    
    @property
    def gup_usage_rate(self) -> float:
        """Calculate GUP usage rate"""
        return (self.gup_count / self.translation_count * 100) if self.translation_count > 0 else 0.0


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
    
    Enhanced for Kernel 6.12+ with comprehensive compatibility layer,
    advanced error handling, and developer-friendly features.
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
        
        # Enhanced state tracking
        self._kernel_caps = None
        self._current_translation_method = TranslationMethod.AUTO
        self._dev_mode_enabled = False
        
        # Initialize logger
        log_level = {
            DebugLevel.ERRORS_ONLY: logging.ERROR,
            DebugLevel.INFO: logging.INFO,
            DebugLevel.DEBUG: logging.DEBUG,
            DebugLevel.VERBOSE: logging.DEBUG
        }.get(debug_level, logging.INFO)
        
        self.logger = AMTLogger("AMT", log_level)
        
        # Initialize caches
        self._system_info = None
        self._stats_cache = None
        self._cache_timeout = 5.0
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
        """
        try:
            if self.device_fd is not None:
                self.logger.warning("Already connected to device")
                return True
            
            # Check if device exists
            if not os.path.exists(DEVICE_PATH):
                raise Exception(f"Device {DEVICE_PATH} not found. Is the kernel module loaded?")
            
            # Check permissions
            if not os.access(DEVICE_PATH, os.R_OK | os.W_OK):
                raise Exception(f"Insufficient permissions for {DEVICE_PATH}. Run as root?")
            
            # Open device
            self.device_fd = os.open(DEVICE_PATH, os.O_RDWR)
            
            # Set debug level in kernel module
            self._set_kernel_debug_level(self.debug_level)
            
            # Get system information and capabilities
            self._system_info = self._get_system_information()
            self._kernel_caps = self._get_kernel_capabilities()
            
            self.logger.info(f"AMT Framework v4.0 initialized successfully")
            self.logger.info(f"Session ID: {self.session_id}")
            self.logger.info(f"Kernel: {'.'.join(map(str, self._kernel_caps.kernel_version))}")
            self.logger.info(f"Architecture: {self._kernel_caps.arch_name}")
            self.logger.info(f"Page Size: {self._kernel_caps.page_size} bytes")
            self.logger.info(f"GUP Available: {self._kernel_caps.has_gup}")
            self.logger.info(f"PTE Offset Map: {self._kernel_caps.has_pte_offset_map}")
            
            if self._kernel_caps.kernel_version >= (6, 12, 0):
                self.logger.warning("Kernel 6.12+ detected - some user-space operations may be restricted")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect: {e}")
            return False
    
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
    
    def close(self):
        """Alias for disconnect()"""
        self.disconnect()
    
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
            raise Exception("Not connected to device. Call connect() first.")
    
    def _validate_address(self, address: int, size: int = 0) -> bool:
        """
        Validate memory address according to safety level
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
        
        return True
    
    def _set_kernel_debug_level(self, level: DebugLevel):
        """Set debug level in kernel module"""
        try:
            level_val = ctypes.c_int(int(level))
            fcntl.ioctl(self.device_fd, AMT_SET_DEBUG_LEVEL, level_val)
            self.logger.debug(f"Kernel debug level set to {level.name}")
        except OSError as e:
            self.logger.warning(f"Failed to set kernel debug level: {e}")
    
    def _get_kernel_capabilities(self) -> KernelCapabilities:
        """Get kernel capabilities"""
        self._check_connection()
        
        try:
            caps = AMTKernelCapabilities()
            fcntl.ioctl(self.device_fd, AMT_GET_KERNEL_CAPS, caps)
            
            # Parse architecture
            arch_map = {
                0: Architecture.X86_64,
                1: Architecture.X86_32,
                2: Architecture.ARM64,
                3: Architecture.ARM32,
                4: Architecture.RISCV64,
                5: Architecture.RISCV32,
            }
            architecture = arch_map.get(caps.architecture, Architecture.UNKNOWN)
            
            # Parse supported methods
            supported_methods = []
            if caps.supported_methods & 1:
                supported_methods.append(TranslationMethod.AUTO)
            if caps.supported_methods & 2:
                supported_methods.append(TranslationMethod.FORCE_PTE)
            if caps.supported_methods & 4:
                supported_methods.append(TranslationMethod.FORCE_GUP)
            if caps.supported_methods & 8:
                supported_methods.append(TranslationMethod.KERNEL_ONLY)
            
            return KernelCapabilities(
                kernel_version=(caps.kernel_version[0], caps.kernel_version[1], caps.kernel_version[2]),
                architecture=architecture,
                arch_name=caps.arch_name.decode('utf-8', errors='ignore').strip('\x00'),
                page_size=caps.page_size,
                has_gup=bool(caps.has_gup),
                has_pte_offset_map=bool(caps.has_pte_offset_map),
                gup_restricted=bool(caps.gup_restricted),
                supports_user_trans=bool(caps.supports_user_trans),
                supports_pte_walk=bool(caps.supports_pte_walk),
                security_level=caps.security_level,
                supported_methods=supported_methods
            )
            
        except OSError as e:
            self.logger.error(f"Failed to get kernel capabilities: {e}")
            raise Exception(f"Kernel capabilities query failed: {e}") from e
    
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
                architecture=info.arch.decode('utf-8', errors='ignore').strip('\x00'),
                security_flags=info.security_flags,
                paranoid_mode=bool(info.paranoid_mode)
            )
            
        except OSError as e:
            self.logger.error(f"Failed to get system information: {e}")
            raise Exception(f"System information query failed: {e}") from e
    
    @property
    def kernel_caps(self) -> Optional[KernelCapabilities]:
        """Get kernel capabilities"""
        return self._kernel_caps
    
    def set_translation_method(self, method: TranslationMethod) -> bool:
        """
        Set address translation method
        
        Args:
            method: Translation method to use
            
        Returns:
            bool: True if method was set successfully
        """
        self._check_connection()
        
        # Check if method is supported
        if self._kernel_caps and method not in self._kernel_caps.supported_methods:
            self.logger.warning(f"Translation method {method.name} not supported by kernel")
            return False
        
        try:
            method_map = {
                TranslationMethod.AUTO: 0,
                TranslationMethod.FORCE_PTE: 1,
                TranslationMethod.FORCE_GUP: 2,
                TranslationMethod.KERNEL_ONLY: 3,
            }
            
            method_val = ctypes.c_uint32(method_map.get(method, 0))
            fcntl.ioctl(self.device_fd, AMT_SET_TRANSLATION_METHOD, method_val)
            
            self._current_translation_method = method
            self.logger.debug(f"Translation method set to {method.name}")
            return True
            
        except OSError as e:
            self.logger.error(f"Failed to set translation method: {e}")
            return False
    
    def set_dev_mode(self, enabled: bool, force_pte_walk: bool = False, 
                     debug_output: bool = True, performance_monitoring: bool = True) -> bool:
        """
        Enable/disable developer mode
        
        Args:
            enabled: Enable developer mode
            force_pte_walk: Force PTE walk even on newer kernels
            debug_output: Enable debug output
            performance_monitoring: Enable performance monitoring
            
        Returns:
            bool: True if mode was set successfully
        """
        self._check_connection()
        
        try:
            config = AMTDevModeConfig()
            config.enabled = 1 if enabled else 0
            config.force_pte_walk = 1 if force_pte_walk else 0
            config.debug_output = 1 if debug_output else 0
            config.performance_monitoring = 1 if performance_monitoring else 0
            
            fcntl.ioctl(self.device_fd, AMT_SET_DEV_MODE, config)
            
            self._dev_mode_enabled = enabled
            self.logger.info(f"Developer mode {'enabled' if enabled else 'disabled'}")
            return True
            
        except OSError as e:
            self.logger.error(f"Failed to set developer mode: {e}")
            return False
    
    def read_physical_memory(self, phys_addr: int, size: int) -> OperationResult:
        """
        Read data from physical memory address
        """
        self._check_connection()
        
        if not self._validate_address(phys_addr, size):
            error_msg = f"Invalid address: 0x{phys_addr:x} (size: {size})"
            self.logger.error(error_msg)
            self.error_count += 1
            return OperationResult(
                success=False,
                error_message=error_msg,
                error_code=AMTError.EINVAL,
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
                        timestamp=result_op.timestamp / 1e9,
                        operation_type=OperationType.READ,
                        kernel_errno=result_op.kernel_errno
                    )
                else:
                    error_code = AMTError(abs(result_op.result)) if result_op.result in [e.value for e in AMTError] else AMTError.EIO
                    error_msg = f"Kernel operation failed with code: {result_op.result}"
                    self.logger.error(error_msg)
                    self.error_count += 1
                    
                    return OperationResult(
                        success=False,
                        error_message=error_msg,
                        error_code=error_code,
                        operation_type=OperationType.READ,
                        kernel_errno=result_op.kernel_errno
                    )
                    
            except OSError as e:
                error_msg = f"Physical memory read failed: {e}"
                self.logger.error(error_msg)
                self.error_count += 1
                
                return OperationResult(
                    success=False,
                    error_message=error_msg,
                    error_code=AMTError.EIO,
                    operation_type=OperationType.READ
                )
    
    def write_physical_memory(self, phys_addr: int, data: bytes) -> OperationResult:
        """
        Write data to physical memory address
        """
        self._check_connection()
        
        if not data:
            error_msg = "No data provided for write operation"
            self.logger.error(error_msg)
            return OperationResult(
                success=False,
                error_message=error_msg,
                error_code=AMTError.EINVAL,
                operation_type=OperationType.WRITE
            )
        
        if not self._validate_address(phys_addr, len(data)):
            error_msg = f"Invalid address for write: 0x{phys_addr:x} (size: {len(data)})"
            self.logger.error(error_msg)
            self.error_count += 1
            return OperationResult(
                success=False,
                error_message=error_msg,
                error_code=AMTError.EINVAL,
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
                        operation_type=OperationType.WRITE,
                        kernel_errno=result_op.kernel_errno
                    )
                else:
                    error_code = AMTError(abs(result_op.result)) if result_op.result in [e.value for e in AMTError] else AMTError.EIO
                    error_msg = f"Kernel write operation failed with code: {result_op.result}"
                    self.logger.error(error_msg)
                    self.error_count += 1
                    
                    return OperationResult(
                        success=False,
                        error_message=error_msg,
                        error_code=error_code,
                        operation_type=OperationType.WRITE,
                        kernel_errno=result_op.kernel_errno
                    )
                    
            except OSError as e:
                error_msg = f"Physical memory write failed: {e}"
                self.logger.error(error_msg)
                self.error_count += 1
                
                return OperationResult(
                    success=False,
                    error_message=error_msg,
                    error_code=AMTError.EIO,
                    operation_type=OperationType.WRITE
                )
    
    def virtual_to_physical(self, virt_addr: int, pid: int = 0) -> TranslationResult:
        """
        Enhanced virtual to physical address translation
        """
        self._check_connection()
        
        if not self._validate_address(virt_addr):
            self.logger.error(f"Invalid virtual address: 0x{virt_addr:x}")
            self.error_count += 1
            return TranslationResult(
                success=False,
                error_message=f"Invalid virtual address: 0x{virt_addr:x}",
                error_code=AMTError.EINVAL
            )
        
        with self._lock:
            try:
                trans = AMTAddrTranslation()
                trans.input_addr = virt_addr
                trans.pid = pid
                trans.flags = 0
                
                fcntl.ioctl(self.device_fd, AMT_VIRT_TO_PHYS, trans)
                
                # Parse method used
                method_map = {
                    0: TranslationMethod.AUTO,
                    1: TranslationMethod.FORCE_PTE,
                    2: TranslationMethod.FORCE_GUP,
                    3: TranslationMethod.KERNEL_ONLY,
                }
                method_used = method_map.get(trans.method, TranslationMethod.AUTO)
                
                # Parse address type
                addr_type_map = {
                    0: AddressType.KERNEL_SPACE,
                    1: AddressType.USER_SPACE,
                    2: AddressType.UNKNOWN,
                }
                address_type = addr_type_map.get(trans.address_type, AddressType.UNKNOWN)
                
                if trans.success:
                    self.operation_count += 1
                    self.logger.debug(f"Translated 0x{virt_addr:x} -> 0x{trans.output_addr:x} using {method_used.name}")
                    
                    return TranslationResult(
                        success=True,
                        physical_addr=trans.output_addr,
                        method_used=method_used,
                        address_type=address_type,
                        kernel_restricted=bool(trans.kernel_restricted),
                        fallback_used=bool(trans.fallback_used),
                        page_table_entries=list(trans.page_table_entries),
                        protection_flags=trans.protection_flags
                    )
                else:
                    error_code = AMTError(abs(trans.error_code)) if trans.error_code in [e.value for e in AMTError] else AMTError.EFAULT
                    error_msg = f"Translation failed for 0x{virt_addr:x}"
                    
                    if trans.kernel_restricted:
                        error_msg += " (kernel restricted)"
                    
                    self.logger.warning(error_msg)
                    self.error_count += 1
                    
                    return TranslationResult(
                        success=False,
                        method_used=method_used,
                        address_type=address_type,
                        kernel_restricted=bool(trans.kernel_restricted),
                        fallback_used=bool(trans.fallback_used),
                        error_message=error_msg,
                        error_code=error_code
                    )
                    
            except OSError as e:
                self.logger.error(f"Address translation failed: {e}")
                self.error_count += 1
                return TranslationResult(
                    success=False,
                    error_message=f"Address translation failed: {e}",
                    error_code=AMTError.EIO
                )
    
    def get_page_information(self, addr: int) -> Optional[PageInformation]:
        """
        Get enhanced page information for an address
        """
        self._check_connection()
        
        with self._lock:
            try:
                info = AMTPageInfo()
                info.addr = addr
                
                fcntl.ioctl(self.device_fd, AMT_GET_PAGE_INFO, info)
                
                self.operation_count += 1
                
                error_code = None
                if info.error_code != 0:
                    error_code = AMTError(abs(info.error_code)) if info.error_code in [e.value for e in AMTError] else AMTError.EFAULT
                
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
                    cache_type=info.cache_type,
                    error_code=error_code
                )
                
            except OSError as e:
                self.logger.error(f"Failed to get page information: {e}")
                self.error_count += 1
                return None
    
    def get_memory_statistics(self, use_cache: bool = True) -> Optional[MemoryStatistics]:
        """
        Get enhanced memory statistics
        """
        self._check_connection()
        
        current_time = time.time()
        if (use_cache and self._stats_cache and 
            current_time - self._last_stats_update < self._cache_timeout):
            return self._stats_cache
        
        with self._lock:
            try:
                stats = AMTMemoryStats()
                fcntl.ioctl(self.device_fd, AMT_GET_STATS_ENHANCED, stats)
                
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
                    bytes_written=stats.bytes_written,
                    translation_count=stats.translation_count,
                    gup_count=stats.gup_count,
                    pte_walk_count=stats.pte_walk_count,
                    kernel_restricted_count=stats.kernel_restricted_count
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
    
    def get_stats(self) -> Dict[str, int]:
        """Get basic statistics for compatibility"""
        return {
            'operations': self.operation_count,
            'errors': self.error_count
        }
    
    def hex_dump(self, data: bytes, addr: int = 0, width: int = 16, 
                 show_ascii: bool = True) -> str:
        """
        Create professional hex dump of data
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
        """
        report = {
            'session_info': {
                'session_id': self.session_id,
                'timestamp': time.time(),
                'version': '4.0 Professional Enhanced',
                'connected': self.device_fd is not None
            },
            'configuration': {
                'debug_level': self.debug_level.name,
                'safety_level': self.safety_level.name,
                'max_buffer_size': self.max_buffer_size,
                'translation_method': self._current_translation_method.name,
                'dev_mode_enabled': self._dev_mode_enabled
            },
            'statistics': {
                'local_operations': self.operation_count,
                'local_errors': self.error_count,
                'success_rate': (self.operation_count / (self.operation_count + self.error_count) * 100) 
                               if (self.operation_count + self.error_count) > 0 else 0.0
            },
            'capabilities': [
                'Physical Memory Read/Write',
                'Enhanced Virtual ↔ Physical Address Translation',
                'Advanced Page Information Retrieval',
                'Kernel 6.12+ Compatibility',
                'Multiple Translation Methods',
                'Developer Mode Support',
                'Professional Error Handling',
                'Thread-Safe Operations'
            ]
        }
        
        # Add kernel capabilities if available
        if self._kernel_caps:
            report['kernel_capabilities'] = {
                'kernel_version': f"{'.'.join(map(str, self._kernel_caps.kernel_version))}",
                'architecture': self._kernel_caps.architecture.name,
                'arch_name': self._kernel_caps.arch_name,
                'page_size': self._kernel_caps.page_size,
                'has_gup': self._kernel_caps.has_gup,
                'has_pte_offset_map': self._kernel_caps.has_pte_offset_map,
                'gup_restricted': self._kernel_caps.gup_restricted,
                'supports_user_trans': self._kernel_caps.supports_user_trans,
                'supports_pte_walk': self._kernel_caps.supports_pte_walk,
                'security_level': self._kernel_caps.security_level,
                'supported_methods': [m.name for m in self._kernel_caps.supported_methods]
            }
        
        # Add system information if available
        sys_info = self.get_system_information()
        if sys_info:
            report['system_info'] = {
                'kernel_version': sys_info.kernel_version,
                'architecture': sys_info.architecture,
                'page_size': sys_info.page_size,
                'cpu_count': sys_info.cpu_count,
                'node_count': sys_info.node_count,
                'paranoid_mode': sys_info.paranoid_mode
            }
        
        # Add memory statistics if available
        mem_stats = self.get_memory_statistics()
        if mem_stats:
            report['memory_stats'] = {
                'total_ram_mb': mem_stats.total_ram // (1024 * 1024),
                'free_ram_mb': mem_stats.free_ram // (1024 * 1024),
                'kernel_operations': mem_stats.operations_count,
                'kernel_errors': mem_stats.error_count,
                'kernel_success_rate': mem_stats.success_rate,
                'translation_count': mem_stats.translation_count,
                'gup_usage_rate': mem_stats.gup_usage_rate,
                'kernel_restricted_count': mem_stats.kernel_restricted_count
            }
        
        return report
    
    @contextmanager
    def operation_context(self, operation_name: str):
        """
        Context manager for operation timing and error handling
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
    Enhanced main function with comprehensive argument parsing
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Advanced Memory Toolkit v4.0 - Enhanced Kernel 6.12+ Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --read-phys 0x1000 256 --hex-dump
  %(prog)s --write-phys 0x2000 48656c6c6f
  %(prog)s --v2p 0xffffffff81000000
  %(prog)s --page-info 0x1000
  %(prog)s --stats --system-info
  %(prog)s --kernel-caps
  %(prog)s --set-method force_gup
  %(prog)s --dev-mode --interactive
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
    
    # Enhanced features
    parser.add_argument('--kernel-caps', action='store_true',
                       help='Show kernel capabilities')
    parser.add_argument('--set-method', choices=['auto', 'force_pte', 'force_gup', 'kernel_only'],
                       help='Set translation method')
    parser.add_argument('--dev-mode', action='store_true',
                       help='Enable developer mode')
    
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
        print("\n🔧 Advanced Memory Toolkit v4.0 Professional Enhanced")
        print("💾 Kernel 6.12+ Compatible Memory Operations Framework")
        print("🔒 Multi-level Safety and Enhanced Error Handling")
        print("🛠️ Advanced Translation Methods and Developer Mode")
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
            safety_level=SafetyLevel(args.safety_level)
        )
    except Exception as e:
        print(f"❌ Failed to initialize AMT: {e}")
        return 1
    
    try:
        with amt:
            # Set translation method if specified
            if args.set_method:
                method_map = {
                    'auto': TranslationMethod.AUTO,
                    'force_pte': TranslationMethod.FORCE_PTE,
                    'force_gup': TranslationMethod.FORCE_GUP,
                    'kernel_only': TranslationMethod.KERNEL_ONLY,
                }
                method = method_map[args.set_method]
                if amt.set_translation_method(method):
                    print(f"✅ Translation method set to {method.name}")
                else:
                    print(f"❌ Failed to set translation method to {method.name}")
            
            # Enable developer mode if requested
            if args.dev_mode:
                if amt.set_dev_mode(True):
                    print("✅ Developer mode enabled")
                else:
                    print("❌ Failed to enable developer mode")
            
            # Handle commands
            if args.kernel_caps:
                caps = amt.kernel_caps
                if caps:
                    print("🔧 Kernel Capabilities:")
                    print(f"  Version: {'.'.join(map(str, caps.kernel_version))}")
                    print(f"  Architecture: {caps.arch_name} ({caps.architecture.name})")
                    print(f"  Page Size: {caps.page_size} bytes")
                    print(f"  GUP Available: {'✅' if caps.has_gup else '❌'}")
                    print(f"  PTE Offset Map: {'✅' if caps.has_pte_offset_map else '❌'}")
                    print(f"  GUP Restricted: {'⚠️' if caps.gup_restricted else '✅'}")
                    print(f"  User Translation: {'✅' if caps.supports_user_trans else '❌'}")
                    print(f"  PTE Walk: {'✅' if caps.supports_pte_walk else '❌'}")
                    print(f"  Security Level: {caps.security_level}")
                    print(f"  Supported Methods: {', '.join(m.name for m in caps.supported_methods)}")
                else:
                    print("❌ Failed to get kernel capabilities")
            
            elif args.read_phys:
                addr, size = int(args.read_phys[0], 16), int(args.read_phys[1])
                result = amt.read_physical_memory(addr, size)
                if result.success:
                    print(f"✅ Read {len(result.data)} bytes from 0x{addr:x}")
                    if args.hex_dump:
                        print(amt.hex_dump(result.data, addr))
                else:
                    print(f"❌ Read failed: {result.error_message}")
                    if result.error_code:
                        print(f"   Error code: {result.error_code.name}")
            
            elif args.v2p:
                vaddr = int(args.v2p[0], 16)
                result = amt.virtual_to_physical(vaddr)
                if result.success:
                    print(f"🔄 Virtual 0x{vaddr:x} → Physical 0x{result.physical_addr:x}")
                    print(f"   Method: {result.method_used.name}")
                    print(f"   Address Type: {result.address_type.name}")
                    if result.kernel_restricted:
                        print(f"   ⚠️ Kernel restricted")
                    if result.fallback_used:
                        print(f"   🔄 Fallback used")
                else:
                    print(f"❌ Translation failed for 0x{vaddr:x}")
                    print(f"   Error: {result.error_message}")
                    if result.error_code:
                        print(f"   Error code: {result.error_code.name}")
            
            elif args.interactive:
                interactive_mode(amt)
            
            # Handle other commands (similar to before but with enhanced output)
            
    except KeyboardInterrupt:
        print("\n⚠️ Operation interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1
    
    return 0


def interactive_mode(amt: AdvancedMemoryToolkit):
    """Enhanced interactive mode"""
    print(f"\n💻 AMT v4.0 Enhanced Interactive Mode")
    print(f"🔧 Session: {amt.session_id}")
    
    if amt.kernel_caps:
        print(f"🖥️ Kernel: {'.'.join(map(str, amt.kernel_caps.kernel_version))} ({amt.kernel_caps.arch_name})")
        if amt.kernel_caps.kernel_version >= (6, 12, 0):
            print("⚠️ Kernel 6.12+ detected - some user-space operations may be restricted")
    
    print("\nEnhanced Commands:")
    commands = {
        'read <addr> <size>': 'Read physical memory',
        'write <addr> <hex_data>': 'Write to physical memory',
        'v2p <vaddr> [pid]': 'Virtual to physical translation',
        'method <auto|force_pte|force_gup>': 'Set translation method',
        'devmode <on|off>': 'Toggle developer mode',
        'caps': 'Show kernel capabilities',
        'stats': 'Show memory statistics',
        'help': 'Show this help',
        'quit': 'Exit interactive mode'
    }
    
    for cmd, desc in commands.items():
        print(f"  {cmd:<30} - {desc}")
    
    while True:
        try:
            cmd_line = input("\namt> ").strip()
            if not cmd_line:
                continue
            
            cmd_parts = cmd_line.split()
            cmd = cmd_parts[0].lower()
            
            if cmd == 'quit' or cmd == 'exit':
                break
            
            elif cmd == 'caps':
                caps = amt.kernel_caps
                if caps:
                    print(f"🔧 Kernel {'.'.join(map(str, caps.kernel_version))} on {caps.arch_name}")
                    print(f"   GUP: {'✅' if caps.has_gup else '❌'} | "
                          f"PTE: {'✅' if caps.has_pte_offset_map else '❌'} | "
                          f"Restricted: {'⚠️' if caps.gup_restricted else '✅'}")
                    print(f"   Methods: {', '.join(m.name for m in caps.supported_methods)}")
                else:
                    print("❌ No capabilities available")
            
            elif cmd == 'method' and len(cmd_parts) >= 2:
                method_map = {
                    'auto': TranslationMethod.AUTO,
                    'force_pte': TranslationMethod.FORCE_PTE,
                    'force_gup': TranslationMethod.FORCE_GUP,
                }
                method_name = cmd_parts[1].lower()
                if method_name in method_map:
                    if amt.set_translation_method(method_map[method_name]):
                        print(f"✅ Method set to {method_name}")
                    else:
                        print(f"❌ Failed to set method")
                else:
                    print(f"❌ Unknown method: {method_name}")
            
            elif cmd == 'devmode' and len(cmd_parts) >= 2:
                enable = cmd_parts[1].lower() in ['on', 'true', '1', 'enable']
                if amt.set_dev_mode(enable):
                    print(f"✅ Developer mode {'enabled' if enable else 'disabled'}")
                else:
                    print(f"❌ Failed to set developer mode")
            
            elif cmd == 'v2p' and len(cmd_parts) >= 2:
                vaddr = int(cmd_parts[1], 16)
                pid = int(cmd_parts[2]) if len(cmd_parts) > 2 else 0
                result = amt.virtual_to_physical(vaddr, pid)
                if result.success:
                    print(f"🔄 0x{vaddr:x} → 0x{result.physical_addr:x}")
                    print(f"   Method: {result.method_used.name} | Type: {result.address_type.name}")
                    if result.kernel_restricted:
                        print("   ⚠️ Kernel restricted")
                    if result.fallback_used:
                        print("   🔄 Fallback used")
                else:
                    print(f"❌ Translation failed: {result.error_message}")
            
            # Handle other commands...
            else:
                if cmd != 'help':
                    print(f"❓ Unknown command: {cmd}")
                for cmd_help, desc in commands.items():
                    print(f"  {cmd_help:<30} - {desc}")
        
        except KeyboardInterrupt:
            print(f"\n💡 Use 'quit' to exit")
        except ValueError as e:
            print(f"❌ Invalid input: {e}")
        except Exception as e:
            print(f"❌ Error: {e}")
    
    print(f"👋 Exiting interactive mode")


if __name__ == "__main__":
    sys.exit(main())
