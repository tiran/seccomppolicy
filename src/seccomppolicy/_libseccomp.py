import ctypes
from ctypes.util import find_library
import errno

from . import _libc
from ._constants import ScmpArch, ScmpCmp

__all__ = (
    "ScmpArg",
    "scmp_filter_ctx",
    "seccomp_arch_add",
    "seccomp_arch_native",
    "seccomp_init",
    "seccomp_load",
    "seccomp_release",
    "seccomp_rule_add_array",
    "seccomp_rule_add_exact_array",
    "seccomp_syscall_resolve_name_arch",
    "seccomp_syscall_resolve_num_arch",
)


_lsc_path = find_library("seccomp")
if _lsc_path is None:
    raise ImportError("Unable to find library libseccomp")

_lsc = ctypes.CDLL(_lsc_path)

# errcheck functions


def _check_init(result, func, args):
    if result is None:
        # seccomp_init(3) returns negative errno
        raise OSError(-result, func.__name__, args)
    return result


def _check_success(result, func, args):
    if result != 0:
        raise OSError(-result, func.__name__, args)
    return result


def _check_syscall_resolve_num(result, func, args):
    if not result:
        raise ValueError(args)
    try:
        # convert char* to Python bytes, then ASCII text
        name = ctypes.string_at(result)
        return name.decode("ascii")
    finally:
        _libc.free(result)


def _check_syscall_resolve_name(result, func, args):
    if result == -1:  # __NR_SCMP_ERROR
        raise ValueError(args)
    return result


def _check_arch(result, func, args):
    if result == ScmpArch.SCMP_ARCH_NATIVE:
        raise OSError(errno.EINVAL, func.__name__, args)
    return ScmpArch(result)


# structures
class scmp_filter(ctypes.Structure):
    __slots__ = ()


scmp_filter_ctx = ctypes.POINTER(scmp_filter)


class ScmpArg(ctypes.Structure):
    """scmp_arg_cmp"""

    __slots__ = ()
    _fields_ = [
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    ]

    def __init__(self, arg, op, datum_a, datum_b=0):
        if arg < 0 or arg > 5:
            raise ValueError("invalid arg '{}'".format(arg))
        if op not in ScmpCmp:
            raise ValueError("invalid op '{}'".format(op))
        # datum_b is only used by SCMP_CMP_MASKED_EQ
        super().__init__(arg, op, datum_a, datum_b)

    @classmethod
    def toarray(cls, *args):
        if len(args) > 5:
            raise ValueError("too many arguments")
        array = (cls * len(args))()
        for i, arg in enumerate(args):
            array[i] = arg
        return array

    def __repr__(self):
        return (
            "{self.__class__.__name__}({self.arg}, ScmpCmp.{op}, "
            "{self.datum_a}, {self.datum_b})"
        ).format(self=self, op=ScmpCmp(self.op)._name_)


# functions

seccomp_init = _lsc.seccomp_init
seccomp_init.argtypes = (ctypes.c_uint32,)
seccomp_init.restype = scmp_filter_ctx
seccomp_init.errcheck = _check_init

seccomp_release = _lsc.seccomp_release
seccomp_release.argtypes = (scmp_filter_ctx,)
seccomp_release.restype = None

seccomp_load = _lsc.seccomp_load
seccomp_load.argtypes = (scmp_filter_ctx,)
seccomp_load.restype = ctypes.c_int
seccomp_load.errcheck = _check_success

seccomp_arch_add = _lsc.seccomp_arch_add
seccomp_arch_add.argtypes = (scmp_filter_ctx, ctypes.c_uint32)
seccomp_arch_add.restype = ctypes.c_int
seccomp_arch_add.errcheck = _check_success

seccomp_arch_native = _lsc.seccomp_arch_native
seccomp_arch_native.argtypes = ()
seccomp_arch_native.restype = ctypes.c_uint32
seccomp_arch_native.errcheck = _check_arch

seccomp_rule_add_array = _lsc.seccomp_rule_add_array
seccomp_rule_add_array.argtypes = (
    scmp_filter_ctx,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.POINTER(ScmpArg),
)
seccomp_rule_add_array.restype = ctypes.c_int
seccomp_rule_add_array.errcheck = _check_success

seccomp_rule_add_exact_array = _lsc.seccomp_rule_add_exact_array
seccomp_rule_add_exact_array.argtypes = (
    scmp_filter_ctx,
    ctypes.c_uint32,
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.POINTER(ScmpArg),
)
seccomp_rule_add_exact_array.restype = ctypes.c_int
seccomp_rule_add_exact_array.errcheck = _check_success

seccomp_syscall_resolve_name_arch = _lsc.seccomp_syscall_resolve_name_arch
seccomp_syscall_resolve_name_arch.argtypes = (ctypes.c_uint32, ctypes.c_char_p)
seccomp_syscall_resolve_name_arch.restype = ctypes.c_int
seccomp_syscall_resolve_name_arch.errcheck = _check_syscall_resolve_name

seccomp_syscall_resolve_num_arch = _lsc.seccomp_syscall_resolve_num_arch
seccomp_syscall_resolve_num_arch.argtypes = (ctypes.c_uint32, ctypes.c_int)
# result is allocated on the heap and must be freed, cannot use c_char_p here
seccomp_syscall_resolve_num_arch.restype = ctypes.POINTER(ctypes.c_char)
seccomp_syscall_resolve_num_arch.errcheck = _check_syscall_resolve_num
