import ctypes
from ctypes.util import find_library

__all__ = ("free",)

_libc_path = find_library("c")
if _libc_path is None:
    raise ImportError("Unable to find library libc")

_libc = ctypes.CDLL(_libc_path, use_errno=True)

free = _libc.free
free.argtypes = (ctypes.c_void_p,)
free.restype = None


def _check_prctl(result, func, args):
    if result == -1:
        raise OSError(ctypes.get_errno(), func.__name__, args)
    return result


_prctl = _libc.prctl
# second argument is actually c_ulong, but some options pass in a pointer
_prctl.argtypes = (
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_ulong,
    ctypes.c_ulong,
    ctypes.c_ulong,
)
_prctl.restype = ctypes.c_int
_prctl.errcheck = _check_prctl


def prctl(option, a2=0, a3=0, a4=0, a5=0):
    """Simple prctl syscall interface"""
    return _prctl(option, a2, a3, a4, a5)
