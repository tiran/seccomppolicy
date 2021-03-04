import ctypes
from ctypes.util import find_library

__all__ = ("free",)

_libc_path = find_library("c")
if _libc_path is None:
    raise ImportError("Unable to find library libc")

_libc = ctypes.CDLL(_libc_path)

free = _libc.free
free.argtypes = (ctypes.c_void_p,)
free.restype = None
