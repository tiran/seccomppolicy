import ctypes
from ctypes.util import find_library
import errno

from ._constants import Capabilities, CapFlag, CapMode


CAP_CLEAR = 0
CAP_SET = 1


class _cap_t(ctypes.Structure):
    __slots__ = ()


cap_t = ctypes.POINTER(_cap_t)
cap_value_t = ctypes.c_int
cap_flag_t = ctypes.c_int  # CapFlag
cap_flag_value_t = ctypes.c_int
cap_mode_t = ctypes.c_uint  # CapMode

try:
    _lc_path = find_library("cap")
    if _lc_path is None:
        raise ImportError("Unable to find library libcap")
    _lc = ctypes.CDLL(_lc_path)
except (OSError, ImportError):
    HAS_LIBCAP = False
    cap_dup = None
    cap_compare = None
    cap_get_proc = None
    cap_set_proc = None
    cap_get_flag = None
    cap_set_flag = None
    cap_get_mode = None
    cap_set_mode = None
    cap_drop_bound = None
    cap_free = None
else:
    HAS_LIBCAP = True

    def _check_init(result, func, args):
        if not result:
            # cap_init(3), cap_get_proc(3) return NULL on error
            raise OSError(result, func.__name__, args)
        return result

    def _check_success(result, func, args):
        if result == -1:
            raise OSError(errno.EINVAL, func, args)
        return result

    def _check_get_mode(result, func, args):
        if result == -1:
            raise OSError(errno.EINVAL, func, args)
        return CapMode(result)

    cap_dup = _lc.cap_dup
    cap_dup.argtype = (cap_t,)
    cap_dup.restype = cap_t
    cap_dup.errcheck = _check_init

    cap_compare = _lc.cap_compare
    cap_compare.argtype = (cap_t, cap_t)
    cap_compare.restype = ctypes.c_int
    cap_compare.errcheck = _check_success

    cap_get_proc = _lc.cap_get_proc
    cap_get_proc.argtype = ()
    cap_get_proc.restype = cap_t
    cap_get_proc.errcheck = _check_init

    cap_set_proc = _lc.cap_set_proc
    cap_set_proc.argtype = (cap_t,)
    cap_set_proc.restype = ctypes.c_int
    cap_set_proc.errcheck = _check_success

    cap_get_flag = _lc.cap_get_flag
    cap_get_flag.argtypes = (
        cap_t,
        cap_value_t,
        cap_flag_t,
        ctypes.POINTER(cap_flag_value_t),
    )
    cap_get_flag.restype = ctypes.c_int
    cap_get_flag.errcheck = _check_success

    cap_set_flag = _lc.cap_set_flag
    cap_set_flag.argtypes = (
        cap_t,
        cap_flag_t,
        ctypes.c_int,  # size of caps array
        ctypes.POINTER(cap_value_t),  # caps, array of cap_value_t
        cap_flag_value_t,
    )
    cap_set_flag.restype = ctypes.c_int
    cap_set_flag.errcheck = _check_success

    cap_drop_bound = _lc.cap_drop_bound
    cap_drop_bound.argtype = (cap_value_t,)
    cap_drop_bound.restype = ctypes.c_int
    cap_drop_bound.errcheck = _check_success

    cap_get_mode = _lc.cap_get_mode
    cap_get_mode.argtype = ()
    cap_get_mode.restype = cap_mode_t
    cap_get_mode.errcheck = _check_get_mode

    cap_set_mode = _lc.cap_set_mode
    cap_set_mode.argtype = (cap_mode_t,)
    cap_set_mode.restype = ctypes.c_int
    cap_set_mode.errcheck = _check_success

    cap_free = _lc.cap_free
    cap_free.argtypes = (cap_t,)
    cap_free.restype = ctypes.c_int
    cap_free.errcheck = _check_success


def has_cap(cap, flag=CapFlag.EFFECTIVE):
    """Get capability of current process

    Returns None if libcap is not available.

    :param cap: Cabability
    :param flag: CapFlag (
    :return: True, False, None
    """
    if not isinstance(cap, Capabilities):
        raise TypeError(cap)
    if not isinstance(flag, CapFlag):
        raise TypeError(flag)

    if HAS_LIBCAP:
        result = cap_flag_value_t()
        cap_p = cap_get_proc()
        try:
            cap_get_flag(cap_p, cap, flag, ctypes.pointer(result))
        finally:
            cap_free(cap_p)
        return True if result.value == CAP_SET else False
    else:
        return None


def drop_cap(*caps, currentprocess=True):
    cap_p = cap_get_proc()
    cap_new = cap_dup(cap_p)
    try:
        ncaps = len(caps)
        cap_arr = (cap_value_t * ncaps)()
        for i, cap in enumerate(caps):
            cap_arr[i] = cap
        cap_set_flag(cap_new, CapFlag.INHERITABLE, ncaps, cap_arr, CAP_CLEAR)
        if currentprocess:
            cap_set_flag(cap_new, CapFlag.PERMITTED, ncaps, cap_arr, CAP_CLEAR)
            cap_set_flag(cap_new, CapFlag.EFFECTIVE, ncaps, cap_arr, CAP_CLEAR)

        # also run cap_drop_bound(cap) ???

        # only set cap when new capset is different
        if cap_compare(cap_p, cap_new):
            # gain effective CAP_SETPCAP if process has only PERMITTED CAP_SETPCAP?
            cap_set_proc(cap_new)
    finally:
        cap_free(cap_p)
        cap_free(cap_new)


if __name__ == "__main__":
    for name, value in Capabilities.__members__.items():
        print(name, has_cap(value))
    print("---")
    print(cap_get_mode())
    caps = [Capabilities.CAP_SYS_BOOT, Capabilities.CAP_SYS_NICE]
    flag = CapFlag.PERMITTED
    print(caps, flag)
    for cap in caps:
        print(cap, has_cap(cap, flag))
    print("dropping...")
    drop_cap(*caps)
    for cap in caps:
        print(cap, has_cap(cap, flag))

    print("---")
    print("cap_set_mode(NOPRIV)")
    cap_set_mode(CapMode.NOPRIV)
    print(cap_get_mode())
    for name, value in Capabilities.__members__.items():
        print(name, has_cap(value))
