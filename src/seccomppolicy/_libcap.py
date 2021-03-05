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
    cap_init = None
    cap_get_proc = cap_set_proc = None
    cap_get_flag = cap_set_flag = None
    cap_get_bound = cap_drop_bound = None
    cap_get_ambient = cap_set_ambient = None
    cap_get_mode = cap_set_mode = None
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

    # initialize empty cap_t
    cap_init = _lc.cap_init
    cap_init.argtype = ()
    cap_init.restype = cap_t
    cap_init.errcheck = _check_init

    # duplicate cap_t
    cap_dup = _lc.cap_dup
    cap_dup.argtype = (cap_t,)
    cap_dup.restype = cap_t
    cap_dup.errcheck = _check_init

    # compare cap_t like memcmp()
    cap_compare = _lc.cap_compare
    cap_compare.argtype = (cap_t, cap_t)
    cap_compare.restype = ctypes.c_int
    cap_compare.errcheck = _check_success

    # get cap_t of calling process
    cap_get_proc = _lc.cap_get_proc
    cap_get_proc.argtype = ()
    cap_get_proc.restype = cap_t
    cap_get_proc.errcheck = _check_init

    # set capabilities of calling process
    cap_set_proc = _lc.cap_set_proc
    cap_set_proc.argtype = (cap_t,)
    cap_set_proc.restype = ctypes.c_int
    cap_set_proc.errcheck = _check_success

    # get capability value for cap_t
    cap_get_flag = _lc.cap_get_flag
    cap_get_flag.argtypes = (
        cap_t,
        cap_value_t,
        cap_flag_t,
        ctypes.POINTER(cap_flag_value_t),
    )
    cap_get_flag.restype = ctypes.c_int
    cap_get_flag.errcheck = _check_success

    # modify capability value of cap_t
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

    # clear capabilities
    cap_clear_flag = _lc.cap_clear_flag
    cap_clear_flag.argtypes = (cap_t, cap_flag_t)
    cap_clear_flag.restype = ctypes.c_int
    cap_clear_flag.errcheck = _check_success

    # process-wide bounding set
    cap_get_bound = _lc.cap_get_bound
    cap_get_bound.argtypes = (cap_value_t,)
    cap_get_bound.restype = ctypes.c_int
    cap_get_bound.errcheck = _check_success

    cap_drop_bound = _lc.cap_drop_bound
    cap_drop_bound.argtypes = (cap_value_t,)
    cap_drop_bound.restype = ctypes.c_int
    cap_drop_bound.errcheck = _check_success

    # process-wide ambient set
    cap_get_ambient = _lc.cap_get_ambient
    cap_get_ambient.argtypes = (cap_value_t,)
    cap_get_ambient.restype = ctypes.c_int
    cap_get_ambient.errcheck = _check_success

    cap_set_ambient = _lc.cap_set_ambient
    cap_set_ambient.argtypes = (cap_value_t, cap_flag_value_t)
    cap_set_ambient.restype = ctypes.c_int
    cap_set_ambient.errcheck = _check_success

    # high level, process-wide get/set mode
    cap_get_mode = _lc.cap_get_mode
    cap_get_mode.argtype = ()
    cap_get_mode.restype = cap_mode_t
    cap_get_mode.errcheck = _check_get_mode

    cap_set_mode = _lc.cap_set_mode
    cap_set_mode.argtype = (cap_mode_t,)
    cap_set_mode.restype = ctypes.c_int
    cap_set_mode.errcheck = _check_success

    # free memory
    cap_free = _lc.cap_free
    cap_free.argtypes = (cap_t,)
    cap_free.restype = ctypes.c_int
    cap_free.errcheck = _check_success


class _CapContext:
    __slots__ = ("_cap_p", "_cap_new")

    def __init__(self):
        self._cap_p = None
        self._cap_new = None

    def get_flag(self, cap, flag=CapFlag.EFFECTIVE):
        """Get capability of current process

        returns CAP_SET / CAP_CLEAR
        """
        result = cap_flag_value_t()
        cap_get_flag(self._cap_p, cap, flag, ctypes.pointer(result))
        return result.value

    def init_set(self, *, dup):
        if self._cap_new is not None:
            raise ValueError
        if dup:
            self._cap_new = cap_dup(self._cap_p)
        else:
            self._cap_new = cap_init()

    def set_flag(self, caps, flag, value):
        ncaps = len(caps)
        cap_arr = (cap_value_t * ncaps)()
        for i, cap in enumerate(caps):
            cap_arr[i] = cap
        cap_set_flag(self._cap_new, flag, ncaps, cap_arr, value)

    def clear_flag(self, flag):
        cap_clear_flag(self._cap_new, flag)

    def set_proc(self):
        # only set cap when new capset is different
        if cap_compare(self._cap_p, self._cap_new):
            cap_set_proc(self._cap_new)
            return True
        else:
            return False

    def __enter__(self):
        self._cap_p = cap_get_proc()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # free cap_new
        cap_new = self._cap_new
        if cap_new is not None:
            self._cap_new = None
            cap_free(cap_new)
        # free cap_p
        cap_p = self._cap_p
        self._cap_p = None
        cap_free(cap_p)


def cap_is_supported(cap):
    """Macro CAP_IS_SUPPORTED(cap)"""
    try:
        cap_get_bound(cap)
    except OSError:
        return False
    else:
        return True


def cap_ambient_supported():
    """Macro CAP_AMBIENT_SUPPORTED()"""
    try:
        cap_get_ambient(Capabilities.CAP_CHOWN)
    except OSError:
        return False
    else:
        return True


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
        with _CapContext() as ctx:
            return bool(ctx.get_flag(cap, flag))
    else:
        return None


def drop_caps(*caps, currentprocess=True):
    with _CapContext() as ctx:
        ctx.init_set(dup=True)

        ctx.set_flag(caps, CapFlag.INHERITABLE, CAP_CLEAR)
        if currentprocess:
            ctx.set_flag(caps, CapFlag.PERMITTED, CAP_CLEAR)
            ctx.set_flag(caps, CapFlag.EFFECTIVE, CAP_CLEAR)

        # also run cap_drop_bound(cap) ???

        return ctx.set_proc()


def limit_caps(*caps, currentprocess=True):
    with _CapContext() as ctx:
        if currentprocess:
            # start with an empty context
            ctx.init_set(dup=False)
            flags = [CapFlag.INHERITABLE, CapFlag.PERMITTED, CapFlag.EFFECTIVE]
        else:
            # dupped context, clear INHERITABLE
            ctx.init_set(dup=True)
            ctx.clear_flag(CapFlag.INHERITABLE)
            flags = [CapFlag.INHERITABLE]

        for flag in flags:
            new_caps = []
            # only keep caps that are currently set
            for cap in caps:
                if ctx.get_flag(cap, flag):
                    new_caps.append(cap)
            if new_caps:
                ctx.set_flag(new_caps, flag, CAP_SET)

        return ctx.set_proc()


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
    drop_caps(*caps)
    for cap in caps:
        print(cap, has_cap(cap, flag))

    print("---")
    print("Limit")
    limit_caps(Capabilities.CAP_SYS_ADMIN, Capabilities.CAP_SETPCAP)
    for name, value in Capabilities.__members__.items():
        print(name, has_cap(value))

    if has_cap(Capabilities.CAP_SETPCAP):
        print("---")
        print("cap_set_mode(NOPRIV)")
        cap_set_mode(CapMode.NOPRIV)
        print(cap_get_mode())
        for name, value in Capabilities.__members__.items():
            print(name, has_cap(value))
