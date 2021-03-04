import enum


__all__ = (
    "Capabilities",
    "CapFlag",
    "CapMode",
    "ScmpAction",
    "ScmpArch",
    "ScmpCmp",
    "ScmpEnum",
    "ScmpNr",
    "translate_scmp",
)

REPR = "{self.__class__.__name__}.{self._name_}"
REPR_VERBOSE = "<{self.__class__.__name__}.{self._name_}: 0x{self._value_:x}>"


class ScmpEnum(enum.IntEnum):
    def __repr__(self):
        return REPR.format(self=self)


def _scmp_act_errno(x):
    return 0x00050000 | (x & 0x0000FFFF)


def _scmp_act_trace(x):
    return 0x7FF00000 | (x & 0x0000FFFF)


class ScmpAction(ScmpEnum):
    """SCMP_ACT actions"""

    @classmethod
    def errno(cls, x=0):
        x = cls._scmp_act_errno(x)
        try:
            return cls(x)
        except ValueError:
            return x

    @classmethod
    def trace(cls, x):
        return cls._scmp_act_trace(x)

    SCMP_ACT_KILL_PROCESS = 0x80000000
    SCMP_ACT_KILL_THREAD = 0x00000000
    SCMP_ACT_KILL = SCMP_ACT_KILL_THREAD
    SCMP_ACT_TRAP = 0x00030000
    SCMP_ACT_NOTIFY = 0x7FC00000
    # ???
    SCMP_ACT_ERRNO = _scmp_act_errno(0)
    SCMP_ACT_TRACE = _scmp_act_trace(0)
    SCMP_ACT_LOG = 0x7FFC0000
    SCMP_ACT_ALLOW = 0x7FFF0000

    SCMP_ACT_EPERM = _scmp_act_errno(getattr(errno, "EPERM", 1))
    SCMP_ACT_EINVAL = _scmp_act_errno(getattr(errno, "EINVAL", 22))
    SCMP_ACT_ENOSYS = _scmp_act_errno(getattr(errno, "ENOSYS", 38))

    SCMP_ACT_ENOENT = _scmp_act_errno(getattr(errno, "ENOENT", 2))
    SCMP_ACT_ESRCH = _scmp_act_errno(getattr(errno, "ESRCH", 3))
    SCMP_ACT_EINTR = _scmp_act_errno(getattr(errno, "EINTR", 4))
    SCMP_ACT_EIO = _scmp_act_errno(getattr(errno, "EIO", 5))
    SCMP_ACT_ENXIO = _scmp_act_errno(getattr(errno, "ENXIO", 6))
    SCMP_ACT_E2BIG = _scmp_act_errno(getattr(errno, "E2BIG", 7))
    SCMP_ACT_ENOEXEC = _scmp_act_errno(getattr(errno, "ENOEXEC", 8))
    SCMP_ACT_EBADF = _scmp_act_errno(getattr(errno, "EBADF", 9))
    SCMP_ACT_ECHILD = _scmp_act_errno(getattr(errno, "ECHILD", 10))
    SCMP_ACT_EAGAIN = _scmp_act_errno(getattr(errno, "EAGAIN", 11))
    SCMP_ACT_ENOMEM = _scmp_act_errno(getattr(errno, "ENOMEM", 12))
    SCMP_ACT_EACCES = _scmp_act_errno(getattr(errno, "EACCES", 13))
    SCMP_ACT_EFAULT = _scmp_act_errno(getattr(errno, "EFAULT", 14))
    SCMP_ACT_ENOTBLK = _scmp_act_errno(getattr(errno, "ENOTBLK", 15))
    SCMP_ACT_EBUSY = _scmp_act_errno(getattr(errno, "EBUSY", 16))
    SCMP_ACT_EEXIST = _scmp_act_errno(getattr(errno, "EEXIST", 17))
    SCMP_ACT_EXDEV = _scmp_act_errno(getattr(errno, "EXDEV", 18))
    SCMP_ACT_ENODEV = _scmp_act_errno(getattr(errno, "ENODEV", 19))
    SCMP_ACT_ENOTDIR = _scmp_act_errno(getattr(errno, "ENOTDIR", 20))
    SCMP_ACT_EISDIR = _scmp_act_errno(getattr(errno, "EISDIR", 21))
    SCMP_ACT_ENFILE = _scmp_act_errno(getattr(errno, "ENFILE", 23))
    SCMP_ACT_EMFILE = _scmp_act_errno(getattr(errno, "EMFILE", 24))
    SCMP_ACT_ENOTTY = _scmp_act_errno(getattr(errno, "ENOTTY", 25))
    SCMP_ACT_ETXTBSY = _scmp_act_errno(getattr(errno, "ETXTBSY", 26))
    SCMP_ACT_EFBIG = _scmp_act_errno(getattr(errno, "EFBIG", 27))
    SCMP_ACT_ENOSPC = _scmp_act_errno(getattr(errno, "ENOSPC", 28))
    SCMP_ACT_ESPIPE = _scmp_act_errno(getattr(errno, "ESPIPE", 29))
    SCMP_ACT_EROFS = _scmp_act_errno(getattr(errno, "EROFS", 30))
    SCMP_ACT_EMLINK = _scmp_act_errno(getattr(errno, "EMLINK", 31))
    SCMP_ACT_EPIPE = _scmp_act_errno(getattr(errno, "EPIPE", 32))
    SCMP_ACT_EDOM = _scmp_act_errno(getattr(errno, "EDOM", 33))
    SCMP_ACT_ERANGE = _scmp_act_errno(getattr(errno, "ERANGE", 34))
    SCMP_ACT_EDEADLOCK = _scmp_act_errno(getattr(errno, "EDEADLOCK", 35))
    SCMP_ACT_ENAMETOOLONG = _scmp_act_errno(getattr(errno, "ENAMETOOLONG", 36))
    SCMP_ACT_ENOLCK = _scmp_act_errno(getattr(errno, "ENOLCK", 37))
    SCMP_ACT_ENOTEMPTY = _scmp_act_errno(getattr(errno, "ENOTEMPTY", 39))
    SCMP_ACT_ELOOP = _scmp_act_errno(getattr(errno, "ELOOP", 40))
    SCMP_ACT_ENOMSG = _scmp_act_errno(getattr(errno, "ENOMSG", 42))
    SCMP_ACT_EIDRM = _scmp_act_errno(getattr(errno, "EIDRM", 43))
    SCMP_ACT_ECHRNG = _scmp_act_errno(getattr(errno, "ECHRNG", 44))
    SCMP_ACT_EL2NSYNC = _scmp_act_errno(getattr(errno, "EL2NSYNC", 45))
    SCMP_ACT_EL3HLT = _scmp_act_errno(getattr(errno, "EL3HLT", 46))
    SCMP_ACT_EL3RST = _scmp_act_errno(getattr(errno, "EL3RST", 47))
    SCMP_ACT_ELNRNG = _scmp_act_errno(getattr(errno, "ELNRNG", 48))
    SCMP_ACT_EUNATCH = _scmp_act_errno(getattr(errno, "EUNATCH", 49))
    SCMP_ACT_ENOCSI = _scmp_act_errno(getattr(errno, "ENOCSI", 50))
    SCMP_ACT_EL2HLT = _scmp_act_errno(getattr(errno, "EL2HLT", 51))
    SCMP_ACT_EBADE = _scmp_act_errno(getattr(errno, "EBADE", 52))
    SCMP_ACT_EBADR = _scmp_act_errno(getattr(errno, "EBADR", 53))
    SCMP_ACT_EXFULL = _scmp_act_errno(getattr(errno, "EXFULL", 54))
    SCMP_ACT_ENOANO = _scmp_act_errno(getattr(errno, "ENOANO", 55))
    SCMP_ACT_EBADRQC = _scmp_act_errno(getattr(errno, "EBADRQC", 56))
    SCMP_ACT_EBADSLT = _scmp_act_errno(getattr(errno, "EBADSLT", 57))
    SCMP_ACT_EBFONT = _scmp_act_errno(getattr(errno, "EBFONT", 59))
    SCMP_ACT_ENOSTR = _scmp_act_errno(getattr(errno, "ENOSTR", 60))
    SCMP_ACT_ENODATA = _scmp_act_errno(getattr(errno, "ENODATA", 61))
    SCMP_ACT_ETIME = _scmp_act_errno(getattr(errno, "ETIME", 62))
    SCMP_ACT_ENOSR = _scmp_act_errno(getattr(errno, "ENOSR", 63))
    SCMP_ACT_ENONET = _scmp_act_errno(getattr(errno, "ENONET", 64))
    SCMP_ACT_ENOPKG = _scmp_act_errno(getattr(errno, "ENOPKG", 65))
    SCMP_ACT_EREMOTE = _scmp_act_errno(getattr(errno, "EREMOTE", 66))
    SCMP_ACT_ENOLINK = _scmp_act_errno(getattr(errno, "ENOLINK", 67))
    SCMP_ACT_EADV = _scmp_act_errno(getattr(errno, "EADV", 68))
    SCMP_ACT_ESRMNT = _scmp_act_errno(getattr(errno, "ESRMNT", 69))
    SCMP_ACT_ECOMM = _scmp_act_errno(getattr(errno, "ECOMM", 70))
    SCMP_ACT_EPROTO = _scmp_act_errno(getattr(errno, "EPROTO", 71))
    SCMP_ACT_EMULTIHOP = _scmp_act_errno(getattr(errno, "EMULTIHOP", 72))
    SCMP_ACT_EDOTDOT = _scmp_act_errno(getattr(errno, "EDOTDOT", 73))
    SCMP_ACT_EBADMSG = _scmp_act_errno(getattr(errno, "EBADMSG", 74))
    SCMP_ACT_EOVERFLOW = _scmp_act_errno(getattr(errno, "EOVERFLOW", 75))
    SCMP_ACT_ENOTUNIQ = _scmp_act_errno(getattr(errno, "ENOTUNIQ", 76))
    SCMP_ACT_EBADFD = _scmp_act_errno(getattr(errno, "EBADFD", 77))
    SCMP_ACT_EREMCHG = _scmp_act_errno(getattr(errno, "EREMCHG", 78))
    SCMP_ACT_ELIBACC = _scmp_act_errno(getattr(errno, "ELIBACC", 79))
    SCMP_ACT_ELIBBAD = _scmp_act_errno(getattr(errno, "ELIBBAD", 80))
    SCMP_ACT_ELIBSCN = _scmp_act_errno(getattr(errno, "ELIBSCN", 81))
    SCMP_ACT_ELIBMAX = _scmp_act_errno(getattr(errno, "ELIBMAX", 82))
    SCMP_ACT_ELIBEXEC = _scmp_act_errno(getattr(errno, "ELIBEXEC", 83))
    SCMP_ACT_EILSEQ = _scmp_act_errno(getattr(errno, "EILSEQ", 84))
    SCMP_ACT_ERESTART = _scmp_act_errno(getattr(errno, "ERESTART", 85))
    SCMP_ACT_ESTRPIPE = _scmp_act_errno(getattr(errno, "ESTRPIPE", 86))
    SCMP_ACT_EUSERS = _scmp_act_errno(getattr(errno, "EUSERS", 87))
    SCMP_ACT_ENOTSOCK = _scmp_act_errno(getattr(errno, "ENOTSOCK", 88))
    SCMP_ACT_EDESTADDRREQ = _scmp_act_errno(getattr(errno, "EDESTADDRREQ", 89))
    SCMP_ACT_EMSGSIZE = _scmp_act_errno(getattr(errno, "EMSGSIZE", 90))
    SCMP_ACT_EPROTOTYPE = _scmp_act_errno(getattr(errno, "EPROTOTYPE", 91))
    SCMP_ACT_ENOPROTOOPT = _scmp_act_errno(getattr(errno, "ENOPROTOOPT", 92))
    SCMP_ACT_EPROTONOSUPPORT = _scmp_act_errno(getattr(errno, "EPROTONOSUPPORT", 93))
    SCMP_ACT_ESOCKTNOSUPPORT = _scmp_act_errno(getattr(errno, "ESOCKTNOSUPPORT", 94))
    SCMP_ACT_ENOTSUP = _scmp_act_errno(getattr(errno, "ENOTSUP", 95))
    SCMP_ACT_EPFNOSUPPORT = _scmp_act_errno(getattr(errno, "EPFNOSUPPORT", 96))
    SCMP_ACT_EAFNOSUPPORT = _scmp_act_errno(getattr(errno, "EAFNOSUPPORT", 97))
    SCMP_ACT_EADDRINUSE = _scmp_act_errno(getattr(errno, "EADDRINUSE", 98))
    SCMP_ACT_EADDRNOTAVAIL = _scmp_act_errno(getattr(errno, "EADDRNOTAVAIL", 99))
    SCMP_ACT_ENETDOWN = _scmp_act_errno(getattr(errno, "ENETDOWN", 100))
    SCMP_ACT_ENETUNREACH = _scmp_act_errno(getattr(errno, "ENETUNREACH", 101))
    SCMP_ACT_ENETRESET = _scmp_act_errno(getattr(errno, "ENETRESET", 102))
    SCMP_ACT_ECONNABORTED = _scmp_act_errno(getattr(errno, "ECONNABORTED", 103))
    SCMP_ACT_ECONNRESET = _scmp_act_errno(getattr(errno, "ECONNRESET", 104))
    SCMP_ACT_ENOBUFS = _scmp_act_errno(getattr(errno, "ENOBUFS", 105))
    SCMP_ACT_EISCONN = _scmp_act_errno(getattr(errno, "EISCONN", 106))
    SCMP_ACT_ENOTCONN = _scmp_act_errno(getattr(errno, "ENOTCONN", 107))
    SCMP_ACT_ESHUTDOWN = _scmp_act_errno(getattr(errno, "ESHUTDOWN", 108))
    SCMP_ACT_ETOOMANYREFS = _scmp_act_errno(getattr(errno, "ETOOMANYREFS", 109))
    SCMP_ACT_ETIMEDOUT = _scmp_act_errno(getattr(errno, "ETIMEDOUT", 110))
    SCMP_ACT_ECONNREFUSED = _scmp_act_errno(getattr(errno, "ECONNREFUSED", 111))
    SCMP_ACT_EHOSTDOWN = _scmp_act_errno(getattr(errno, "EHOSTDOWN", 112))
    SCMP_ACT_EHOSTUNREACH = _scmp_act_errno(getattr(errno, "EHOSTUNREACH", 113))
    SCMP_ACT_EALREADY = _scmp_act_errno(getattr(errno, "EALREADY", 114))
    SCMP_ACT_EINPROGRESS = _scmp_act_errno(getattr(errno, "EINPROGRESS", 115))
    SCMP_ACT_ESTALE = _scmp_act_errno(getattr(errno, "ESTALE", 116))
    SCMP_ACT_EUCLEAN = _scmp_act_errno(getattr(errno, "EUCLEAN", 117))
    SCMP_ACT_ENOTNAM = _scmp_act_errno(getattr(errno, "ENOTNAM", 118))
    SCMP_ACT_ENAVAIL = _scmp_act_errno(getattr(errno, "ENAVAIL", 119))
    SCMP_ACT_EISNAM = _scmp_act_errno(getattr(errno, "EISNAM", 120))
    SCMP_ACT_EREMOTEIO = _scmp_act_errno(getattr(errno, "EREMOTEIO", 121))
    SCMP_ACT_EDQUOT = _scmp_act_errno(getattr(errno, "EDQUOT", 122))
    SCMP_ACT_ENOMEDIUM = _scmp_act_errno(getattr(errno, "ENOMEDIUM", 123))
    SCMP_ACT_EMEDIUMTYPE = _scmp_act_errno(getattr(errno, "EMEDIUMTYPE", 124))
    SCMP_ACT_ECANCELED = _scmp_act_errno(getattr(errno, "ECANCELED", 125))
    SCMP_ACT_ENOKEY = _scmp_act_errno(getattr(errno, "ENOKEY", 126))
    SCMP_ACT_EKEYEXPIRED = _scmp_act_errno(getattr(errno, "EKEYEXPIRED", 127))
    SCMP_ACT_EKEYREVOKED = _scmp_act_errno(getattr(errno, "EKEYREVOKED", 128))
    SCMP_ACT_EKEYREJECTED = _scmp_act_errno(getattr(errno, "EKEYREJECTED", 129))
    SCMP_ACT_EOWNERDEAD = _scmp_act_errno(getattr(errno, "EOWNERDEAD", 130))
    SCMP_ACT_ENOTRECOVERABLE = _scmp_act_errno(getattr(errno, "ENOTRECOVERABLE", 131))
    SCMP_ACT_ERFKILL = _scmp_act_errno(getattr(errno, "ERFKILL", 132))


class ScmpCmp(ScmpEnum):
    """SCMP_CMP compare operators"""

    SCMP_CMP_NE = 1
    SCMP_CMP_LT = 2
    SCMP_CMP_LE = 3
    SCMP_CMP_EQ = 4
    SCMP_CMP_GE = 5
    SCMP_CMP_GT = 6
    SCMP_CMP_MASKED_EQ = 7


class ScmpNr(ScmpEnum):
    """NR_SCMP / pseudo syscalls"""

    ERROR = -1
    UNDEF = -2


class ELF_EM(enum.IntEnum):
    """linux/elf-em.h"""

    I386 = 3
    MIPS = 8
    PARISC = 15
    PPC = 20
    PPC64 = 21
    S390 = 22
    ARM = 40
    X86_64 = 62
    AARCH64 = 183
    RISCV = 243


class AuditArch(enum.IntEnum):
    """audit.h"""

    CONVENTION_MIPS64_N32 = 0x20000000
    AA_64BIT = 0x80000000
    LE = 0x40000000


class ScmpArch(ScmpEnum):
    """SCMP_ARCH architectures"""

    SCMP_ARCH_NATIVE = 0
    SCMP_ARCH_X86 = ELF_EM.I386 | AuditArch.LE
    SCMP_ARCH_X86_64 = ELF_EM.X86_64 | AuditArch.AA_64BIT | AuditArch.LE
    SCMP_ARCH_X32 = ELF_EM.X86_64 | AuditArch.LE
    SCMP_ARCH_ARM = ELF_EM.ARM | AuditArch.LE
    SCMP_ARCH_AARCH64 = ELF_EM.AARCH64 | AuditArch.AA_64BIT | AuditArch.LE
    SCMP_ARCH_MIPS = ELF_EM.MIPS
    SCMP_ARCH_MIPS64 = ELF_EM.MIPS | AuditArch.AA_64BIT
    SCMP_ARCH_MIPS64N32 = (
        ELF_EM.MIPS | AuditArch.AA_64BIT | AuditArch.CONVENTION_MIPS64_N32
    )
    SCMP_ARCH_MIPSEL = ELF_EM.MIPS | AuditArch.LE
    SCMP_ARCH_MIPSEL64 = ELF_EM.MIPS | AuditArch.AA_64BIT | AuditArch.LE
    SCMP_ARCH_MIPSEL64N32 = (
        ELF_EM.MIPS
        | AuditArch.AA_64BIT
        | AuditArch.LE
        | AuditArch.CONVENTION_MIPS64_N32
    )
    SCMP_ARCH_PARISC = ELF_EM.PARISC
    SCMP_ARCH_PARISC64 = ELF_EM.PARISC | AuditArch.AA_64BIT
    SCMP_ARCH_PPC = ELF_EM.PPC
    SCMP_ARCH_PPC64 = ELF_EM.PPC64 | AuditArch.AA_64BIT
    SCMP_ARCH_PPC64LE = ELF_EM.PPC64 | AuditArch.AA_64BIT | AuditArch.LE
    SCMP_ARCH_S390 = ELF_EM.S390
    SCMP_ARCH_S390X = ELF_EM.S390 | AuditArch.AA_64BIT
    SCMP_ARCH_RISCV64 = ELF_EM.RISCV | AuditArch.AA_64BIT | AuditArch.LE


# seccomp.json include/exclude archs
ARCHES_MAP = {
    # X86
    "x86": ScmpArch.SCMP_ARCH_X86,
    "x86_64": ScmpArch.SCMP_ARCH_X86_64,
    "amd64": ScmpArch.SCMP_ARCH_X86_64,
    "x32": ScmpArch.SCMP_ARCH_X32,
    # ARM
    "arm": ScmpArch.SCMP_ARCH_ARM,
    "arm64": ScmpArch.SCMP_ARCH_AARCH64,
    # MIPS BE
    "mips": ScmpArch.SCMP_ARCH_MIPS,
    "mips64": ScmpArch.SCMP_ARCH_MIPS64,
    "mips64n32": ScmpArch.SCMP_ARCH_MIPS64N32,
    # MIPSel (LE)
    "mipsel": ScmpArch.SCMP_ARCH_MIPSEL,
    "mipsel64": ScmpArch.SCMP_ARCH_MIPSEL64,
    "mipsel64n32": ScmpArch.SCMP_ARCH_MIPSEL64N32,
    # alt spellings (?)
    "mips64p32": ScmpArch.SCMP_ARCH_MIPS64N32,
    "mips64le": ScmpArch.SCMP_ARCH_MIPSEL64,
    "mips64p32le": ScmpArch.SCMP_ARCH_MIPSEL64N32,
    "mipsle": ScmpArch.SCMP_ARCH_MIPSEL,
    # PPC
    "ppc": ScmpArch.SCMP_ARCH_PPC,
    "ppc64": ScmpArch.SCMP_ARCH_PPC64,
    "ppc64le": ScmpArch.SCMP_ARCH_PPC64LE,
    # IBM/Z
    "s390": ScmpArch.SCMP_ARCH_S390,
    "s390x": ScmpArch.SCMP_ARCH_S390X,
}


class Capabilities(ScmpEnum):
    """linux/capability.h"""

    CAP_CHOWN = 0
    CAP_DAC_OVERRIDE = 1
    CAP_DAC_READ_SEARCH = 2
    CAP_FOWNER = 3
    CAP_FSETID = 4
    CAP_KILL = 5
    CAP_SETGID = 6
    CAP_SETUID = 7
    CAP_SETPCAP = 8
    CAP_LINUX_IMMUTABLE = 9
    CAP_NET_BIND_SERVICE = 10
    CAP_NET_BROADCAST = 11
    CAP_NET_ADMIN = 12
    CAP_NET_RAW = 13
    CAP_IPC_LOCK = 14
    CAP_IPC_OWNER = 15
    CAP_SYS_MODULE = 16
    CAP_SYS_RAWIO = 17
    CAP_SYS_CHROOT = 18
    CAP_SYS_PTRACE = 19
    CAP_SYS_PACCT = 20
    CAP_SYS_ADMIN = 21
    CAP_SYS_BOOT = 22
    CAP_SYS_NICE = 23
    CAP_SYS_RESOURCE = 24
    CAP_SYS_TIME = 25
    CAP_SYS_TTY_CONFIG = 26
    CAP_MKNOD = 27
    CAP_LEASE = 28
    CAP_AUDIT_WRITE = 29
    CAP_AUDIT_CONTROL = 30
    CAP_SETFCAP = 31
    CAP_MAC_OVERRIDE = 32
    CAP_MAC_ADMIN = 33
    CAP_SYSLOG = 34
    CAP_WAKE_ALARM = 35
    CAP_BLOCK_SUSPEND = 36
    CAP_AUDIT_READ = 37
    CAP_PERFMON = 38
    CAP_BPF = 39
    CAP_CHECKPOINT_RESTORE = 40


class CapFlag(enum.IntEnum):
    """cap_flag_t sys/capability.h"""

    EFFECTIVE = 0
    PERMITTED = 1
    INHERITABLE = 2


class CapMode(enum.IntEnum):
    """cap_mode_t sys/capability.h"""

    UNCERTAIN = 0
    NOPRIV = 1
    PURE1E_INIT = 2
    PURE1E = 3


def translate_scmp(s):
    """Translate a string to enum member"""
    if s.startswith("SCMP_ACT_"):
        return getattr(ScmpAction, s)
    elif s.startswith("SCMP_CMP_"):
        return getattr(ScmpCmp, s)
    elif s.startswith("SCMP_ARCH_"):
        return getattr(ScmpArch, s)
    elif s.startswith("CAP_"):
        return getattr(Capabilities, s)
    elif s in ARCHES_MAP:
        return ARCHES_MAP[s]
    else:
        raise ValueError(s)
