import functools
import tempfile

from . import _libseccomp as _lsc
from ._libseccomp import ScmpArg
from ._constants import ScmpArch

__all__ = (
    "ScmpArg",
    "Syscall",
    "Seccomp",
    "NATIVE_ARCH",
)

# current CPU arch
NATIVE_ARCH = _lsc.seccomp_arch_native()


class Seccomp:
    __slots__ = ("_default_action", "_ctx")

    def __init__(self, default_action):
        self._default_action = default_action
        self._ctx = None

    def __enter__(self):
        if self._ctx is not None:
            raise RuntimeError
        self._ctx = _lsc.seccomp_init(self._default_action)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sc = self._ctx
        self._ctx = None
        _lsc.seccomp_release(sc)

    def add_arch(self, arch):
        _lsc.seccomp_arch_add(self._ctx, arch)

    def _add_rule(self, action, syscall, args, func):
        if not isinstance(syscall, Syscall):
            syscall = Syscall(syscall)
        arg_array = ScmpArg.toarray(*args)
        try:
            return func(self._ctx, action, int(syscall), len(arg_array), arg_array)
        except OSError as e:
            raise OSError(e.errno, func.__name__, (action, syscall, args))

    def add_rule(self, action, syscall, *args):
        self._add_rule(action, syscall, args, _lsc.seccomp_rule_add_array)

    def add_rule_exact(self, action, syscall, *args):
        self._add_rule(action, syscall, args, _lsc.seccomp_rule_add_exact_array)

    def _export(self, func):
        with tempfile.TemporaryFile() as f:
            func(self._ctx, f.fileno())
            f.seek(0)
            return f.read()

    def export_pfc(self):
        return self._export(_lsc.seccomp_export_pfc).decode("utf-8")

    def load(self):
        _lsc.seccomp_load(self._ctx)


@functools.total_ordering
class Syscall:
    __slots__ = ("_name", "_nr", "_arch")

    def __init__(self, name_or_nr, arch_token=ScmpArch.SCMP_ARCH_NATIVE):
        self._arch = arch_token
        if isinstance(name_or_nr, str):
            self._name = name_or_nr
            self._nr = _lsc.seccomp_syscall_resolve_name_arch(
                self._arch, name_or_nr.encode("ascii")
            )
        elif isinstance(name_or_nr, int):
            self._name = _lsc.seccomp_syscall_resolve_num_arch(arch_token, name_or_nr)
            self._nr = name_or_nr
        else:
            raise TypeError(name_or_nr)

    def __eq__(self, other):
        if not isinstance(other, Syscall):
            return NotImplemented
        return (
            self.name == other.name and self.nr == other.nr and self.arch == other.arch
        )

    def __lt__(self, other):
        if not isinstance(other, Syscall):
            return NotImplemented
        return self.nr < other.nr

    def __hash__(self):
        return hash((self.name, self.nr, int(self.arch)))

    def __repr__(self):
        return "<{self.__class__.__name__} {self.name}({self.nr})>".format(self=self)

    def __str__(self):
        return self.name

    def __int__(self):
        return self.nr

    @property
    def name(self):
        return self._name

    @property
    def nr(self):
        return self._nr

    @property
    def arch(self):
        return self._arch
