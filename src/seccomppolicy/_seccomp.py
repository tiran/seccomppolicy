import functools

from . import _libseccomp as _lsc
from ._libseccomp import ScmpArg
from ._constants import ScmpArch

__all__ = ("ScmpArg", "Syscall")


@functools.total_ordering
class Syscall:
    __slots__ = ("_name", "_nr", "_arch")

    def __init__(self, name_or_nr, arch_token=ScmpArch.SCMP_ARCH_NATIVE):
        self._arch = arch_token
        if isinstance(name_or_nr, str):
            self._name = name_or_nr
            self._nr = None
        elif isinstance(name_or_nr, int):
            self._name = _lsc.seccomp_syscall_resolve_num_arch(arch_token, name_or_nr)
            self._nr = name_or_nr
        else:
            raise TypeError(name_or_nr)

    def __eq__(self, other):
        if not isinstance(other, Syscall):
            return NotImplemented
        return self.name == other.name and self.arch == other.arch

    def __lt__(self, other):
        if not isinstance(other, Syscall):
            return NotImplemented
        return self.nr < other.nr

    def __hash__(self):
        return hash((self.name, int(self.arch)))

    def __repr__(self):
        return "<{self.__class__.__name__} {self.name}({self.nr})>".format(self=self)

    @property
    def name(self):
        return self._name

    @property
    def nr(self):
        if self._nr is None:
            self._nr = _lsc.seccomp_syscall_resolve_name_arch(
                self._arch, self._name.encode("ascii")
            )
        return self._nr

    @property
    def arch(self):
        return self._arch
