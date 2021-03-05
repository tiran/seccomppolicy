import json
import os

from packaging.version import parse as parse_version

from ._constants import translate_scmp
from . import _seccomp
from . import _libcap


# TODO clean up and simplify code
class _Condition:
    _current_kernel = parse_version(os.uname().release.split("-", 1)[0])
    _native_arch = _seccomp.NATIVE_ARCH

    def __init__(self, *, arches=None, caps=None, minKernel=None):
        if arches:
            self.arches = frozenset(arches)
        else:
            self.arches = None
        self.caps = caps
        if minKernel:
            self.min_kernel = parse_version(self.min_kernel)
        else:
            self.min_kernel = None

    def _check_arches(self):
        if not self.arches:
            # no arches: applies to all arches
            return None
        else:
            return self._native_arch in self.arches

    def _check_caps(self):
        if not self.caps:
            # no capability restriction
            return None
        return any(_libcap.has_cap(cap) for cap in self.caps)

    def _check_kernel(self):
        if not self.min_kernel:
            # no Kernel version restriction
            return None
        else:
            # current Kernel version must be equal or greater than min version
            return self._current_kernel >= self.min_kernel


class IncludeCondition(_Condition):
    def __bool__(self):
        if self._check_arches() is False:
            return False
        if self._check_caps() is False:
            return False
        if self._check_kernel() is False:
            return False
        return True


class ExcludeCondition(_Condition):
    def __bool__(self):
        if self._check_arches() is False:
            return True
        if self._check_caps() is False:
            return True
        if self._check_kernel() is False:
            return True
        return False


def load_file(fname):
    with open(fname) as f:
        root = json.load(f)
    return _parse(root)


def _incl_excl(obj):
    if obj is None:
        return {}
    result = {}
    caps = obj.get("caps")
    if caps:
        result["caps"] = [translate_scmp(cap) for cap in caps]
    arches = obj.get("arches")
    if arches:
        result["arches"] = [translate_scmp(arch) for arch in arches]
    mk = obj.get("minKernel")
    if mk:
        result["minKernel"] = mk
    return result


def _parse(root):
    config = dict(
        default_action=translate_scmp(root["defaultAction"]),
        archmap={},
        syscalls=[],
    )

    for archmap in root.get("archMap", ()):
        arch = translate_scmp(archmap["architecture"])
        config["archmap"][arch] = [
            translate_scmp(sa) for sa in archmap["subArchitectures"]
        ]

    for syscall in root["syscalls"]:
        action = translate_scmp(syscall["action"])
        comment = syscall["comment"]
        args = [
            _seccomp.ScmpArg(
                arg["index"], translate_scmp(arg["op"]), arg["value"], arg["valueTwo"]
            )
            for arg in syscall.get("args") or ()
        ]
        names = [_seccomp.Syscall(name) for name in syscall.get("names") or ()]
        includes = _incl_excl(syscall.get("includes"))
        excludes = _incl_excl(syscall.get("excludes"))

        config["syscalls"].append(
            dict(
                action=action,
                args=args,
                comment=comment,
                names=names,
                includes=includes,
                excludes=excludes,
            )
        )

    return config


if __name__ == "__main__":
    import pprint

    pprint.pprint(load_file("/usr/share/containers/seccomp.json"))
