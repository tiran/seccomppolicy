import json
import pprint

from ._constants import translate_scmp
from ._seccomp import ScmpArg, Syscall


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
            ScmpArg(
                arg["index"], translate_scmp(arg["op"]), arg["value"], arg["valueTwo"]
            )
            for arg in syscall.get("args") or ()
        ]
        names = [Syscall(name) for name in syscall.get("names") or ()]
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

    pprint.pprint(config)


if __name__ == "__main__":
    load_file("/usr/share/containers/seccomp.json")
