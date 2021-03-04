from ._constants import ScmpArch

__all__ = ("SUB_ARCHITECTURES",)

# https://src.fedoraproject.org/rpms/containers-common/blob/f34/f/seccomp.json
SUB_ARCHITECTURES = {
    ScmpArch.SCMP_ARCH_X86: [ScmpArch.SCMP_ARCH_X86_64, ScmpArch.SCMP_ARCH_X32],
    ScmpArch.SCMP_ARCH_X86_64: [ScmpArch.SCMP_ARCH_X86, ScmpArch.SCMP_ARCH_X32],
    ScmpArch.SCMP_ARCH_X32: [ScmpArch.SCMP_ARCH_X86_64, ScmpArch.SCMP_ARCH_X86],
    ScmpArch.SCMP_ARCH_AARCH64: [ScmpArch.SCMP_ARCH_ARM],
    ScmpArch.SCMP_ARCH_MIPS64: [ScmpArch.SCMP_ARCH_MIPS, ScmpArch.SCMP_ARCH_MIPS64N32],
    ScmpArch.SCMP_ARCH_MIPS64N32: [ScmpArch.SCMP_ARCH_MIPS, ScmpArch.SCMP_ARCH_MIPS64],
    ScmpArch.SCMP_ARCH_MIPSEL64: [
        ScmpArch.SCMP_ARCH_MIPSEL,
        ScmpArch.SCMP_ARCH_MIPSEL64N32,
    ],
    ScmpArch.SCMP_ARCH_MIPSEL64N32: [
        ScmpArch.SCMP_ARCH_MIPSEL,
        ScmpArch.SCMP_ARCH_MIPSEL64,
    ],
    ScmpArch.SCMP_ARCH_S390X: [ScmpArch.SCMP_ARCH_S390],
}
