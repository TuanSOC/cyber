"""seccomp filter for tool processes: no network sockets.

Tools read a capture file and write logs; they never need the network. A parser exploit
therefore cannot reach the broker (password guessing) or MinIO from the tool uid. Loaded in
the child after it dropped privileges (libseccomp sets no_new_privs itself).
"""

import ctypes
import ctypes.util
import errno
import socket

SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO_BASE = 0x00050000
SCMP_CMP_EQ = 4
DENIED_DOMAINS = (socket.AF_INET, socket.AF_INET6, socket.AF_PACKET)


class _ArgCmp(ctypes.Structure):
    _fields_ = (
        ("arg", ctypes.c_uint),
        ("op", ctypes.c_int),
        ("datum_a", ctypes.c_uint64),
        ("datum_b", ctypes.c_uint64),
    )


def _library() -> ctypes.CDLL:
    name = ctypes.util.find_library("seccomp") or "libseccomp.so.2"
    lib = ctypes.CDLL(name, use_errno=True)
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = (ctypes.c_uint32,)
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
    lib.seccomp_rule_add_array.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = (
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(_ArgCmp),
    )
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_load.argtypes = (ctypes.c_void_p,)
    lib.seccomp_release.argtypes = (ctypes.c_void_p,)
    return lib


# Resolved in the parent so the child does as little as possible between fork and exec.
_LIB = _library()
_SOCKET = _LIB.seccomp_syscall_resolve_name(b"socket")


def deny_network() -> None:
    """Install the filter in the current process (call from preexec_fn). Raises on failure."""
    ctx = _LIB.seccomp_init(SCMP_ACT_ALLOW)
    if not ctx:
        raise OSError("seccomp_init failed")
    try:
        action = SCMP_ACT_ERRNO_BASE | errno.EACCES
        for domain in DENIED_DOMAINS:
            cmp = _ArgCmp(arg=0, op=SCMP_CMP_EQ, datum_a=int(domain), datum_b=0)
            if _LIB.seccomp_rule_add_array(ctx, action, _SOCKET, 1, ctypes.byref(cmp)) != 0:
                raise OSError("seccomp_rule_add failed")
        if _LIB.seccomp_load(ctx) != 0:
            raise OSError("seccomp_load failed")
    finally:
        _LIB.seccomp_release(ctx)
