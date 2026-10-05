"""Ask the operating system which path an open file descriptor names.

A check that runs on a path and an open that runs on the same path are two
look-ups; a directory swapped for a link between them makes the open read a
file the checks never saw. The path the kernel reports for the descriptor is
the file actually opened, so judging that path closes the window.
"""

from __future__ import annotations

import os
import pathlib
import sys

__all__ = ["descriptor_path"]

# Longest path GetFinalPathNameByHandleW can return (the extended-length limit).
_WINDOWS_MAX_PATH = 32_768


def descriptor_path(descriptor: int) -> str | None:
    """Return the path the kernel holds for an open descriptor, or None when it cannot say.

    Linux reads ``/proc/self/fd``, macOS asks ``fcntl(F_GETPATH)`` and Windows
    ``GetFinalPathNameByHandleW``. Another system, or a Linux without ``/proc``,
    returns None and the caller keeps its other checks.

    Args:
        descriptor: An open file descriptor.

    Returns:
        The path as the kernel reports it, or None.

    Examples:
        >>> import tempfile
        >>> with tempfile.NamedTemporaryFile() as handle:
        ...     found = descriptor_path(handle.fileno())
        ...     found is None or os.path.normcase(found) == os.path.normcase(os.path.realpath(handle.name))
        True
    """
    try:
        return _lookup(descriptor)
    except OSError:
        return None


if sys.platform == "win32":
    import ctypes
    import msvcrt

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _get_final_path = _kernel32.GetFinalPathNameByHandleW
    # HANDLE, LPWSTR, DWORD cchFilePath, DWORD dwFlags -> DWORD; fixed-width types,
    # because ctypes.wintypes follows the interpreter's machine, not Windows.
    _get_final_path.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32)
    _get_final_path.restype = ctypes.c_uint32

    def _lookup(descriptor: int) -> str | None:
        buffer = ctypes.create_unicode_buffer(_WINDOWS_MAX_PATH)
        length = _get_final_path(msvcrt.get_osfhandle(descriptor), buffer, _WINDOWS_MAX_PATH, 0)
        if not 0 < length < _WINDOWS_MAX_PATH:
            return None
        return _strip_extended_prefix(buffer.value)

    def _strip_extended_prefix(path: str) -> str:
        # The handle's path carries the extended-length prefix that os.path.realpath drops.
        if path.startswith("\\\\?\\UNC\\"):
            return "\\\\" + path[len("\\\\?\\UNC\\") :]
        if path.startswith("\\\\?\\"):
            return path[len("\\\\?\\") :]
        return path

elif sys.platform == "darwin":
    import fcntl

    def _lookup(descriptor: int) -> str | None:
        reply = fcntl.fcntl(descriptor, fcntl.F_GETPATH, bytes(os.pathconf("/", "PC_PATH_MAX")))
        return os.fsdecode(reply.split(b"\x00", 1)[0]) or None

else:

    def _lookup(descriptor: int) -> str | None:
        found = str(pathlib.Path(f"/proc/self/fd/{descriptor}").readlink())
        # A file unlinked since the open reads "<path> (deleted)"; that path is still the
        # one to judge. A pipe or socket reads "pipe:[...]" and names no path at all.
        found = found.removesuffix(" (deleted)")
        return found if found.startswith("/") else None
