from __future__ import annotations

import ctypes
import os
import platform
import threading


_console_handlers = []
_console_handlers_lock = threading.Lock()


def is_windows() -> bool:
    return os.name == "nt" and platform.system().lower() == "windows"


def is_admin() -> bool:
    if not is_windows():
        return False

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def register_console_close_handler(callback):
    """Run callback when the Windows console is closed/logged off/shut down.

    Ctrl+C remains handled by Python as KeyboardInterrupt. The returned function
    unregisters the native handler. A module-level reference keeps the ctypes
    callback alive for the lifetime of the process.
    """
    if not is_windows():
        return lambda: None

    handler_type = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_uint)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    set_handler = kernel32.SetConsoleCtrlHandler
    set_handler.argtypes = (handler_type, ctypes.c_bool)
    set_handler.restype = ctypes.c_bool

    close_events = {2, 5, 6}  # CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT

    @handler_type
    def native_handler(ctrl_type):
        if int(ctrl_type) not in close_events:
            return False
        try:
            callback(int(ctrl_type))
        except BaseException:
            # The console is already closing; cleanup is best-effort and must
            # never crash the native control-handler thread.
            pass
        return True

    if not set_handler(native_handler, True):
        code = ctypes.get_last_error()
        raise OSError(code, "SetConsoleCtrlHandler failed")

    with _console_handlers_lock:
        _console_handlers.append(native_handler)

    def unregister():
        try:
            set_handler(native_handler, False)
        finally:
            with _console_handlers_lock:
                if native_handler in _console_handlers:
                    _console_handlers.remove(native_handler)

    return unregister
