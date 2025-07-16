import sys
from typing import Any, Callable, Optional


# https://stackoverflow.com/a/9741784
class ExitHooks:
    def __init__(self):
        self.exit_code: Optional[int] = None
        self.exception: Optional[Exception] = None
        self._orig_exit: Optional[Callable[[int], None]] = None

    def hook(self):
        """Install the exit and exception hooks."""
        self._orig_exit = sys.exit
        sys.exit = self.exit
        sys.excepthook = self.exc_handler

    def exit(self, code: int = 0):
        """Custom exit handler that captures the exit code."""
        self.exit_code = code
        if self._orig_exit is not None:
            self._orig_exit(code)

    def exc_handler(self, exc_type: type, exc: Exception, *args: Any):
        """Custom exception handler that captures exceptions."""
        self.exception = exc


_HOOKS = ExitHooks()
_HOOKS.hook()


def get_exit_code() -> Optional[int]:
    """Get the exit code from the last program exit."""
    return _HOOKS.exit_code


def get_exception() -> Optional[Exception]:
    """Get the exception from the last unhandled exception."""
    return _HOOKS.exception


def has_exited_gracefully() -> bool:
    """
    Returns True if the program exited gracefully (without an exception).
    """
    if _HOOKS.exit_code is not None and _HOOKS.exit_code != 0:
        return False
    return _HOOKS.exception is None
