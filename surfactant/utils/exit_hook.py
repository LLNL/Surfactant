import sys


# https://stackoverflow.com/a/9741784
class ExitHooks:
    def __init__(self):
        self.exit_code = None
        self.exception = None

    def hook(self):
        self._orig_exit = sys.exit
        sys.exit = self.exit
        sys.excepthook = self.exc_handler

    def exit(self, code=0):
        self.exit_code = code
        self._orig_exit(code)

    def exc_handler(self, exc_type, exc, *args):
        self.exception = exc


_HOOKS = ExitHooks()
_HOOKS.hook()


def get_exit_code():
    return _HOOKS.exit_code


def get_exception():
    return _HOOKS.exception


def has_exited_gracefully():
    """
    Returns True if the program exited gracefully (without an exception).
    """
    if _HOOKS.exit_code is not None and _HOOKS.exit_code != 0:
        return False
    return _HOOKS.exception is None
