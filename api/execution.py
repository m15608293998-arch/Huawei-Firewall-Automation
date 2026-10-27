import fcntl
import time
from contextlib import contextmanager
from pathlib import Path


class ExecutionTimeout(TimeoutError):
    pass


@contextmanager
def exclusive_file_lock(path: Path, timeout_seconds: float):
    deadline = time.monotonic() + timeout_seconds
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ExecutionTimeout("Timed out waiting for {0}.".format(path.name))
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(min(0.05, remaining))
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
