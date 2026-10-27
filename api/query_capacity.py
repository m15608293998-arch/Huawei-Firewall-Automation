import asyncio
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable

from api.config import settings


class QueryBusyError(RuntimeError):
    pass


@dataclass
class _Query:
    key: tuple
    future: Future
    wrapped: asyncio.Future
    callers: int = 1


class DeviceQueryCoordinator:
    """One device query per API process, with bounded asynchronous followers."""

    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="firewall-query")
        self._lock = threading.Lock()
        self._active: _Query | None = None
        self.closed = False

    async def run(self, key: tuple, operation: Callable[[], Any]) -> Any:
        with self._lock:
            if self.closed:
                raise QueryBusyError("Firewall query service is shutting down.")
            group = self._active
            follower = group is not None and not group.future.done()
            if follower:
                if group.key != key or group.callers >= settings.query_max_waiters + 1:
                    raise QueryBusyError("Firewall query capacity is full; retry later.")
                group.callers += 1
            else:
                future = self._executor.submit(operation)
                wrapped = asyncio.wrap_future(future)
                # All callers share one bridge; canceled or timed-out requests
                # must not leave additional callbacks on the running Future.
                wrapped.add_done_callback(lambda done: None if done.cancelled() else done.exception())
                group = _Query(key, future, wrapped)
                self._active = group

        wrapped = group.wrapped
        try:
            if follower:
                try:
                    return await asyncio.wait_for(asyncio.shield(wrapped), settings.query_wait_timeout_seconds)
                except TimeoutError as exc:
                    raise QueryBusyError("Timed out waiting for the shared firewall query; retry later.") from exc
            # Shield the actual execution: cancellation cannot free its slot
            # while a Runner still holds locks or reads the devices.
            return await asyncio.shield(wrapped)
        finally:
            with self._lock:
                group.callers -= 1

    def close(self):
        with self._lock:
            self.closed = True
        self._executor.shutdown(wait=False, cancel_futures=True)
