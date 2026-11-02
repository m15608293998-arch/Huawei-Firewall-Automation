from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import multiprocessing
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from api import storage as storage_module
from api.storage import JobStorage


def initialize_in_process(directory, index, barrier, results):
    errors = []
    for iteration in range(12):
        barrier.wait(timeout=15)
        try:
            store = JobStorage(Path(directory) / (str(iteration) + ".sqlite3"))
            store.grant_subject_permission(str(index), "firewall.job.read", "now")
        except Exception as exc:
            errors.append((iteration, type(exc).__name__, str(exc)))
        barrier.wait(timeout=15)
    results.put(errors)


class StorageInitializationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "jobs.sqlite3"

    def test_overlapping_wal_switch_cannot_fail_another_initializer(self):
        entered, release, overlap = threading.Event(), threading.Event(), threading.Event()
        second_started = threading.Event()
        active = threading.Lock()
        original_connect = JobStorage._connect

        class Connection:
            def __init__(self, connection):
                self.connection = connection

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def execute(self, sql, *args):
                if sql.lower() != "pragma journal_mode = wal":
                    return self.connection.execute(sql, *args)
                if not active.acquire(blocking=False):
                    overlap.set()
                    raise storage_module.sqlite3.OperationalError("database is locked")
                try:
                    entered.set()
                    if not release.wait(3):
                        raise AssertionError("WAL switch fixture was not released")
                    return self.connection.execute(sql, *args)
                finally:
                    active.release()

        @contextmanager
        def connect(store, *args, **kwargs):
            with original_connect(store, *args, **kwargs) as connection:
                yield Connection(connection)

        def second():
            second_started.set()
            return JobStorage(self.path)

        with patch.object(JobStorage, "_connect", connect), ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(JobStorage, self.path)
            try:
                self.assertTrue(entered.wait(2))
                follower = pool.submit(second)
                self.assertTrue(second_started.wait(2))
                # Model the observed SQLITE_BUSY when two fresh connections switch
                # journals together; allow the follower to reach that window.
                overlap.wait(0.2)
            finally:
                release.set()
            for future in (first, follower):
                store = future.result(timeout=5)
                with store._connect() as connection:
                    columns = {row["name"] for row in connection.execute("pragma table_info(jobs)")}
                self.assertTrue({"deadline_at", "request_fingerprint"}.issubset(columns))

    def test_simultaneous_process_bootstrap_preserves_schema_and_writes(self):
        context = multiprocessing.get_context("spawn")
        barrier, results = context.Barrier(4), context.Queue()
        processes = [context.Process(target=initialize_in_process,
                                     args=(self.temp.name, index, barrier, results)) for index in range(4)]
        try:
            for process in processes:
                process.start()
            for _ in processes:
                self.assertEqual(results.get(timeout=30), [])
            for process in processes:
                process.join(timeout=5)
                self.assertEqual(process.exitcode, 0)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
            results.close()
            results.join_thread()
        for iteration in range(12):
            store = JobStorage(Path(self.temp.name) / (str(iteration) + ".sqlite3"))
            self.assertEqual(len(store.list_subject_permissions()), 4)
            with store._connect() as connection:
                self.assertEqual(connection.execute("pragma journal_mode").fetchone()[0], "wal")

    def test_initialization_failure_does_not_block_a_later_startup(self):
        with patch.object(JobStorage, "_ensure_column", side_effect=RuntimeError("injected schema failure")):
            with self.assertRaisesRegex(RuntimeError, "injected schema failure"):
                JobStorage(self.path)
        store = JobStorage(self.path)
        self.assertEqual(store.list_jobs(), [])
        store.grant_subject_permission("subject", "firewall.job.read", "now")
        self.assertEqual(store.get_subject_permissions("subject"), ["firewall.job.read"])


if __name__ == "__main__":
    unittest.main()
