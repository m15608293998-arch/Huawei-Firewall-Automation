from concurrent.futures import ThreadPoolExecutor
import multiprocessing
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from api.admin_users import AdminUserService, ManagedUserBusyError
from api.execution import ExecutionTimeout
from fastapi import HTTPException
from api.schemas import ManagedUserUpdate
from api.storage import JobStorage


class FileKeycloak:
    def __init__(self, directory):
        self.directory = Path(directory)

    def get_user(self, subject):
        return {'id': subject, 'username': subject}

    def set_user_profile(self, subject, profile):
        (self.directory / ('role-' + subject)).write_text(profile or 'none')


def process_update(directory, profile, started, saved, release, completed, errors):
    try:
        store = JobStorage(Path(directory) / 'users.sqlite3')
        service = AdminUserService(store, FileKeycloak(directory))
        original = store.save_managed_user_access
        def save(**kwargs):
            if saved is not None:
                saved.set()
                if not release.wait(8):
                    raise RuntimeError('Test release timed out')
            return original(**kwargs)
        with patch.object(store, 'save_managed_user_access', side_effect=save):
            started.set()
            service.update('employee', ManagedUserUpdate(username='employee', profile=profile))
        completed.set()
    except BaseException as exc:
        errors.put(repr(exc))


class AdminProfileConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.storage = JobStorage(self.root/'users.sqlite3')
        self.kc = FileKeycloak(self.root)
        self.service = AdminUserService(self.storage, self.kc)
        self.service.update('employee', ManagedUserUpdate(username='employee', profile='user'))

    def test_same_user_updates_are_serialized_across_processes(self):
        ctx = multiprocessing.get_context('spawn')
        entered, release, first_started, second_started = [ctx.Event() for _ in range(4)]
        first_done, second_done, errors = ctx.Event(), ctx.Event(), ctx.Queue()
        first = ctx.Process(target=process_update, args=(str(self.root), 'admin', first_started, entered, release, first_done, errors))
        second = ctx.Process(target=process_update, args=(str(self.root), 'user', second_started, None, release, second_done, errors))
        first.start()
        blocked = False
        try:
            self.assertTrue(entered.wait(8))
            second.start()
            self.assertTrue(second_started.wait(8))
            blocked = not second_done.wait(0.4)
        finally:
            release.set()
            for process in (first, second):
                if process.pid is not None:
                    process.join(10)
                    if process.is_alive():
                        process.kill(); process.join()
        self.assertEqual(first.exitcode, 0)
        self.assertEqual(second.exitcode, 0)
        self.assertTrue(first_done.is_set(), 'First update failed')
        self.assertTrue(second_done.is_set(), 'Second update failed')
        self.assertTrue(blocked, 'Second process must wait until KC and DB are saved together')
        self.assertEqual((self.root/'role-employee').read_text(), 'user')
        self.assertEqual(self.storage.get_managed_user('employee')['profile'], 'user')

    def test_failed_save_compensates_before_waiting_update_runs(self):
        entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
        other = AdminUserService(JobStorage(self.storage.database_path), self.kc)
        def fail(**kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('Test release timed out')
            raise RuntimeError('Injected database write failure')
        def later():
            second_started.set()
            return other.update('employee', ManagedUserUpdate(username='employee', profile='admin'))
        with patch.object(self.storage, 'save_managed_user_access', side_effect=fail):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(self.service.update, 'employee', ManagedUserUpdate(username='employee', profile='admin'))
                try:
                    self.assertTrue(entered.wait(3))
                    second = pool.submit(later)
                    self.assertTrue(second_started.wait(3))
                    # A different subject can still complete while employee is locked.
                    other.update('different', ManagedUserUpdate(username='different', profile='user'))
                finally:
                    release.set()
                with self.assertRaisesRegex(RuntimeError, 'Injected'):
                    first.result(timeout=5)
                second.result(timeout=5)
        self.assertEqual((self.root/'role-employee').read_text(), 'admin')
        self.assertEqual(self.storage.get_managed_user('employee')['profile'], 'admin')


    def test_lock_timeout_returns_retryable_response_without_role_mutation(self):
        import api.main as api_main
        with patch('api.admin_users.exclusive_file_lock', side_effect=ExecutionTimeout('busy')), \
                patch.object(self.kc, 'set_user_profile') as update_role:
            with self.assertRaises(ManagedUserBusyError) as caught:
                self.service.update('employee', ManagedUserUpdate(username='employee', profile='admin'))
            update_role.assert_not_called()
        with patch.object(api_main.admin_user_service, 'update', side_effect=caught.exception):
            with self.assertRaises(HTTPException) as response:
                api_main.update_managed_user('employee', ManagedUserUpdate(username='employee', profile='admin'), None)
        self.assertEqual(response.exception.status_code, 503)
        self.assertEqual(response.exception.headers['Retry-After'], '1')
        self.assertEqual(self.storage.get_managed_user('employee')['profile'], 'user')


if __name__ == '__main__':
    unittest.main()
