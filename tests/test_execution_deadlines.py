import fcntl
import importlib.util
import json
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import yaml

from api.config import settings
from api.execution import ExecutionTimeout, exclusive_file_lock
from api.runner_service import AnsibleRunnerService


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("deadline_cli", ROOT / "roles/usg6000e_trade_access/files/run_usg_cli.py")
CLI = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CLI)


class ExecutionDeadlineTests(unittest.TestCase):
    def test_contended_lock_times_out_and_can_be_acquired_after_release(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            with path.open("a") as held:
                fcntl.flock(held.fileno(), fcntl.LOCK_EX)
                started = time.monotonic()
                with self.assertRaises(ExecutionTimeout):
                    with exclusive_file_lock(path, 0.03):
                        self.fail("Contended lock must not be acquired")
                self.assertLess(time.monotonic() - started, 0.5)
            with exclusive_file_lock(path, 0.1):
                pass

    def test_snapshot_returns_bounded_busy_result_without_querying_device(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(settings, "database_path", Path(directory) / "jobs.sqlite3"), \
                patch.object(settings, "runner_lock_timeout_seconds", 0.03):
            lock = Path(directory) / "firewall_parent.lock"
            with lock.open("a") as held:
                fcntl.flock(held.fileno(), fcntl.LOCK_EX)
                service = AnsibleRunnerService()
                service.run_firewall_snapshot = Mock()
                result = service.run_reconciled_snapshot("ips")
                self.assertEqual(result.status, "timeout")
                service.run_firewall_snapshot.assert_not_called()

    def test_continuous_pagination_cannot_reset_total_deadline(self):
        child = SimpleNamespace(execution_deadline=1, before="", after="---- More ----", expect=Mock(return_value=1), send=Mock())
        with patch.object(CLI.time, "monotonic", side_effect=[0, 0.2, 0.4, 0.7, 1.1]), patch.object(CLI.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "deadline exceeded"):
                CLI.expect_prompt_or_more(child, 60)
        self.assertEqual(child.expect.call_count, 1)

    def test_no_command_is_sent_after_deadline(self):
        child = SimpleNamespace(execution_deadline=1, send=Mock())
        with patch.object(CLI.time, "monotonic", return_value=2):
            with self.assertRaisesRegex(RuntimeError, "deadline exceeded"):
                CLI.run_command_with_busy_retry(child, "save", 180)
        child.send.assert_not_called()

    def test_subsecond_runner_budget_is_not_truncated_to_disabled_timeout(self):
        options = AnsibleRunnerService._runner_options(time.monotonic() + 0.1)
        self.assertGreater(options["settings"]["job_timeout"], 0)
        self.assertLess(options["settings"]["job_timeout"], 0.2)
        self.assertIn("USG6000E_RUN_DEADLINE", options["envvars"])

    def test_real_runner_timeout_terminates_local_process_group_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pids = root / "pids.json"
            fixture = root / "slow.py"
            fixture.write_text(
                "import json,os,subprocess,sys,time\nfrom pathlib import Path\n"
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)'])\n"
                "Path({0!r}).write_text(json.dumps([os.getpid(),child.pid]))\n"
                "time.sleep(120)\n".format(str(pids))
            )
            (root / "ansible.cfg").write_text("[defaults]\ninventory = " + str(root / "inventory") + "\n")
            (root / "inventory").write_text("localhost ansible_connection=local\n")
            playbook = root / "timeout.yml"
            playbook.write_text(yaml.safe_dump([{
                "hosts": "localhost", "connection": "local", "gather_facts": False,
                "tasks": [{"ansible.builtin.command": {"argv": [sys.executable, str(fixture)]}}],
            }]))
            with patch.object(settings, "project_root", root), \
                    patch.object(settings, "playbook_path", "timeout.yml"), \
                    patch.object(settings, "runner_private_data_dir", root / "runner"):
                service = AnsibleRunnerService()
                started = time.monotonic()
                try:
                    result = service.run_trade_access({
                        "job_id": "timeout-fixture", "action": "deny", "target_ip": "203.0.113.10",
                        "mask": 32, "ports": [], "local_tmp_dir": str(root / "job"),
                        "execution_timeout_seconds": 3,
                    }, "TEST-FW")
                    self.assertEqual(result.status, "timeout")
                    self.assertLess(time.monotonic() - started, 8)
                    self.assertTrue(pids.exists(), "Timeout fixture must reach its local subprocess")
                    for pid in json.loads(pids.read_text()):
                        proc = Path("/proc/{0}/stat".format(pid))
                        self.assertTrue(not proc.exists() or proc.read_text().split()[2] == "Z", "Local child process survived runner timeout")
                    # Reusing the same lock after timeout must still work.
                    with exclusive_file_lock(root / "runner/TEST-FW/firewall_runner.lock", 0.1):
                        pass
                finally:
                    if pids.exists():
                        for pid in json.loads(pids.read_text()):
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass


if __name__ == "__main__":
    unittest.main()
