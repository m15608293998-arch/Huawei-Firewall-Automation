import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from api.config import settings
from api.runner_service import AnsibleRunnerService


class RunnerServiceTests(unittest.TestCase):
    def test_port_actions_are_passed_to_ansible_and_full_deny_does_not_need_ports(self) -> None:
        captured_calls = []

        def fake_run(**kwargs):
            captured_calls.append(kwargs)
            return types.SimpleNamespace(status="successful", rc=0)

        fake_runner = types.SimpleNamespace(run=fake_run)
        original_private_data_dir = settings.runner_private_data_dir

        with tempfile.TemporaryDirectory() as temp_dir:
            settings.runner_private_data_dir = Path(temp_dir) / "runner"
            try:
                with patch.dict(sys.modules, {"ansible_runner": fake_runner}):
                    service = AnsibleRunnerService()
                    service.run_trade_access(
                        {
                            "job_id": "allow-job",
                            "action": "allow",
                            "target_ip": "192.168.5.224",
                            "mask": 32,
                            "ports": [12001, 12002],
                            "principal_subject": "employee-a",
                            "description": None,
                            "local_tmp_dir": str(Path(temp_dir) / "allow-job"),
                        }
                    )
                    service.run_trade_access(
                        {
                            "job_id": "deny-job",
                            "action": "deny",
                            "target_ip": "192.168.5.224",
                            "mask": 32,
                            "ports": [],
                            "principal_subject": "employee-a",
                            "description": None,
                            "local_tmp_dir": str(Path(temp_dir) / "deny-job"),
                        }
                    )
                    service.run_trade_access(
                        {
                            "job_id": "deny-ports-job",
                            "action": "deny_ports",
                            "target_ip": "192.168.5.224",
                            "mask": 32,
                            "ports": [12001],
                            "principal_subject": "employee-a",
                            "description": None,
                            "local_tmp_dir": str(Path(temp_dir) / "deny-ports-job"),
                        }
                    )
            finally:
                settings.runner_private_data_dir = original_private_data_dir

        self.assertEqual(
            captured_calls[0]["extravars"]["application_ports"],
            [12001, 12002],
        )
        self.assertNotIn("application_ports", captured_calls[1]["extravars"])
        self.assertEqual(captured_calls[2]["extravars"]["application_ports"], [12001])


if __name__ == "__main__":
    unittest.main()
